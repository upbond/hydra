package cli_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/ory/hydra/driver"
	"github.com/ory/hydra/driver/config"
	"github.com/ory/hydra/internal"
	"github.com/ory/kratos/x"
	"github.com/ory/x/logrusx"

	"github.com/stretchr/testify/assert"

	"github.com/ory/hydra/grant/jwtbearer"

	"github.com/ory/hydra/cmd"

	"github.com/spf13/cobra"

	"github.com/stretchr/testify/require"

	"github.com/ory/hydra/cmd/cli"
	"github.com/ory/hydra/internal/testhelpers"
	"github.com/ory/x/cmdx"
)

func newJanitorCmd() *cobra.Command {
	return cmd.NewRootCmd()
}

func TestJanitorHandler_PurgeTokenNotAfter(t *testing.T) {
	ctx := context.Background()
	testCycles := testhelpers.NewConsentJanitorTestHelper("").GetNotAfterTestCycles()

	require.True(t, len(testCycles) > 0)

	for k, v := range testCycles {
		t.Run(fmt.Sprintf("case=%s", k), func(t *testing.T) {
			jt := testhelpers.NewConsentJanitorTestHelper(t.Name())
			reg, err := jt.GetRegistry(ctx, k)
			require.NoError(t, err)

			// setup test
			t.Run("step=setup-access", jt.AccessTokenNotAfterSetup(ctx, reg.ClientManager(), reg.OAuth2Storage()))
			t.Run("step=setup-refresh", jt.RefreshTokenNotAfterSetup(ctx, reg.ClientManager(), reg.OAuth2Storage()))

			// run the cleanup routine
			t.Run("step=cleanup", func(t *testing.T) {
				cmdx.ExecNoErr(t, newJanitorCmd(),
					"janitor",
					fmt.Sprintf("--%s=%s", cli.KeepIfYounger, v.String()),
					fmt.Sprintf("--%s=%s", cli.AccessLifespan, jt.GetAccessTokenLifespan().String()),
					fmt.Sprintf("--%s=%s", cli.RefreshLifespan, jt.GetRefreshTokenLifespan().String()),
					fmt.Sprintf("--%s", cli.Tokens),
					jt.GetDSN(),
				)
			})

			// validate test
			notAfter := time.Now().Round(time.Second).Add(-v)
			t.Run("step=validate-access", jt.AccessTokenNotAfterValidate(ctx, notAfter, reg.OAuth2Storage()))
			t.Run("step=validate-refresh", jt.RefreshTokenNotAfterValidate(ctx, notAfter, reg.OAuth2Storage()))
		})
	}
}

func TestJanitorHandler_PurgeLoginConsentNotAfter(t *testing.T) {
	ctx := context.Background()
	testCycles := testhelpers.NewConsentJanitorTestHelper("").GetNotAfterTestCycles()

	for k, v := range testCycles {
		jt := testhelpers.NewConsentJanitorTestHelper(k)
		reg, err := jt.GetRegistry(ctx, k)
		require.NoError(t, err)

		t.Run(fmt.Sprintf("case=%s", k), func(t *testing.T) {
			// Setup the test
			t.Run("step=setup", jt.LoginConsentNotAfterSetup(ctx, reg.ConsentManager(), reg.ClientManager()))

			// Run the cleanup routine
			t.Run("step=cleanup", func(t *testing.T) {
				cmdx.ExecNoErr(t, newJanitorCmd(),
					"janitor",
					fmt.Sprintf("--%s=%s", cli.KeepIfYounger, v.String()),
					fmt.Sprintf("--%s=%s", cli.ConsentRequestLifespan, jt.GetConsentRequestLifespan().String()),
					fmt.Sprintf("--%s", cli.Requests),
					jt.GetDSN(),
				)
			})

			notAfter := time.Now().UTC().Round(time.Second).Add(-v)
			consentLifespan := time.Now().UTC().Round(time.Second).Add(-jt.GetConsentRequestLifespan())
			t.Run("step=validate", jt.LoginConsentNotAfterValidate(ctx, notAfter, consentLifespan, reg.ConsentManager()))
		})
	}
}

func TestJanitorHandler_PurgeJWTBearer(t *testing.T) {
	ctx := context.Background()
	reg := internal.NewMockedRegistry(t)

	conf := internal.NewConfigurationWithDefaults()
	conf.MustSet(config.KeyDSN, fmt.Sprintf("sqlite://file:%s?mode=memory&_fk=true&cache=shared", x.NewUUID()))
	reg, err := driver.NewRegistryFromDSN(ctx, conf, logrusx.New("test_hydra", "master"))
	require.NoError(t, err)

	var grant1, grant2, grant3 jwtbearer.Grant
	t.Run("step=setup", func(t *testing.T) {
		grant1, grant2, grant3 = jwtbearer.TestCreateStubGrants(t, reg.Persister())
	})

	// cleanup
	t.Run("step=cleanup", func(t *testing.T) {
		cmdx.ExecNoErr(t, newJanitorCmd(),
			"janitor",
			fmt.Sprintf("--%s", cli.GrantTypeJWTBearer),
			conf.DSN(),
		)
	})

	t.Run("step=validate", func(t *testing.T) {
		count, err := reg.Persister().CountGrants(context.TODO())
		require.NoError(t, err)
		assert.Equal(t, 1, count)

		_, err = reg.Persister().GetConcreteGrant(context.TODO(), grant1.ID)
		assert.NoError(t, err)

		_, err = reg.Persister().GetConcreteGrant(context.TODO(), grant2.ID)
		assert.Error(t, err)

		_, err = reg.Persister().GetConcreteGrant(context.TODO(), grant3.ID)
		assert.Error(t, err)
	})
}

func TestJanitorHandler_PurgeLoginConsent(t *testing.T) {
	/*
		Login and Consent also needs to be purged on two conditions besides the KeyConsentRequestMaxAge and notAfter time
		- when a login/consent request was never completed (timed out)
		- when a login/consent request was rejected
	*/

	t.Run("case=login-consent-timeout", func(t *testing.T) {
		t.Run("case=login-timeout", func(t *testing.T) {
			ctx := context.Background()
			jt := testhelpers.NewConsentJanitorTestHelper(t.Name())
			reg, err := jt.GetRegistry(ctx, t.Name())
			require.NoError(t, err)

			// setup
			t.Run("step=setup", jt.LoginTimeoutSetup(ctx, reg.ConsentManager(), reg.ClientManager()))

			// cleanup
			t.Run("step=cleanup", func(t *testing.T) {
				cmdx.ExecNoErr(t, newJanitorCmd(),
					"janitor",
					fmt.Sprintf("--%s", cli.Requests),
					jt.GetDSN(),
				)
			})

			t.Run("step=validate", jt.LoginTimeoutValidate(ctx, reg.ConsentManager()))

		})

		t.Run("case=consent-timeout", func(t *testing.T) {
			ctx := context.Background()
			jt := testhelpers.NewConsentJanitorTestHelper(t.Name())
			reg, err := jt.GetRegistry(ctx, t.Name())
			require.NoError(t, err)

			// setup
			t.Run("step=setup", jt.ConsentTimeoutSetup(ctx, reg.ConsentManager(), reg.ClientManager()))

			// run cleanup
			t.Run("step=cleanup", func(t *testing.T) {
				cmdx.ExecNoErr(t, newJanitorCmd(),
					"janitor",
					fmt.Sprintf("--%s", cli.Requests),
					jt.GetDSN(),
				)
			})

			// validate
			t.Run("step=validate", jt.ConsentTimeoutValidate(ctx, reg.ConsentManager()))
		})

	})

	t.Run("case=login-consent-rejection", func(t *testing.T) {
		ctx := context.Background()

		t.Run("case=login-rejection", func(t *testing.T) {
			jt := testhelpers.NewConsentJanitorTestHelper(t.Name())
			reg, err := jt.GetRegistry(ctx, t.Name())
			require.NoError(t, err)

			// setup
			t.Run("step=setup", jt.LoginRejectionSetup(ctx, reg.ConsentManager(), reg.ClientManager()))

			// cleanup
			t.Run("step=cleanup", func(t *testing.T) {
				cmdx.ExecNoErr(t, newJanitorCmd(),
					"janitor",
					fmt.Sprintf("--%s", cli.Requests),
					jt.GetDSN(),
				)
			})

			// validate
			t.Run("step=validate", jt.LoginRejectionValidate(ctx, reg.ConsentManager()))
		})

		t.Run("case=consent-rejection", func(t *testing.T) {
			jt := testhelpers.NewConsentJanitorTestHelper(t.Name())
			reg, err := jt.GetRegistry(ctx, t.Name())
			require.NoError(t, err)

			// setup
			t.Run("step=setup", jt.ConsentRejectionSetup(ctx, reg.ConsentManager(), reg.ClientManager()))

			// cleanup
			t.Run("step=cleanup", func(t *testing.T) {
				cmdx.ExecNoErr(t, newJanitorCmd(),
					"janitor",
					fmt.Sprintf("--%s", cli.Requests),
					jt.GetDSN(),
				)
			})

			// validate
			t.Run("step=validate", jt.ConsentRejectionValidate(ctx, reg.ConsentManager()))
		})
	})
}

func TestJanitorHandler_Arguments(t *testing.T) {
	cmdx.ExecNoErr(t, cmd.NewRootCmd(),
		"janitor",
		fmt.Sprintf("--%s", cli.Requests),
		"memory",
	)
	cmdx.ExecNoErr(t, cmd.NewRootCmd(),
		"janitor",
		fmt.Sprintf("--%s", cli.Tokens),
		"memory",
	)
	cmdx.ExecNoErr(t, cmd.NewRootCmd(),
		"janitor",
		fmt.Sprintf("--%s", cli.GrantTypeJWTBearer),
		"memory",
	)

	_, _, err := cmdx.ExecCtx(context.Background(), cmd.NewRootCmd(), nil,
		"janitor",
		"memory")
	require.Error(t, err)
	require.Contains(t, err.Error(), "Janitor requires at least --tokens or --requests or --grant-type-jwt-bearer to be set")
}
