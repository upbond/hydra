package cli

import (
	"context"
	"fmt"
	"time"

	"github.com/pkg/errors"

	"github.com/ory/x/flagx"

	"github.com/spf13/cobra"

	"github.com/ory/hydra/driver"
	"github.com/ory/hydra/driver/config"
	"github.com/ory/x/configx"
	"github.com/ory/x/errorsx"
)

const (
	KeepIfYounger          = "keep-if-younger"
	AccessLifespan         = "access-lifespan"
	RefreshLifespan        = "refresh-lifespan"
	ConsentRequestLifespan = "consent-request-lifespan"
	Tokens                 = "tokens"
	Requests               = "requests"
	GrantTypeJWTBearer     = "grant-type-jwt-bearer"
	ReadFromEnv            = "read-from-env"
	Config                 = "config"
)

type JanitorHandler struct{}

func NewJanitorHandler() *JanitorHandler {
	return &JanitorHandler{}
}

func (_ *JanitorHandler) Args(cmd *cobra.Command, args []string) error {
	if len(args) == 0 &&
		!flagx.MustGetBool(cmd, ReadFromEnv) &&
		len(flagx.MustGetStringSlice(cmd, Config)) == 0 {

		fmt.Printf("%s\n", cmd.UsageString())
		return fmt.Errorf("%s\n%s\n%s\n",
			"A DSN is required as a positional argument when not passing any of the following flags:",
			"- Using the environment variable with flag -e, --read-from-env",
			"- Using the config file with flag -c, --config")
	}

	if !flagx.MustGetBool(cmd, Tokens) && !flagx.MustGetBool(cmd, Requests) && !flagx.MustGetBool(cmd, GrantTypeJWTBearer) {
		return fmt.Errorf("%s\nJanitor requires at least --%s or --%s or --%s to be set\n", cmd.UsageString(), Tokens, Requests, GrantTypeJWTBearer)
	}

	return nil
}

func (_ *JanitorHandler) RunE(cmd *cobra.Command, args []string) error {
	return purge(cmd, args)
}

func purge(cmd *cobra.Command, args []string) error {
	var d driver.Registry

	co := []configx.OptionModifier{
		configx.WithFlags(cmd.Flags()),
		configx.SkipValidation(),
	}

	keys := map[string]string{
		AccessLifespan:         config.KeyAccessTokenLifespan,
		RefreshLifespan:        config.KeyRefreshTokenLifespan,
		ConsentRequestLifespan: config.KeyConsentRequestMaxAge,
	}

	for k, v := range keys {
		if x := flagx.MustGetDuration(cmd, k); x > 0 {
			co = append(co, configx.WithValue(v, x))
		}
	}

	notAfter := time.Now().UTC()
	if keepYounger := flagx.MustGetDuration(cmd, KeepIfYounger); keepYounger > 0 {
		notAfter = notAfter.Add(-keepYounger)
	}

	if !flagx.MustGetBool(cmd, ReadFromEnv) && len(flagx.MustGetStringSlice(cmd, Config)) == 0 {
		co = append(co, configx.WithValue(config.KeyDSN, args[0]))
	}

	do := []driver.OptionsModifier{
		driver.DisableValidation(),
		driver.DisablePreloading(),
		driver.WithOptions(co...),
	}

	d = driver.New(cmd.Context(), do...)

	if len(d.Config().DSN()) == 0 {
		return fmt.Errorf("%s\n%s\n%s\n", cmd.UsageString(),
			"When using flag -e, environment variable DSN must be set.",
			"When using flag -c, the dsn property should be set.")
	}

	if err := d.Init(cmd.Context()); err != nil {
		return fmt.Errorf("%s\n%s\n", cmd.UsageString(),
			"Janitor can only be executed against a SQL-compatible driver but DSN is not a SQL source.")
	}

	p := d.Persister()

	var routines []cleanupRoutine
	if flagx.MustGetBool(cmd, Tokens) {
		routines = append(routines, cleanup(p.FlushInactiveAccessTokens, "access tokens"))
		routines = append(routines, cleanup(p.FlushInactiveRefreshTokens, "refresh tokens"))
	}

	if flagx.MustGetBool(cmd, Requests) {
		routines = append(routines, cleanup(p.FlushInactiveLoginConsentRequests, "login-consent requests"))
	}

	if flagx.MustGetBool(cmd, GrantTypeJWTBearer) {
		routines = append(routines, cleanup(p.FlushInactiveGrants, "grant types jwt bearer"))
	}

	return cleanupRun(cmd.Context(), notAfter, routines...)
}

type cleanupRoutine func(ctx context.Context, notAfter time.Time) error

func cleanup(cr cleanupRoutine, routineName string) cleanupRoutine {
	return func(ctx context.Context, notAfter time.Time) error {
		if err := cr(ctx, notAfter); err != nil {
			return errors.Wrap(errorsx.WithStack(err), fmt.Sprintf("Could not cleanup inactive %s", routineName))
		}
		fmt.Printf("Successfully completed Janitor run on %s\n", routineName)
		return nil
	}
}

func cleanupRun(ctx context.Context, notAfter time.Time, routines ...cleanupRoutine) error {
	if len(routines) == 0 {
		return errors.New("clean up run received 0 routines")
	}

	for _, r := range routines {
		if err := r(ctx, notAfter); err != nil {
			return err
		}
	}
	return nil
}
