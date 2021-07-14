FROM golang:1.16-alpine AS builder

RUN apk -U --no-cache add build-base git gcc bash

WORKDIR /go/src/github.com/ory/hydra

ADD go.mod go.mod
ADD go.sum go.sum

ENV GO111MODULE on
ENV CGO_ENABLED 1

RUN go mod download

ADD . .

RUN go build -tags sqlite -o /usr/bin/hydra

FROM alpine:3.13.4

RUN addgroup -S ory; \
    adduser -S ory -G ory -D  -h /home/ory -s /bin/nologin; \
    chown -R ory:ory /home/ory

COPY --from=builder /usr/bin/hydra /usr/bin/hydra

# By creating the sqlite folder as the ory user, the mounted volume will be owned by ory:ory, which
# is required for read/write of SQLite.
RUN mkdir -p /var/lib/sqlite
RUN chown ory:ory /var/lib/sqlite
VOLUME /var/lib/sqlite

ARG profile="local"

# Exposing the ory home directory to simplify passing in hydra configuration (e.g. if the file $HOME/.hydra.yaml
# exists, it will be automatically used as the configuration file).
VOLUME /home/ory
COPY "./deploy/hydra.$profile.yml" /home/ory/.hydra.yml

# Declare the standard ports used by hydra (4433 for public service endpoint, 4434 for admin service endpoint)
EXPOSE 4444 4445

USER ory

ENTRYPOINT ["hydra"]
CMD ["serve", "all", "-c", "/home/ory/.hydra.yml", "--dangerous-force-http"]
