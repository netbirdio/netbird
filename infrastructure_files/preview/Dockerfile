# Preview image for the combined server.
#
# This is combined/Dockerfile.multistage plus exactly one thing: an entrypoint
# that renders /etc/netbird/config.yaml before starting the server.
#
# It exists because the combined server reads its configuration from a YAML file
# and nothing else - LoadConfig in combined/cmd/config.go unmarshals a file, and
# there is no environment-variable path into CombinedConfig. A preview's public
# URL is only assigned at deploy time, so the OIDC issuer, the dashboard's
# redirect URIs and the relay/signal addresses cannot be baked into a committed
# config file. Something has to write that file at container start.
#
# The builder stage below is deliberately the same as the one in
# combined/Dockerfile.multistage: a Docker build takes a single Dockerfile and
# has to compile this branch's own source, so starting FROM a prebuilt combined
# image is not an option. Keep the two in sync.
#
# Build context is the repository root.

FROM golang:1.25-bookworm AS builder
WORKDIR /app

# CGO is required: the embedded IdP and the activity store use go-sqlite3.
RUN apt-get update && apt-get install -y --no-install-recommends gcc libc6-dev \
    && rm -rf /var/lib/apt/lists/*

COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download

COPY . .

# A preview has no tags to describe, so the version is passed in rather than
# derived from git the way combined/Dockerfile.multistage does.
ARG NETBIRD_VERSION=preview
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=1 GOOS=linux go build \
    -ldflags="-s -w -X github.com/netbirdio/netbird/version.version=${NETBIRD_VERSION}" \
    -o netbird-server ./combined

FROM ubuntu:24.04
RUN apt update && apt install -y ca-certificates && rm -fr /var/cache/apt

COPY --from=builder /app/netbird-server /go/bin/netbird-server
COPY infrastructure_files/preview/entrypoint.sh /usr/local/bin/netbird-preview-entrypoint
RUN chmod +x /usr/local/bin/netbird-preview-entrypoint

ENV NB_PREVIEW_PORT=8080
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/netbird-preview-entrypoint"]
