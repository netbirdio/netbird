# syntax=docker/dockerfile:1

# Builds the upload server from source. Run it from the repository root:
#
#   docker build -f upload-server/Dockerfile .
#
# Releases package the goreleaser-built binary with Dockerfile.release instead,
# which keeps the published image as it was (distroless base, running as root).
#
# The image runs as the base image's nonroot user (uid 65532), which owns the
# default STORE_DIR, /var/lib/netbird. A volume mounted there must be writable
# by that uid: a named Docker volume takes the directory's ownership on first
# use, a bind mount needs chown, and Kubernetes needs fsGroup: 65532.
#
# Build args:
#   VARIANT=release|debug  debug swaps the base for Chainguard busybox (a shell)
#   VERSION                stamped into the binary the same way goreleaser does
#
# Chainguard publishes only :latest for free, so the bases are pinned by digest
# and moved by Dependabot.

ARG VARIANT=release

# Pure Go: cross-compile from the build host instead of emulating the target.
FROM --platform=$BUILDPLATFORM golang:1.26.7-bookworm@sha256:e8c859f5632dcfde7b32d2012b4351728f6437930887c2f6a91ea242459e5514 AS builder
WORKDIR /app

COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download

COPY . .
ARG TARGETOS
ARG TARGETARCH
ARG VERSION=development
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -trimpath \
      -ldflags "-s -w -X github.com/netbirdio/netbird/version.version=${VERSION}" \
      -o /out/netbird-upload ./upload-server \
    && mkdir -p /out/var/lib/netbird

FROM cgr.dev/chainguard/static:latest@sha256:41e17ed83c594a64a9396b6ab96dd26d5ddc290dacf4c177464712ff21ad534f AS base-release
FROM cgr.dev/chainguard/busybox:latest@sha256:b2953ab1cae4a6265e18cf675851bd99975211b150d7a014774911d76eb309ba AS base-debug

# hadolint ignore=DL3006
FROM base-${VARIANT}
COPY --from=builder --chown=65532:65532 /out/var/lib/netbird /var/lib/netbird
COPY --from=builder /out/netbird-upload /go/bin/netbird-upload
WORKDIR /var/lib/netbird
USER 65532:65532
ENTRYPOINT ["/go/bin/netbird-upload"]
