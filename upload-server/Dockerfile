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
# Images are pinned by digest alone. The builder is golang:1.26.10-bookworm and
# the bases are Chainguard's :latest, the only free tag; bump them by hand with
# docker buildx imagetools inspect <image:tag>.

ARG VARIANT=release

# Pure Go: cross-compile from the build host instead of emulating the target.
FROM --platform=$BUILDPLATFORM golang@sha256:632dff7351799a5a9954a48dc06670ade72ee44e8c351cdc0e5a57af2fea21af AS builder
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

FROM cgr.dev/chainguard/static@sha256:17367e4d3ae2b46c3290858e483fac09be085c92b372360fe3bf6a6150848fde AS base-release
FROM cgr.dev/chainguard/busybox@sha256:98e9e7306c899a8af252ef1ff50c54def91c2fe04677298eafdf0b902f2980ed AS base-debug

# hadolint ignore=DL3006
FROM base-${VARIANT}
COPY --from=builder --chown=65532:65532 /out/var/lib/netbird /var/lib/netbird
COPY --from=builder /out/netbird-upload /go/bin/netbird-upload
WORKDIR /var/lib/netbird
USER 65532:65532
ENTRYPOINT ["/go/bin/netbird-upload"]
