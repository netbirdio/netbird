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
FROM --platform=$BUILDPLATFORM golang@sha256:2920bb124f1a2e12a1d39f0cab756ae0068441ee1da7655dec7f5e374944095b AS builder
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

FROM cgr.dev/chainguard/static@sha256:fc42af33e643f20d08baf03cddcc1c02ba57052dfb02edb0d79f3fc47bcea8d9 AS base-release
FROM cgr.dev/chainguard/busybox@sha256:788270e8cb45854403aa13c37603ddc31fc9d871db5b04cb27adf5f3f5b7d6c3 AS base-debug

# hadolint ignore=DL3006
FROM base-${VARIANT}
COPY --from=builder --chown=65532:65532 /out/var/lib/netbird /var/lib/netbird
COPY --from=builder /out/netbird-upload /go/bin/netbird-upload
WORKDIR /var/lib/netbird
USER 65532:65532
ENTRYPOINT ["/go/bin/netbird-upload"]
