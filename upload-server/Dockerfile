# Builds the upload server from source. Run it from the repository root:
#
#   docker build -f upload-server/Dockerfile .
#
# Releases package the goreleaser-built binary with Dockerfile.release instead;
# the runtime image is the same.
FROM --platform=$BUILDPLATFORM golang:1.26.7-bookworm AS builder
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
      -o /out/netbird-upload ./upload-server

FROM gcr.io/distroless/base:debug
ENTRYPOINT [ "/go/bin/netbird-upload" ]
COPY --from=builder /out/netbird-upload /go/bin/netbird-upload
