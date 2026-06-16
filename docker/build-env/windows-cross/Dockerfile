# Windows-cross build environment.
#
# Cross-compiles Windows .exe targets from a Linux container using
# mingw-w64. Mirrors the toolchain set used by
# .github/workflows/golang-test-windows.yml insofar as that is possible
# without a Windows kernel.
#
# IMPORTANT — what this image CAN do:
#   - `GOOS=windows go build ./...` to validate that Windows builds compile
#   - CGO Windows cross-compile via x86_64-w64-mingw32-gcc when CGO_ENABLED=1
#     (matches CI's choco-installed mingw-w64)
#
# IMPORTANT — what this image CANNOT do:
#   - Run Windows binaries (no Windows kernel under Docker on Linux).
#   - Replicate the CI's `go test` runs which execute on a real
#     windows-latest runner (wintun.dll, PsExec, registry, etc.).
#     Use the CI for that or a native Windows VM.
#
# Usage (from the netbird repo root):
#
#   docker build -t netbird/build-windows docker/build-env/windows-cross
#
#   # Cross-compile a static client (.exe) from Linux:
#   docker run --rm -v "$PWD:/src" -w /src netbird/build-windows \
#       bash -c 'CGO_ENABLED=1 GOOS=windows GOARCH=amd64 \
#           CC=x86_64-w64-mingw32-gcc CXX=x86_64-w64-mingw32-g++ \
#           go build -o netbird.exe ./client'
#
#   # Just validate that everything *compiles* on Windows (no CGO):
#   docker run --rm -v "$PWD:/src" -w /src netbird/build-windows \
#       bash -c 'GOOS=windows GOARCH=amd64 go build ./...'
#
# Tooling versions (keep in sync with go.mod and any future explicit pin
# documented in golang-test-windows.yml):
#   - Ubuntu 22.04
#   - Go 1.25.5 (matches go.mod)
#   - mingw-w64 (Ubuntu package — pin further if drift becomes a problem)

FROM ubuntu:22.04

ARG DEBIAN_FRONTEND=noninteractive
ARG GO_VERSION=1.25.5

ENV GOPATH=/go
ENV GOTOOLCHAIN=local
ENV PATH=${GOPATH}/bin:/usr/local/go/bin:${PATH}

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        git \
        build-essential \
        mingw-w64 \
    && rm -rf /var/lib/apt/lists/*

# Install Go (matches go.mod).
RUN curl -fsSL "https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz" \
        | tar -C /usr/local -xz \
    && go version

WORKDIR /src

CMD ["/bin/bash"]
