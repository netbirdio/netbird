#!/usr/bin/env bash

# This script installs dependencies to replicate the Codex environment
# for building and testing NetBird.

set -e

# Versions
GO_VERSION="1.23.9"
GORELEASER_VER="v2.3.2"

# Update package lists and install system dependencies
sudo apt-get update
sudo apt-get install -y --no-install-recommends \
    curl wget git build-essential gettext-base iptables \
    libgl1-mesa-dev xorg-dev libayatana-appindicator3-dev \
    libpcap-dev docker.io docker-compose

# Install Go
if ! go version | grep -q "$GO_VERSION"; then
    wget -q https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz
    sudo rm -rf /usr/local/go
    sudo tar -C /usr/local -xzf go${GO_VERSION}.linux-amd64.tar.gz
    rm go${GO_VERSION}.linux-amd64.tar.gz
fi
export PATH=$PATH:/usr/local/go/bin

# Install gRPC tools
GO_BIN=$(go env GOPATH)/bin
[ -d "$GO_BIN" ] || mkdir -p "$GO_BIN"
go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest

# Install goreleaser
go install github.com/goreleaser/goreleaser/v2@$GORELEASER_VER

# Install golangci-lint
curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b "$GO_BIN" latest

# Run go mod tidy if executed in repository root
if [ -f go.mod ]; then
    go mod tidy
fi

cat <<'MSG'
Environment setup complete. Ensure $GOPATH/bin is in your PATH to use installed tools.
MSG


