#!/bin/bash
set -e

if ! which realpath > /dev/null 2>&1
then
  echo realpath is not installed
  echo run: brew install coreutils
  exit 1
fi

old_pwd=$(pwd)
script_path=$(dirname "$(realpath "$0")")
cd "$script_path"

repo_root=$(git rev-parse --show-toplevel)
# shellcheck source=/dev/null
. "$repo_root/proto-tools.env"

actual_protoc=$(protoc --version | awk '{print $2}')
if [[ "$actual_protoc" != "$PROTOC_VERSION" ]]; then
  echo "ERROR: protoc version $actual_protoc differs from pinned $PROTOC_VERSION" >&2
  echo "Install protoc $PROTOC_VERSION from https://github.com/protocolbuffers/protobuf/releases" >&2
  exit 1
fi

go install "google.golang.org/protobuf/cmd/protoc-gen-go@${PROTOC_GEN_GO_VERSION}"
go install "google.golang.org/grpc/cmd/protoc-gen-go-grpc@${PROTOC_GEN_GO_GRPC_VERSION}"
protoc -I ./ ./daemon.proto --go_out=../ --go-grpc_out=../ --experimental_allow_proto3_optional
cd "$old_pwd"
