#!/usr/bin/env bash
set -euo pipefail

project_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
repo_dir="$(cd "$project_dir/../.." && pwd)"

command -v protoc >/dev/null 2>&1 || {
  echo "protoc is not installed"
  exit 1
}

command -v dart >/dev/null 2>&1 || {
  echo "dart is not installed"
  exit 1
}

export PATH="$PATH:$HOME/.pub-cache/bin"

if ! command -v protoc-gen-dart >/dev/null 2>&1; then
  dart pub global activate protoc_plugin
fi

mkdir -p "$project_dir/lib/src/generated"

protoc \
  -I "$repo_dir/client/proto" \
  --dart_out=grpc:"$project_dir/lib/src/generated" \
  "$repo_dir/client/proto/daemon.proto"

