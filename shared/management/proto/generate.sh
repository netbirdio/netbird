#!/bin/bash
set -e

if ! which realpath > /dev/null 2>&1
then
  echo realpath is not installed
  echo run: brew install coreutils
  exit 1
fi

old_pwd=$(pwd)
script_path=$(dirname $(realpath "$0"))
cd "$script_path"
go install google.golang.org/protobuf/cmd/protoc-gen-go@v1.26
go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@v1.1
protoc -I ./ ./management.proto --go_out=../ --go-grpc_out=../
protoc -I ./ ./proxy_service.proto --go_out=../ --go-grpc_out=../
# Reflection-free TinyGo variant: emits build-tagged embedpb_generated.go and
# re-stamps //go:build !tinygo onto the stock .pb.go protoc just rewrote.
go run github.com/soypat/embedpb/cmd/embedpb@v0.0.0-20260812030151-767038853f17 -tag tinygo .
cd "$old_pwd"
