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
cd "$old_pwd"