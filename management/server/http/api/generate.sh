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
go install github.com/deepmap/oapi-codegen/cmd/oapi-codegen@4a1477f6a8ba6ca8115cc23bb2fb67f0b9fca18e
oapi-codegen --config cfg.yaml openapi.yml
cd "$old_pwd"