#!/bin/bash
go install google.golang.org/protobuf/cmd/protoc-gen-go@v1.26
go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@v1.1
protoc -I proto/ proto/signalexchange.proto --go_out=. --go-grpc_out=.