# Wiretrustee Signal Server

This is a Wiretrustee signal-exchange server and client library to exchange connection information between Wiretrustee peers

The project uses gRpc library and defines service in protobuf file located in:
 ```proto/signalexchange.proto```

To build the project you have to do the following things.

Install golang gRpc tools:
```bash
#!/bin/bash
go install google.golang.org/protobuf/cmd/protoc-gen-go@v1.26
go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@v1.1
```

Generate gRpc code:

```bash
#!/bin/bash
protoc -I proto/ proto/signalexchange.proto --go_out=. --go-grpc_out=.
```
