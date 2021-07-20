# Wiretrustee Management Server

Install golang gRpc tools:
```bash
#!/bin/bash
go install google.golang.org/protobuf/cmd/protoc-gen-go@v1.26
go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@v1.1
```

Generate gRPC code:

```bash
#!/bin/bash
protoc -I proto/ proto/management.proto --go_out=. --go-grpc_out=.
```
