package proto

// embedpb generates the reflection-free protobuf implementation that the TinyGo
// build uses; see client/wasm/README.md. TinyGo's reflect has no
// (reflect.Type).MethodByName, so the stock protobuf runtime panics as soon as
// it builds its reflection coder.
//
// -stamp-stock=false because the //go:build !tinygo constraints on the stock
// .pb.go files here are already committed. generate.sh omits the flag: protoc
// strips those constraints when it rewrites the .pb.go files, so they have to be
// re-stamped right after.
//go:generate go tool embedpb -tag tinygo -stamp-stock=false .
