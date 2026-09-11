# Building the WASM client

Both toolchain instructives emit `netbird.wasm` and `wasm_exec.js` into `client/wasm/`. The `wasm_exec.js`  glue must
come from the toolchain that built the binary; Go's and TinyGo's are not interchangeable.

## Go

```sh
cd client/wasm/cmd
GOOS=js GOARCH=wasm CGO_ENABLED=0 go build -o ../netbird.wasm .
cp "$(go env GOROOT)/lib/wasm/wasm_exec.js" ../
```

`CGO_ENABLED=0` is required: a global `go env -w CGO_ENABLED=1` leaves the `cgo` tag set for
`GOOS=js`, dropping both `os/user` implementations (`undefined: lookupUser`).

## TinyGo

Needs `wasm-opt` (binaryen >= 102) on PATH — its `--asyncify` pass is how TinyGo implements
goroutines, so without it nothing that blocks works. Takes ~15 min.

```sh
go generate -run=embedpb ./...
cd client/wasm/cmd
tinygo build -target wasm -interp-timeout=15m -o ../netbird.wasm .
cp "$(tinygo env TINYGOROOT)/targets/wasm_exec.js" ../
```

`go generate` writes the reflection-free protobuf TinyGo needs (its `reflect` has no
`MethodByName`); `-run=embedpb` selects just those four proto packages, leaving the mockgen
and bpf2go directives alone. `-interp-timeout` raises TinyGo's 180s default, which the package
initializers of `grpc/credentials` alone exceed. Also useful: `-no-debug` (-35 MB),
`-opt=0` when wasm-opt OOMs, `-gc=leaking` to rule out the collector.

## Tags

Passed to either toolchain. `wglneto` swaps gvisor for the lneto netstack; `netstackdebug`
dumps every packet on both backends; `xnetdebug` and `debugheaplog` add lneto logging and
only apply with `wglneto`.
