# Privileged tests

Some tests in this repo need `root` or mutate host network state: they create
TUN/WireGuard interfaces, open netlink/raw sockets, run eBPF programs, or shell
out to `ip`/`iptables`/`nft`/`ifconfig`/`route`. Running them on a developer
machine would require `sudo` and could leave stray interfaces or routes behind.

These tests are gated behind the **`privileged` build tag** so the default test
run is host-safe.

## Running tests

```bash
# Host-safe: excludes privileged tests. Runs as a normal user, no sudo.
make test-unit
# equivalently:
go test -tags devcert ./...

# Privileged suite: runs the privileged-tagged tests inside a
# --privileged --cap-add=NET_ADMIN container (requires Docker).
make test-privileged

# Narrow the container run to a single test / package:
PRIV_RUN=TestNftablesManager PRIV_PKGS=./client/firewall/nftables/... make test-privileged
```

`PRIV_RUN` adds a `-run` test-name filter and `PRIV_PKGS` overrides the package
list; both are optional and default to the full privileged suite.

`make test-privileged` invokes the `ory/dockertest` harness in
`client/testutil/privileged/`. The harness:

1. Skips immediately when it detects it is already inside the container
   (`DOCKER_CI=true`), so the privileged tests run in place instead of recursing.
2. Otherwise spins up a `golang:1.25-alpine` container (matching CI),
   bind-mounts the repo and the host Go build/module caches, installs the
   required packages, and runs `go test -tags 'devcert privileged'` over the
   client packages.
3. Streams the container's output to the test log and fails if the suite fails.

## Adding a privileged test

A test is privileged if it does any of:

- creates a real interface via `iface.NewWGIFace(...).Create()`,
- opens a netlink or raw socket that hard-fails without `CAP_NET_ADMIN`,
- runs an eBPF program (`ebpf.*.Listen()`),
- shells out to `ip`, `iptables`, `nft`, `ifconfig`, or `route` to change state.

Add the tag to the **top** of the file, combined with any existing platform
constraint:

```go
//go:build privileged && linux

package foo
```

If a file mixes privileged and pure-logic tests, **split it**: keep the pure
tests (and any shared data — type/var declarations, table-driven `testCases`,
helper interfaces) in an untagged file, and move the privileged tests into a
`*_privileged_test.go` file with the tag. Shared declarations must stay untagged,
otherwise the unprivileged files in the package will not compile.

Always verify both build modes compile on every target platform:

```bash
go vet -tags devcert ./...
go vet -tags 'devcert privileged' ./...
```

## CI

- The `Client / Unit` job runs `go test -tags devcert` with **no** `sudo` — only
  host-safe tests.
- The `Client (Docker) / Unit` job runs `go test -tags 'devcert privileged'`
  inside a `--privileged --cap-add=NET_ADMIN` container, which is where the
  privileged tests actually execute.
