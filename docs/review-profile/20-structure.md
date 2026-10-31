# 20 Structure: where code lives

The monorepo keeps each component inside its own directory, with a small set
of shared packages. A diff that adds a file or an import is checked against
this map before anything else; a file in the wrong place is cheap to move now
and expensive after merge (licence boundary, release packaging, and the cloud
repository's wiring all key on paths).

## Component map

| Path | Component | Licence | Notes |
| --- | --- | --- | --- |
| `client/` | agent | BSD-3 | runs as root; `cmd/` CLI, `internal/` logic, `server/` daemon, `proto/` daemon IPC, `iface/`, `firewall/`, `ssh/`, `ui/`, `android/`, `ios/`, `wasm/`, `embed/`, `mdm/`, `system/` |
| `management/` | control plane | AGPL-3 | `server/` holds domain packages, `server/http/` REST, `server/store/` persistence, `server/migration/` |
| `signal/` | handshake broker | AGPL-3 | `peer/`, `server/` |
| `relay/` | relay | AGPL-3 | `protocol/`, `server/`, `healthcheck/` |
| `proxy/` | identity-aware proxy | AGPL-3 | `internal/llm/`, `acme/`, `accesslog/`, `middleware/`, `tcp/`, `udp/` |
| `combined/` | single-binary server | AGPL-3 | wires management, signal, relay, proxy |
| `shared/` | imported by agent and services | BSD-3 | `management/{proto,client,http/api}`, `signal/{proto,client}`, `relay/`, `auth/`, `sshauth/`, `metrics/`, `context/`, `lifecycle/`, `netiputil/`, `llm/` |
| `dns/`, `route/`, `stun/`, `sharedsock/`, `util/`, `encryption/`, `flow/`, `formatter/`, `version/`, `base62/`, `monotime/`, `trustedproxy/`, `idp/` | shared primitives | BSD-3 | root-level because both sides import them |
| `e2e/` | end-to-end suites and harness | | `harness/` is the shared fixture code |
| `integration_tests/` | management integration suite | | run by `mage integrationtest:all` |
| `infrastructure_files/`, `release_files/`, `.goreleaser*.yaml` | packaging | | self-hosted compose templates, release artefacts |
| `tools/` | maintenance tooling | | `idp-migrate` is allowed to import AGPL packages |
| `magefiles/` | mage targets | | OpenAPI bindings, integration tests |
| `agent-network/`, `docs/` | documentation | | `docs/` also holds MDM policy templates |

## Rules

### STR-001 Agent code never imports a service package
severity: blocker
scope: imports in every non-test file outside `management/`, `signal/`,
`relay/`, `proxy/`, `combined/`, `tools/idp-migrate/`
check: an import of `github.com/netbirdio/netbird/(management|signal|relay|proxy)/`.
say: "The agent and `shared/` are BSD-licensed and may not import the AGPL
services (`check-license-dependencies.yml`). If both sides need it, it goes
under `shared/` or a root-level package."
why: licence boundary; also the reason protos and service clients live in
`shared/` rather than next to the server.

### STR-002 Something both sides use lives in `shared/` or a root primitive
severity: should
scope: new files
check: a type, helper, or constant added under `management/` that the client
then references through a copy, or added under `client/` and referenced by
management. Duplicated constants on both sides (header names, metadata keys,
limits) are the usual symptom.
say: "Both sides need `<thing>`; put it in `shared/<area>/` so they cannot
drift."

### STR-003 Protos live under `shared/` or `client/proto`, never under a server dir
severity: should
scope: `**/*.proto`
check: a new `.proto` outside `shared/management/proto`,
`shared/signal/proto`, `shared/relay/`, `client/proto`, `flow/proto`,
`proxy/` internal protos.
why: CONTRIBUTING.md Directory structure; the agent imports the generated
client code.

### STR-004 REST handlers follow the per-resource package layout
severity: nit
scope: `management/server/http/handlers/**`
check: a new handler added to an unrelated resource package, or a new resource
package that does not register through the existing handler wiring in
`management/server/http/handler.go`. Middleware goes in `http/middleware`,
request/response helpers in `http/util` (see 40-control-plane.md).

### STR-005 Domain logic lives in the domain package, not the handler and not the store
severity: should
scope: `management/server/**`
check: validation or authorization logic inside `http/handlers/**`; business
rules (defaults, cross-entity checks) inside `store/sql_store_*.go`.
Handlers decode, authorise through the manager, call the manager, and encode.
Stores read and write. The manager in `management/server/<domain>/` owns the
rules.

### STR-006 Platform-specific agent code uses file suffixes and the stub pattern
severity: should
scope: `client/**`, `util/**`, `sharedsock/**`, `route/**`, `dns/**`,
`version/**`
check: `runtime.GOOS` switches inside a function where a `_<os>.go` split is
the convention in the surrounding package; a `_<os>.go` file with no
counterpart or `//go:build` fallback for the others. See 50-client.md for
the suffix and tag inventory.

### STR-007 Tests sit beside the code; privileged tests carry the tag
severity: should
scope: `**/*_test.go`
check: a test that creates a TUN, opens netlink or raw sockets, or shells out
to `ip`/`iptables`/`nft`/`route` without `//go:build privileged`; a privileged
test placed outside the packages the Docker harness lists. The host-safe run
is `make test-unit`; the privileged suite is `make test-privileged`
(`docs/testing-privileged.md`).

### STR-008 Generated outputs are not hand-edited and live where their generator writes them
severity: blocker
scope: `**/*.pb.go`, `**/*.gen.go`, `**/bundle.yaml`, `**/mock_*.go`,
`**/*_mock.go`, `client/ui/frontend/**/bindings/**`
check: a change to a generated file without the matching change to its source
(`.proto`, `openapi.yml`, interface with a `go:generate` directive) in the
same diff, or a generated file edited without its header. See 30-generated.md.

### STR-009 Binaries, caches, and local config never enter the tree
severity: blocker
scope: new files
check: `netbird`, `netbird-mgmt`, `*.test`, `*.db`, `*.sqlite`, `go.work`,
`.env`, `coverage.txt`, `bin/`, `dist/`, IDE folders. `go.work` is
git-ignored in the cloud repository for a reason (see the cloud profile).

### STR-010 Package names and directories match
severity: nit
scope: new packages
check: a directory whose package clause differs from its name (except
`_test` packages and `main`), a package named `util`, `common`, `helpers`,
`misc` added anywhere new; a new `internal/` that is not the agent's.
say: "Name the package for what it provides."

### STR-011 Keep the agent's public surface in `client/embed` and `client/proto` stable
severity: ask
scope: `client/embed/**`, `client/proto/**`, `client/internal/**` symbols
exported for mobile bindings (`client/android`, `client/ios`)
check: a signature change on an exported function consumed by the mobile
bindings or the embedded client.
say: "`<symbol>` is consumed outside this repository (mobile bindings /
embedded client); is the change coordinated?"
why: AGENTS.md "unused parameters in shared code may be consumed by builds
outside this repository".
