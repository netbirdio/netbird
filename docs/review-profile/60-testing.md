# 60 Testing

What a change must come with, and what the tests themselves must look like.
Coverage on new code must not go backwards (Codecov, per-component flags), and
thresholds are never adjusted to clear the report.

## What the diff must include

### TEST-001 A bug fix comes with a test that fails without it
severity: should
scope: PRs ticking "bug fix" or titled fix/regression
check: no `_test.go` change in the diff, or a test change that would pass on
the base branch too (look for the asserted behaviour in the pre-change code).
say: "Add the reproducing test (fails on main for the reason in the ticket,
passes here); the PR checklist asks for it."
why: AGENTS.md Testing, "Reproduce a bug before fixing it".

### TEST-002 New code paths have tests in the same package
severity: should
scope: new exported functions, new handler, new store method, new manager
method
check: added non-trivial function with no test referencing it. Thin wrappers
and generated code are exempt.

### TEST-003 Store changes are tested against both SQLite and Postgres
severity: should
scope: `management/server/store/**`, `management/server/migration/**`
check: a new query or migration whose test only runs the default engine, or
uses SQL syntax that differs between the two (`ILIKE`, `RETURNING`, JSON
operators, `datetime()`), or assumes case-insensitive collation.
say: "The management test jobs run with `NETBIRD_STORE_ENGINE=sqlite` and
`postgres`; make sure this passes under both (and MySQL where still
supported)."
why: `golang-test-linux.yml` Management / Unit and Integration matrix.

### TEST-004 Host-mutating tests are privileged-tagged and live in the harness's package list
severity: blocker
scope: `client/**/*_test.go`
check: a test that creates interfaces, touches netlink, raw sockets, routing,
firewall, or `/etc/resolv.conf`, without `//go:build privileged`. The
Linux job runs `-tags 'devcert privileged'` under sudo and the Docker job
mirrors it; macOS and Windows jobs do not have root.
why: `docs/testing-privileged.md`; a privileged test without the tag breaks
`make test-unit` on developer machines.

### TEST-005 Tests that need the development certificate carry `devcert`
severity: should
scope: tests touching TLS, relay, proxy ACME
check: a test skipped or failing without `-tags devcert` that is not tagged;
`go test ./...` without the tag silently skips them (AGENTS.md Pitfalls).

### TEST-006 Race detector on concurrent code
severity: should
scope: diffs touching goroutines, mutexes, channels, atomics
check: the PR does not state that `go test -race` ran on the touched packages,
or a test uses `time.Sleep` to order goroutines rather than a channel,
`sync.WaitGroup`, or `require.Eventually`.
say: "Please run `go test -race ./<pkg>/...`; replace the sleep with an
explicit synchronisation so the test is not timing-dependent."

### TEST-007 Platform-specific tests compile on every target
severity: blocker
scope: `**/*_test.go`
check: a test file referencing a `_linux.go` symbol without its own
`_linux.go` suffix or build tag; a test added for Windows/macOS behaviour that
the matrix will never run (say so in the PR).

## How the tests must look

### TEST-010 `require` for setup, `assert` for the condition under test
severity: nit
scope: `**/*_test.go`
check: `assert.NoError` on a setup step whose failure makes later lines panic
or meaningless; `require` on a leaf comparison that should let the test
continue and report the rest. Messages: optional on `NoError`/`Error`, always
present on comparison, boolean, and collection assertions.

### TEST-011 Test real behaviour, not API existence
severity: should
scope: `**/*_test.go`
check: a test that only asserts `err == nil` or `NotNil(result)` after a call,
or asserts that a mock was called, when the observable end state (bytes that
arrived, the row after the write, the translated packet, the rule in the
table) is available.
say: "Assert on what a consumer would see: `<end state>`."

### TEST-012 Avoid mocks for code we own
severity: should
scope: `**/*_test.go`, `**/mock*`
check: a new gomock/mockery mock for a store, manager, or controller that has
a real in-memory or SQLite implementation; a new hand-written fake duplicating
a real component. Accepted mocks: external systems (IdP HTTP APIs, Stripe,
cloud provider SDKs), the WireGuard interface (`iface` mock), network I/O
that cannot run in CI, and the existing `store_mock.go` for pure error-path
tests.
say: "Use the real `<component>` (`newTestStore` / `createManager` helpers) and
assert on the stored result; a mock here tests the mock."

### TEST-013 `t.Setenv`, `t.Cleanup`, `t.TempDir`
severity: nit
scope: `**/*_test.go`
check: `os.Setenv` in a test (use `t.Setenv`; to test the unset case call
`t.Setenv` first then `os.Unsetenv`); `defer` for cleanup in a test with
`t.Parallel` subtests (use `t.Cleanup`); hand-made temp dirs.

### TEST-014 No sleeps, no real network, no wall-clock dependence
severity: should
scope: `**/*_test.go`
check: `time.Sleep` used as synchronisation; a test dialling a public host; a
test asserting on `time.Now()` without injecting a clock or using tolerances.
Flaky tests get re-run blind by nobody here; identify the failure instead.

### TEST-015 Table tests with named cases; parallel where safe
severity: nit
scope: `**/*_test.go`
check: copy-pasted test functions differing by one input; `t.Parallel` on
tests sharing a global (store engine env, a port, a temp file).

### TEST-016 Golden data and fixtures are regenerated by their tool
severity: should
scope: `**/testdata/**`, `integration_tests/**`
check: a hand-edited golden file (the network-map golden data is regenerated
by `mage integrationtest:regenerateNmapGoldenData`; store test fixtures are
the `.sql` files under `management/server/testdata`).

### TEST-017 Explanatory comments in tests are welcome
severity: skip
scope: `**/*_test.go`
check: do not post GO-DOC-002 or the comment-length budget on test files.

### TEST-018 Benchmarks that guard query counts stay green
severity: should
scope: `management/server/**`
check: a change to account loading, peer listing, or network-map generation
without a look at the `*_bench_test.go` and `affected_peers_querycount_test.go`
style tests that pin the number of store queries; a new per-peer or per-group
store call inside a loop.
say: "This adds a store round-trip per <entity>; the benchmark / query-count
tests pin that number. Batch it or load it once up front."
why: the Management Benchmark jobs push results to a Prometheus gateway and
regressions are compared across runs.

## End-to-end

### TEST-020 E2E suites use the shared harness
severity: nit
scope: `e2e/**`
check: a new suite that spins up its own containers rather than using
`e2e/harness`; a suite that is not wired into the matching workflow
(`agent-network-e2e.yml`, `reverse-proxy-e2e.yml`).
