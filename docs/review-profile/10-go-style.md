# 10 Go style

Mechanical Go rules shared by every component. Most are `nit`: post them
batched, with a suggestion block where the fix is a one-liner, and never block
on them. The linter configuration is
[`.golangci.yaml`](../../.golangci.yaml) (golangci-lint v2, `default: none`,
explicit enable list); anything that configuration reports is CI's job, not
the agent's (README noise policy, rule 1).

## Errors

### GO-ERR-001 No "failed to" or "error" prefix in `fmt.Errorf`
severity: nit
scope: `**/*.go`
check: `fmt.Errorf("failed to ...` , `fmt.Errorf("error ...`,
`errors.New("failed to ...`. Log messages may say "failed to".
say: "Drop the prefix: `fmt.Errorf(\"parse remote address: %w\", err)`."
why: AGENTS.md Error handling. The prefix repeats at every wrap level and the
message reads "failed to x: failed to y: failed to z".

### GO-ERR-002 Wrap with `%w`, add short context, or return bare when delegating
severity: nit
scope: `**/*.go`
check: `fmt.Errorf("...: %v", err)` or `%s` where the error is returned (loses
`errors.Is`/`As`); a wrap that adds no information
(`fmt.Errorf("split host port: %w", err)` around `net.SplitHostPort`).
say: "Use `%w` so callers can `errors.Is` it" or "This wrap adds nothing; return
`err` directly."

### GO-ERR-003 Single-assignment `if err :=` when the error is only used inside
severity: nit
scope: `**/*.go`
check: `err := f()` immediately followed by `if err != nil { return ... }` with
no later use of `err` or of another returned value.
say: "`if err := f(); err != nil {` keeps the scope tight."

### GO-ERR-004 Do not log and return the same error
severity: should
scope: `**/*.go`
check: `log.Errorf(...err...)` or `log.Warnf` immediately followed by `return
err` or a wrap of it, outside an HTTP or gRPC handler that has already written
its response.
say: "Return it or log it, not both; the caller already reports it and the
reader cannot tell whether it happened twice."

### GO-ERR-005 Never return a typed nil as `error`
severity: blocker
scope: `**/*.go`
check: a function returning `error` that declares `var e *SomeError` (or
assigns a concrete pointer type) and returns `e` on the success path.
say: "A nil `*SomeError` stored in `error` is non-nil; return `nil` literally on
success."

### GO-ERR-006 Errors not acted on are logged at the right level
severity: should
scope: `**/*.go`
check: `_ = f()` or an ignored second return on a write, send, `Close` after
a write, or cleanup. Read-only `Close` may be ignored.
say: "Log this at debug (or act on it); writes, sends, and cleanup errors are
never dropped silently."

### GO-ERR-007 Teardown accumulates, setup aborts
severity: should
scope: functions named `Close`, `Stop`, `Cleanup`, `Reset`, `Remove*`,
`Start`, `Init`, `Setup`, `New*`
check: a cleanup loop that returns on the first error (leaves the rest dirty),
or a setup that continues after an error without rolling back. The
accumulator is `multierror` with `nberrors.FormatErrorOrNil` so an empty
accumulator returns plain `nil`.
say: "Cleanup should continue past individual failures and return the
accumulated error (see `client/errors.FormatErrorOrNil`)." or "Setup partial
state is invalid: undo what already succeeded before returning."

### GO-ERR-008 Transport boundaries convert errors once
severity: should
scope: `management/server/http/**`, `management/server/grpcserver/**`,
`client/server/**`
check: an HTTP handler that writes a raw `err.Error()` with an ad hoc status,
or a gRPC handler that returns an unclassified error. See 40-control-plane.md
for the `status.Errorf` + `util.WriteError` mapping.

## Comments and naming

### GO-DOC-001 Exported identifiers have a sentence doc comment
severity: nit (CI reports it: revive `exported`)
scope: `**/*.go`
check: an exported func, type, const, or var without a comment that starts
with the identifier and ends with a period. Only post it when lint has not
run yet, and never block.

### GO-DOC-002 Comments explain why, not what
severity: nit
scope: `**/*.go`
check: a trailing comment that paraphrases the line (`// close the
connection`), a comment that references the PR, the task, or "this change",
or a comment block over ~250 characters inside a function body.
say: "Delete the what-comment" / "Pull the block into a named function and
keep the one-line why."
why: AGENTS.md Comments and Length budget. Explanatory comments in tests are
exempt.

### GO-DOC-003 No LLM-slop tells
severity: nit
scope: `**/*.go`, markdown, commit messages
check: em dashes in code comments or commit text, "Note that", "It's worth
noting", "This ensures that", "In order to", restating the diff, trailing
"Summary" sections, hedging ("may potentially").
say: "Plain sentence, no narration."
why: AGENTS.md Repo-wide principles 7. Default, not a ban; do not post it as
the only finding on a PR.

### GO-NAME-001 "WireGuard" only where the code is coupled to WireGuard
severity: should
scope: `client/**`, `route/**`, `dns/**`
check: a new identifier, log line, or comment containing `wg`/`WireGuard`
for the interface, host, peers, or traffic in firewall, routing, DNS, or
status code. Allowed: wireguard-go calls, handshake fields, netlink WG
attributes, `client/iface` internals, existing `wgIface` plumbing.
say: "Say 'the NetBird interface' / 'the overlay'; this code is
transport-agnostic."
why: AGENTS.md "The overlay interface is not WireGuard".

### GO-NAME-002 Prefer unexported
severity: nit
scope: `**/*.go`
check: a new exported identifier used only inside its package. In `shared/`
and other library packages, ask instead of asserting; external builds consume
them.

### GO-NAME-003 Environment variables are named constants parsed with `strconv.ParseBool`
severity: should
scope: `**/*.go`
check: `os.Getenv("NB_...")` with a string literal at the call site, or a
boolean env compared as `== "true"` / `!= ""`.
say: "Name it `const EnvX = \"NB_X\"` and parse with `strconv.ParseBool`, logging
a parse failure at warn, per AGENTS.md Environment variables."

## Type safety

### GO-TYPE-001 No bare primitives for domain IDs
severity: should
scope: `**/*.go`
check: a new function with two or more adjacent `string` parameters that are
IDs (account, peer, user, group, policy, route, service, setup key), or a map
keyed by a bare `string` ID. Convert at protobuf/HTTP/library boundaries only.
say: "Two adjacent `string` IDs cannot be caught when swapped; use the typed ID
(`type PeerID string`) through the internal path."
why: AGENTS.md Type safety. Note `type X = string` is an alias and silently
accepts bare strings; it must be `type X string`.

### GO-TYPE-002 IPs are `netip.Addr`/`netip.Prefix`, unmapped
severity: should
scope: `**/*.go`
check: a new field, parameter, or map key holding an address as `string` or
`net.IP`; a `netip.ParseAddr`, `netip.AddrFromSlice`, or `AddrPort().Addr()`
whose result is stored or compared without `.Unmap()`.
say: "Parse at the boundary into `netip.Addr` and call `Unmap()`; a v4-mapped v6
address silently fails to match IPv4 rules."

### GO-TYPE-003 Ports are `uint16`, enums are typed strings with constants
severity: nit
scope: `**/*.go`
check: a port carried as `int` beyond the library call that forced it; a new
string "enum" compared against literals in more than one place.

## Concurrency and lifecycle

These are `should` by default and `blocker` when the code runs in the agent
daemon (root) or guards store state in management.

### GO-CONC-001 Two-pass race check on shared state
severity: should
scope: any diff that reads or writes a struct field, map, or slice from more
than one goroutine
check: a map or slice read outside the mutex that guards its writes; a new
goroutine that reads a receiver field which `Stop`/`Close` nils or reassigns.
say: "Capture `<field>` into a local (or pass it as a parameter) before `go
func`; `Stop` nils it without waiting." Ask for `go test -race` on the touched
package in the PR.
why: AGENTS.md Repo-wide principles 8 and Concurrency and lifecycle.

### GO-CONC-002 Never wait on a channel or call out while holding a lock the other side needs
severity: should
scope: `**/*.go`
check: `<-done`, `wg.Wait()`, a callback invocation, a network call, or a
store call between `mu.Lock()` and `mu.Unlock()` (or under a `defer
mu.Unlock()`).
say: "Copy what you need under the lock, release it, then wait/call."

### GO-CONC-003 `Stop`/`Close` idempotent and releasing
severity: should
scope: methods named `Stop`, `Close`, `Shutdown`
check: a second call would double-close a channel, cancel a nil func, or
panic; maps and caches are not cleared (a cancelled goroutine holding a live
map pins it); post-stop use is not rejected where it must be (a nil map only
panics on write).

### GO-CONC-004 Publish coupled state only after every fallible step
severity: should
scope: constructors, `Start`, `Init`
check: receiver fields assigned one by one between fallible calls, so an
error mid-way leaves a half-initialised object that a readiness check reports
as ready; an earlier external side effect (chain created, handle opened, rule
inserted) not rolled back on a later error.
say: "Build into locals, assign to the receiver at the end; roll back
`<side effect>` on the error path."

### GO-CONC-005 A failed `Start` undoes what it started, and the already-started guard comes first
severity: blocker in `client/**`, should elsewhere
scope: `Start` methods that bring up several subsystems
check: a return on error after subsystem N without tearing down 1..N-1; an
"already running" check placed after the teardown path so a rejected second
`Start` dismantles the running one.

### GO-CONC-006 Constructors clean up on their own error paths
severity: should
scope: `New*` functions
check: a goroutine, ticker, watcher, or handle started in a constructor and
not stopped before a later `return nil, err`. The object is never returned,
so its `Close` never runs.

### GO-CONC-007 `context.Context` first, propagated, never stored
severity: nit
scope: `**/*.go`
check: a new function taking `ctx` in any position but the first; a struct
field of type `context.Context` (except the request-scoped ones already in the
codebase); `context.Background()` or `context.TODO()` where a caller context
is available.

## Logging

### GO-LOG-001 Never log secrets
severity: blocker
scope: `**/*.go`
check: a log call whose arguments include a private key, preshared key, setup
key, token, PAT, password, session cookie, or an object whose `String()`
includes one (config structs, login requests, `PeerLogin` payloads).
say: "`<field>` is a secret; log a redacted form or nothing."
why: AGENTS.md Repo-wide principles 11.

### GO-LOG-002 Peer IPs and hostnames stay at debug or below
severity: should
scope: `client/**`, `management/**`, `signal/**`, `relay/**`
check: `log.Infof`/`Warnf`/`Errorf` (or structured equivalents) that
interpolate a peer's overlay or public IP, FQDN, or hostname.
say: "Keep peer addresses and names at debug; above that log the peer ID or
key fingerprint."

### GO-LOG-003 Levels: debug for unactionable, trace for spam, warn for degraded, error for broken
severity: nit
scope: `**/*.go`
check: `log.Errorf` on a path that retries or recovers (should be warn/debug);
`log.Infof` inside a per-packet, per-peer-tick, or per-request loop (should be
debug/trace); a new `log.Warnf` that fires on every normal startup.

### GO-LOG-004 No `fmt.Print*` outside the CLI root commands
severity: nit (CI reports it: forbidigo)
scope: `**/*.go` except `management/cmd/root.go`, `signal/cmd/root.go`
check: `fmt.Println`/`Printf`/`print`. Only mention if lint has not run.

## Structure of functions

### GO-FN-001 Early returns, guard clauses
severity: nit
scope: `**/*.go`
check: a new `if ... { <long body> } else { return/err }` shape, or three or
more nesting levels added.

### GO-FN-002 Split rather than silence complexity
severity: should
scope: `**/*.go`
check: a `//nolint:gocyclo`, `//nolint:funlen`, or `//nolint:gocritic` added
to a new or grown function.
say: "Break it into named helpers; a nolint on complexity is not accepted."

### GO-FN-003 Long `switch` cases become named functions or a table
severity: nit
scope: `**/*.go`
check: a `switch` where cases carry multi-line explanatory comments or more
than roughly ten lines each; a second `switch` over the same enum elsewhere in
the package (signal to introduce an interface).
why: AGENTS.md "Long switch and if/else chains".

### GO-FN-004 `nolint` carries a reason
severity: nit
scope: `**/*.go`
check: `//nolint:<linter>` without a trailing `// reason` on a new line.
Existing style in the repo: `//nolint:gosec` on generated-file writes in
`magefiles/openapi.go`; prefer fixing over suppressing.

## Formatting

### GO-FMT-001 `gofmt`/`goimports` clean, import groups std / third-party / netbird
severity: nit
scope: `**/*.go`
check: unformatted file (CI's formatter step), or imports not grouped in the
three blocks the rest of the file uses. Post only as a suggestion.

### GO-FMT-002 Line length around 90 for comments
severity: nit
scope: `**/*.go`
check: a comment line well past 90 characters. Code lines are not held to it.
