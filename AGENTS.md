# NetBird Agent Guidelines

**NetBird** is an open source connectivity platform: a WireGuard®-based overlay
network with a control plane. The **agent** (`client/`) runs on user machines as
a privileged daemon and manages the WireGuard interface, routing, firewall, and
DNS. **Management** (`management/`) is the control plane and REST/gRPC API,
**Signal** (`signal/`) brokers peer handshakes, **Relay** (`relay/`) carries
traffic when a direct tunnel is impossible, and **Proxy** (`proxy/`) is the
identity-aware proxy behind Agent Network.

This file applies to the whole repository, and is the single source of truth for
agent guidance here. `CLAUDE.md` is a one-line pointer to it — keep the guidance
in this file, not duplicated there.

## Contents

- [STOP and ask the user before](#stop-and-ask-the-user-before)
- [Quick reference](#quick-reference)
- [Structure](#structure)
- [Where to look](#where-to-look)
- [Security](#security)
- [Agent conventions](#agent-conventions)
- [Repo-wide principles](#repo-wide-principles)
- [Type safety](#type-safety)
- [Concurrency and lifecycle](#concurrency-and-lifecycle)
- [Error handling](#error-handling)
- [Comments](#comments)
- [Testing](#testing)
- [Pitfalls](#pitfalls)
- [Commits, PRs, releases](#commits-prs-releases)
- [After you push: CI and review bots](#after-you-push-ci-and-review-bots)
- [Discussion and support](#discussion-and-support)

## STOP and ask the user before

- **Opening a pull request for anything beyond a trivial fix, without an agreed
  ticket.** Ask the user directly: *"Is there a discussion or issue for this
  change?"* NetBird is discussion-first — community reports start in
  [Discussions](https://github.com/netbirdio/netbird/discussions), DevRel
  validates them, and only validated discussions become issues. A PR that
  changes behavior with no linked issue may be closed on arrival. If there is no
  ticket, offer to draft the discussion post **instead of** the PR, and wait for
  the user's call. Only typos, broken links, documentation corrections, and
  one-line fixes that already have an issue can skip this.
- **Designing in any high-risk area** (see
  [CONTRIBUTING.md](CONTRIBUTING.md#high-risk-areas)): public API and OpenAPI
  schema, gRPC protos, behavior existing deployments would notice after an
  upgrade, peer connectivity (ICE, NAT traversal, relay selection, WireGuard® or
  Rosenpass key handling), client system integration (routing, firewall, DNS,
  interface), authentication and authorization, CLI or service flags, config
  file format, daemon IPC, store schema and migrations, or a new feature. The
  design gets agreed in the ticket before code is written.
- **Writing a store migration or changing a persisted model.** Migrations are
  one-way in the field and both the GORM and pgx paths may need the change.
- **Hand-editing generated code.** `*.pb.go`, `*.gen.go`, and mocks are outputs.
  Edit the source (`.proto`, `openapi.yml`) and rerun the matching
  `generate.sh`.
- **Adding, removing, or bumping a dependency**, and never vendor a fork.
- **Weakening a security control** — authentication, authorization, certificate
  verification, privilege dropping, or peer identity checks — even when it is
  the fastest way to make a test pass.
- **Force-pushing to `main`**, force-pushing any branch that is already under
  review, amending pushed commits, or bypassing hooks with `--no-verify`.

## Quick reference

```bash
# Build
go build ./...
cd client && CGO_ENABLED=0 go build .        # agent
cd management && go build .                  # management service
cd signal && go build .                      # signal service

# Verify (run before every push)
go fmt ./...
make lint            # golangci-lint on files changed vs origin/main (also the pre-push hook)
make lint-all        # full-repository lint, matches CI
make test-unit       # host-safe unit tests, -tags devcert, no sudo
make test-privileged # privileged-tagged suite in a Docker container with NET_ADMIN
make setup-hooks     # wire make lint into .githooks/pre-push

# Narrow runs
go test ./client/internal/dns/...
go test -race -run TestPeerConn ./client/internal/peer/...
PRIV_RUN=TestNftablesManager PRIV_PKGS=./client/firewall/nftables/... make test-privileged

# Code generation (never hand-edit the output)
./shared/management/http/api/generate.sh   # REST types from openapi.yml
./shared/management/proto/generate.sh
./shared/signal/proto/generate.sh
./client/proto/generate.sh
./flow/proto/generate.sh

# Run locally (lab only, never on a machine you rely on)
sudo ./client/netbird up --log-level debug --log-file console
sudo ./client/netbird down                   # teardown: restores routing, firewall, DNS
./signal/signal run --log-level debug --log-file console
./management/management management --log-level debug --log-file console --config ./management.json
```

`netbird up` needs root and rewrites the host's routing table, firewall rules,
DNS configuration, and WireGuard® interface. Run it only in a disposable test
environment (a VM, container, or throwaway host) that you can rebuild, never on
a workstation or server whose connectivity matters. Run `sudo netbird down`
before you stop working, before rebuilding the binary, and on every failure
path, so the host's networking state is restored instead of left half-applied.
See [Pitfalls](#pitfalls) for why cleanup on every exit path matters.

## Structure

```text
netbird/
├── client/              NetBird agent
│   ├── cmd/             agent CLI
│   ├── internal/        agent business logic (engine, peer, dns, routemanager, ...)
│   ├── server/          daemon for background execution
│   ├── proto/           daemon gRPC protos
│   ├── iface/           WireGuard® interface management
│   ├── firewall/        nftables, iptables, pf, WFP, userspace backends
│   ├── ssh/             built-in SSH server and client
│   ├── ui/              desktop UI (Wails v3 + React)
│   ├── android/, ios/   mobile bindings
│   ├── wasm/            WebAssembly build
│   └── mdm/, system/    MDM policy, host information
├── management/          control plane
│   └── server/          account, peer, groups, networks, posture, permissions,
│                        settings, store, http (REST), idp, integrations, migration
├── signal/              handshake broker (peer/, server/)
├── relay/               relay service (protocol/, server/, healthcheck/)
├── proxy/               identity-aware proxy (llm/, acme/, accesslog/, middleware/, tcp/, udp/)
├── agent-network/       Agent Network overview
├── shared/              imported by both agent and services
│   ├── management/      proto/, client/, http/api (OpenAPI + generated types)
│   ├── signal/          proto/, client/
│   └── relay/, auth/, sshauth/, metrics/
├── e2e/                 end-to-end suites and harness
├── encryption/, dns/, route/, stun/, sharedsock/, util/, flow/
├── infrastructure_files/  docker compose and getting-started templates
└── release_files/       files packaged into releases
```

## Where to look

| Task                        | Location                                                     |
| --------------------------- | ------------------------------------------------------------ |
| REST API / OpenAPI          | `shared/management/http/api/` + `management/server/http/`    |
| Management gRPC protocol    | `shared/management/proto/`                                   |
| Signal protocol             | `shared/signal/proto/`                                       |
| Daemon IPC protocol         | `client/proto/`                                              |
| Peer connection and NAT     | `client/internal/peer/`                                      |
| Network map handling        | `client/internal/engine.go`, `shared/management/networkmap/` |
| Routing                     | `client/internal/routemanager/`, `route/`                    |
| Firewall backends           | `client/firewall/`                                           |
| DNS                         | `client/internal/dns/`, `dns/`                               |
| WireGuard® interface        | `client/iface/`                                              |
| Persistence and migrations  | `management/server/store/`, `management/server/migration/`   |
| IdP integrations            | `management/server/idp/`                                     |
| Permissions model           | `management/server/permissions/`                             |
| LLM routing / Agent Network | `proxy/internal/llm/`, `agent-network/`                      |
| End-to-end tests            | `e2e/`                                                       |

## Security

### Never fail open

When a security check — access control, an IP restriction, an auth decision —
hits an error such as an unparseable value, an unavailable lookup, or a state it
does not recognize, it must **deny**. Never skip the check or allow the request
through because the check itself failed, and make the `default` and unknown cases
of a security-related `switch` deny rather than fall through.

### Daemon RPC input is untrusted

The agent runs as root (LocalSystem on Windows), so a daemon RPC crosses a
privilege boundary: treat every field as untrusted input rather than as something
the UI or CLI validated on the way in.

When you add or change an RPC, ask what the handler does with caller input while
running as root. If the answer touches a filesystem path, a URL or host, or a
privileged state change, it needs a gate **in the handler** — a check in the client
that normally calls it is not a check at all.

- **A caller-supplied path the daemon opens.** Never `os.Open` it as root.
  Constrain it, then open it *as the caller* with `ipcauth.OpenOwnedFile`, which
  opens `O_NOFOLLOW`, requires a regular file, and refuses a file the caller does
  not own — so a symlink or hardlink aimed at a root-only file is rejected.
- **A caller-supplied URL or host the daemon fetches.** Restrict the scheme and
  allow only known hosts for unprivileged callers. Prefer a lexical host
  allowlist plus TLS verification over "resolve the host, then reject private
  IPs": the resolve-then-trust pattern has a DNS-rebinding race (public IP at
  check time, attacker IP at connect time), while a name allowlist has no IP
  check to race. Never accept `http://` where `https://` is expected.
- **A privileged state change** (SSH root login, management URL, deregistration)
  gates on the caller identity from `ipcauth.CallerIdentity(ctx)`.

Caller identity comes from the kernel — `SO_PEERCRED`, `LOCAL_PEERCRED`, or the
named-pipe client token — and never from an RPC field. When
`ipcauth.CallerIdentity` reports that it could not determine an identity, **deny**;
do not fall back to treating the caller as the transport peer.

## Agent conventions

### Three networking modes

Where packets actually flow depends on the mode the agent is running in. The
three are not interchangeable, so establish which one a change applies to — and
what it should do in the other two — before you write it.

- **kernel mode** (Linux only): in-kernel WireGuard®. The kernel handles both
  peer-to-peer and routed traffic, and ACLs are iptables or nftables rules. The
  client programs kernel facilities but never sees the traffic itself.
- **userspace mode** (wireguard-go with a TUN): wireguard-go runs in-process. The
  kernel handles peer-to-peer traffic once it leaves the TUN, while routed traffic
  — exit nodes and network routes — goes through the userspace forwarder, which
  terminates the connection and re-establishes it over OS sockets. Used on
  platforms without kernel WireGuard® or when the user opts out.
- **netstack mode**: wireguard-go in-process with no TUN and no kernel
  networking. The forwarder does all routing by stitching userspace sockets, and
  listeners such as the embedded SSH and DNS servers bind on a gVisor netstack.
  Used where the process cannot create a TUN device, such as the embedded client
  (`client/embed/`) and the WASM build.

### The overlay interface is not "WireGuard"

Do not put "WireGuard" in identifiers or comments unless the code is genuinely
coupled to WireGuard® specifically — a wireguard-go call, a handshake field, a
kernel WireGuard® netlink attribute. For the interface, the host, peers, or
traffic in general, say "the NetBird interface", "the interface", or "the overlay".
Most firewall, routing, and DNS code is transport-agnostic, so a WireGuard®
reference there is simply inaccurate and rots as the transports change.

### IPv6 is a soft feature

The IPv6 overlay is opt-in dual-stack, and capability can change at runtime. Treat
it as soft rather than a requirement:

- Gate local v6 paths on the interface accessor (`wgIface.Address().HasIPv6()`),
  not on raw state fields, and skip the v6 path when the host has no v6 rather
  than returning an error.
- Treat an empty or unparseable peer v6 address as "no v6 for that peer" and skip
  it, keeping the v4 path working.
- Never let a missing v6 break v4. Fail-closed is for security checks; a
  capability mismatch skips the v6 work and carries on.

### Environment variables

Name the variable in a constant and parse booleans with `strconv.ParseBool` rather
than comparing strings inline, so an unexpected value is logged instead of
silently meaning false:

```go
const EnvDisableFeature = "NB_DISABLE_FEATURE"

func isDisabledByEnv() bool {
    val := os.Getenv(EnvDisableFeature)
    if val == "" {
        return false
    }
    disabled, err := strconv.ParseBool(val)
    if err != nil {
        log.Warnf("failed to parse %s: %v", EnvDisableFeature, err)
        return false
    }
    return disabled
}
```

### Validating against protocol specs

When a change depends on what a protocol actually mandates, read the specification
text from the [IETF datatracker](https://datatracker.ietf.org/) rather than a
summary, and check that you have the current RFC — the widely cited one for a
protocol is often superseded. Cite the section, not just the document, so a
reviewer can jump straight to the rule.

## Repo-wide principles

1. **Run `go fmt` on every modified Go file.** Formatting is not optional.
2. **Zero unaddressed linter warnings.** Fix what `golangci-lint` reports on code
   you touch, and delete imports, helpers, and parameters your refactor orphaned.
   Exception: unused parameters in shared code may be consumed by builds outside
   this repository — do not remove them, ask instead.
3. **Function comments are mandatory for exported functions**, written as full
   sentences with a period, starting with the identifier name.
4. **Prefer private functions and constants.** Export only what a caller outside
   the package genuinely needs.
5. **Early returns and guard clauses.** Handle errors and edge cases first
   instead of nesting `if`/`else` chains.
6. **Split complex functions.** If a function trips a complexity warning, break
   it into named helpers rather than silencing the warning.
7. **Avoid LLM-slop tells:** em dashes, hedging narration, restating the diff in
   prose, trailing summaries. Defaults, not absolute bans. Applies to code,
   comments, commit messages, and PR descriptions alike.
8. **Concurrency: do a two-pass race analysis after every change** that touches
   shared state, including reads of existing maps and slices. Guard them with a
   mutex (or an atomic or channel where that fits better), keep critical
   sections short, and run `go test -race` on the touched packages. See
   [Concurrency and lifecycle](#concurrency-and-lifecycle) for the failure modes
   to check for.
9. **Cross-platform builds must keep working.** The agent targets Linux, macOS,
   Windows, FreeBSD, Android, and iOS. When you add a platform-specific file,
   add the counterpart or a build-tagged fallback for the others.
10. **Never hand-edit generated files.** Change the source and regenerate.
11. **Never log secrets** — private keys, setup keys, tokens, PAT values — and
    keep peer IPs and hostnames out of logs above debug level.

## Type safety

**No bare primitives for domain concepts.** A `string` parameter for an account
ID next to a `string` parameter for a peer ID is two bugs waiting to happen,
because the compiler cannot catch the swap. Declare the type once and use it
throughout, converting only at the boundaries where data enters or leaves —
protobuf, gRPC, HTTP, an external library.

```go
type ServiceID string
type AccountID string

// Internal: typed all the way through
func (r *Router) RemoveRoute(host SNIHost, svcID ServiceID) { ... }

// Proto boundary: convert once, on the way in and on the way out
svcID := ServiceID(mapping.GetId())
req.ServiceId = string(svcID)
```

- **IP addresses are `netip.Addr`**, not `string` and not `net.IP`. Parse at the
  boundary and pass the typed value inward.
- **Always `Unmap()`** after parsing an address, after converting from `net.IP`,
  and after extracting one from `RemoteAddr()`. This normalizes a v4-mapped v6
  address (`::ffff:10.1.2.3`) to plain v4 so IPv4 rules match it. A stored or
  compared mapped address silently fails to match those rules.
- **Ports are `uint16`** internally; use `int` only where a library forces it and
  convert immediately.
- **Enums are a typed string with constants**, so the valid set is discoverable
  and a typo fails to compile.
- **Map keys follow the same rule**, and must be a real type (`type ServiceID
  string`) rather than an alias (`type serviceID = string`) — an alias silently
  accepts bare strings.

## Concurrency and lifecycle

Beyond the mutex hygiene in the principles above, check for these failure
modes.

- **Never read a struct field inside a goroutine** when another goroutine may nil
  or reassign it. Pass the value as a parameter, or capture it into a local before
  launching. This matters most when `Stop()` nils a field without waiting for the
  goroutine to finish.

  ```go
  go func(ifaceName string) {   // good: passed in, cannot be nilled underneath
      m.Start(ctx, ifaceName)
  }(iface.Name())
  ```

- **Never wait on a channel while holding a lock the sender needs.** Copy what you
  need out from under the lock, release it, then wait.

  ```go
  func (m *Manager) Stop() {
      m.mu.Lock()
      cancel, done := m.cancel, m.done
      m.mu.Unlock()
      if cancel != nil {
          cancel()
          <-done
      }
  }
  ```

- **`Stop`/`Close` must be idempotent** — guard on an already-stopped flag or a
  nil cancel — and must release the state they guarded. Clear maps and caches;
  a cancelled goroutine holding a live map still pins that memory. Note that a
  nil map only panics on writes; reads and iteration behave like an empty map,
  so where post-close use must be rejected, check the stopped flag explicitly.
- **Publish coupled state only after every fallible step succeeds.** When several
  fields form an invariant, build them into locals and assign them to the receiver
  at the end. Assigning as you go leaves the object half-initialized when a later
  step fails, so a readiness predicate reports ready while a coupled field is nil.
  If an earlier step already had an external side effect — a created chain, an
  opened handle, an inserted rule — roll it back before returning the error.
- **Clean up what you own on constructor error paths.** Once a constructor has
  started something, every later error path must undo it: cancel a goroutine and
  wait for it to exit, stop a ticker, close a watcher. The object is never
  returned, so its `Close` will never run.
- **A failed `Start` must undo everything it started.** When a component brings up
  several subsystems in sequence — connection manager, watchers, routing, DNS,
  flow, persisted state — a failure partway through has to tear down the ones
  already running, not just close the handle the error came from. Put the
  already-started guard *before* that teardown path, so a rejected second `Start`
  cannot dismantle the one that is running.

## Error handling

Use single-assignment form when the error is only needed inside the `if`:

```go
// Good
if err := someCall(); err != nil {
    return fmt.Errorf("context: %w", err)
}

// Bad - unnecessary split
err := someCall()
if err != nil {
    return fmt.Errorf("context: %w", err)
}
```

Use multiple assignment when the value is needed after the block:

```go
result, err := someCall()
if err != nil {
    return fmt.Errorf("context: %w", err)
}
```

Add short, meaningful context, and **do not** start `fmt.Errorf` messages with
obvious words like "failed to" or "error":

```go
// Good
return fmt.Errorf("parse remote address: %w", err)
return fmt.Errorf("listen on %s: %w", addr, err)

// Bad
return fmt.Errorf("failed to parse remote address: %w", err)
return fmt.Errorf("error listening on %s: %w", addr, err)

// "failed" is fine in log messages
log.Debugf("failed to parse remote address: %v", err)
```

Skip the wrapping when a function only extracts or delegates and the wrap would
add nothing:

```go
func parseAddr(addr string) (string, int, error) {
    host, portStr, err := net.SplitHostPort(addr)
    if err != nil {
        return "", 0, err
    }
    // ...
}
```

Log the errors you choose not to act on:

- `log.Debugf()` for errors that do not affect program flow but help debugging.
- `log.Tracef()` for very verbose errors that would otherwise spam logs.
- **Never ignore** errors from writes, network sends, or critical cleanup.
- Close errors may be ignored for read-only operations; log them at debug for
  writes.

**Do not log and return the same error.** It gets reported twice, from two places,
and the second reader cannot tell whether it happened once or twice. Return it and
let the caller decide. The exception is an API handler that has already written a
response. Internal helpers return errors rather than logging and swallowing them.

**Never return a typed nil as an error.** A nil `*MyError` stored in an `error`
interface is not nil, so `err != nil` is true and callers take the failure path on
success. Return the error only where it is actually set:

```go
if _, err := conn.Write(buf); err != nil {   // good
    return err
}
return nil
```

**Accumulate with `multierror` when an operation should continue past individual
failures** — teardown, cleanup, or setup where partial success is acceptable.
`client/errors.FormatErrorOrNil` returns nil for an empty accumulator, so callers
still see a plain nil on full success:

```go
func (m *Manager) Cleanup() error {
    var merr *multierror.Error
    for _, r := range m.resources {
        if err := r.Close(); err != nil {
            merr = multierror.Append(merr, fmt.Errorf("close %s: %w", r.Name, err))
        }
    }
    return nberrors.FormatErrorOrNil(merr)
}
```

| Scenario              | Approach              | Why                                       |
| --------------------- | --------------------- | ----------------------------------------- |
| Cleanup / teardown    | Accumulate            | Clean up as much as possible              |
| Setup with rollback   | Abort on first error  | Partial state is invalid; undo what stuck |
| Setup with partial OK | Accumulate            | Degraded operation is still useful        |

## Comments

Comment the **why**, never the **what**. Default to no comment, and add one only
when a hidden constraint or workaround would surprise a future reader. Never
reference the current task, PR, or your own changes in a comment.

```go
// Bad - trailing comments explaining the obvious
defer localConn.Close() // Close the connection
if err != nil {         // Check if error occurred

// Good
defer localConn.Close()

// Good - explains a non-obvious constraint
// Use incremental checksum update per RFC 1624 for performance.
checksum = updateChecksum(checksum, oldPort, newPort)
```

### Length budget

Neither of these is linter-enforced, so they are conventions the surrounding code
mostly follows rather than hard limits:

- **Around 90 characters per line.** Wrap the comment rather than running well past
  it.
- **Roughly 250 characters per comment**, about three wrapped lines. Doc comments
  on exported identifiers may exceed it when the API genuinely needs the
  explanation; inline comments inside a function body rarely should.

The budget is a smell detector, not a rule to game. Do not compress a needed
explanation into cryptic shorthand to fit — if a block of code needs more than
250 characters of prose, the code is doing too much. Fix the code:

- **Extract a named function.** A well-named function replaces the comment: the
  name says *what*, the body shows *how*, and the comment you no longer write
  was the *what* anyway. Clean Code calls this "explain yourself in code".
- **Extract a named constant or predicate.** `if isExpiredSetupKey(key)` needs
  no comment; `if key.ExpiresAt.Before(now) && !key.Revoked && key.UsageLimit > 0`
  does.
- **Keep the surviving comment for the why** — the RFC, the kernel quirk, the
  ordering constraint. That part is usually one or two lines.

### Long switch and if/else chains

A `switch` whose cases carry multi-line explanations is the usual place this
budget is breached, and the comment is a symptom. In order of preference:

1. **Extract each case body into a named function.** The case becomes one line,
   the name carries the meaning, and the switch reads as a table of contents.
2. **Replace the switch with a lookup table** — `map[Kind]handlerFunc` — when the
   branches are uniform. Adding a case stops meaning editing a growing function.
3. **Replace conditional with polymorphism** when branches vary by type and the
   same switch shape starts appearing in more than one place. Clean Code's rule
   of thumb: tolerate a switch statement if it appears **once**, is buried in a
   factory that returns an interface, and no other switch dispatches on the same
   type. A second switch over the same enum is the signal to introduce the
   interface.

Do not restructure a switch purely to satisfy the budget when the cases are one
line each and self-evident — a flat, boring `switch` over an enum is fine and
needs no comments at all.

Explanatory comments in tests are welcome — they document the scenario being set
up, and the 250-character budget does not apply to them.

## Testing

- **Unit tests** live beside the code as `_test.go`. `make test-unit` runs the
  host-safe set with `-tags devcert` and no sudo.
- **Privileged tests** carry the `privileged` build tag and mutate host
  networking. They run through `make test-privileged`, inside a Docker container
  with `NET_ADMIN`. Never bypass that harness by running them directly on the
  host.
- **End-to-end suites** live in `e2e/` with a shared harness.
- **Test real behavior, not API existence.** Assert on the observable end state
  a consumer would see — bytes that arrived, the packet after translation, the
  row after the write — not merely that a method exists or returns an error.
- **Avoid mocks for code we own.** Exercise the real store, manager, or
  controller and assert what the caller actually receives.
- **`require` for setup and preconditions, `assert` for the conditions under
  test.** Use `require` whenever a later line would panic or be meaningless
  otherwise.
- **Message guidance:** optional for `NoError`/`Error`; always give context for
  comparison, boolean, and collection assertions.
- **Reproduce a bug before fixing it.** Write the test, watch it fail *for the
  reason you expect* — a test that fails for an unrelated reason proves nothing —
  then apply the fix and confirm it passes. Add the thin surrounding cases while
  you are there.
- **Use `t.Setenv`** rather than `os.Setenv` so the previous value is restored on
  cleanup. To test the unset case, call `t.Setenv` first to register the restore,
  then `os.Unsetenv`.
- **Prefer `t.Cleanup` over `defer`** in any test with parallel subtests: the
  parent function returns, running its `defer`s, while parallel subtests are
  still suspended. Sequential subtests finish inside `t.Run`, so `defer` is safe
  there, but `t.Cleanup` works in both cases.
- **Explanatory comments in tests are welcome.** Describe the scenario being set
  up; the comment budget below does not apply to them.

```go
server, err := StartTestServer()
require.NoError(t, err, "Test server setup must succeed")
defer server.Close()

result, err := client.DoOperation()
assert.NoError(t, err)
assert.Equal(t, expectedResult, result, "Result should match expected")
```

## Pitfalls

- **The agent runs as root.** Anything touching routing, firewall, DNS, or the
  interface can take a user's machine off the network. Prefer a reversible
  change and make sure cleanup runs on every exit path.
- **Management has two account loaders** (GORM and pgx). Adding a relation to an
  account often means updating both, or it silently comes back empty in
  production.
- **`go test ./...` without `-tags devcert` skips tests** that need the
  development certificate. Use `make test-unit`.
- **`make lint` only checks the diff against `origin/main`.** CI runs
  `make lint-all`; run it too before pushing a large change.
- **Protos are consumed by released clients.** An old agent must keep working
  against a new Management, so fields are added, never renumbered or removed.
- **Windows requires the wintun driver**, and the daemon serves a named pipe
  (`npipe://netbird`) rather than loopback TCP. Loopback TCP carries no caller
  identity, so privileged operations are refused over it.

## Commits, PRs, releases

- **PR titles must start with a bracketed tag.** Before you propose a title,
  **read [`.github/workflows/pr-title-check.yml`](.github/workflows/pr-title-check.yml)
  and take the allowed tags from the `allowedTags` array in that file.** It is
  the only source of truth, it changes as components are added, and the check
  runs on every title edit — a tag that is not in that array is a red build. Do
  not rely on a list memorized from anywhere else, including this file.

  ```text
  [client] Authorize daemon IPC callers by their local identity
  [management,client] Add MDM policy support
  ```

  Multiple tags are comma-separated inside one pair of brackets. Match the tag
  to the component you actually changed, not to the one you read the most.

- **Use the repository's PR template.** Fill in
  [`.github/pull_request_template.md`](.github/pull_request_template.md) rather
  than replacing it with your own summary: describe the change, link the issue,
  tick the checklist honestly (including "ran locally" and "single purpose"),
  and complete the documentation section. Do not tick a box you have not
  verified, and do not delete rows that do not apply — the docs gate in CI reads
  that section and fails when it is missing.

- **Keep the PR description short.** Under 1000 words on top of the template's
  own text, and usually far less — a few paragraphs. Reviewers read the diff;
  the description exists to explain what the diff cannot say for itself. This is
  well below what an agent will produce by default, so cut before you post.

- **Body: why before what.** Lead with the problem and the reason for this
  approach, then the shape of the change. No bullet list of files changed, no
  per-function walkthrough, no restating the diff in prose, no trailing summary
  section, no self-congratulatory closing line.

- **No `Co-Authored-By` or tool-attribution trailers in the PR description**,
  and none in commits either. Contributors own their contributions. Whatever
  tooling produced the diff, the person opening the PR is its author: they have
  read every line, they can explain why it works, they can answer review
  questions without going back to a model, and they are accountable for the
  consequences of merging it. Do not add a trailer, footer, or description line
  that spreads that ownership onto a tool.

- **Commit subjects follow the same `[scope] Subject` convention.** Keep the
  subject short, and use the body for why before what. No bullet lists of files
  changed.

- **Push review fixes as separate commits.** The PR is squashed on merge, so
  there is no reason to rewrite history mid-review; many small commits make the
  re-review readable.

- **Do not force-push a branch that is under review.** A force-push detaches
  existing review comments from the lines they were written against, destroys
  the "changes since your last review" diff a reviewer relies on, and discards
  the CI history that showed which commit broke what. Add commits instead —
  including for fixups and reverts. Force-push only when there is no
  alternative: a rebase to clear a genuine conflict, or removing a secret or a
  large binary that was committed by mistake. When you must, ask the user first,
  then say so in a PR comment so reviewers know their anchors moved. Never
  force-push `main`, and never force-push a branch you do not own.

- **One PR, one purpose.** Split refactors out of fixes and fixes out of
  features.

- **Keep the PR small.** Size is the single strongest predictor of how long a PR
  waits. Aim for **under ~400 changed lines across under ~20 files**; past
  roughly **1000 lines or 50 files** a community PR is likely to be sent back to
  be split, or left unreviewed until it is. Large PRs from outside the core team
  may be blocked outright when the size was never agreed in the ticket —
  reviewing a sprawling change against a privileged networking daemon is a
  security risk in itself, not just a time cost.

  Judge the size by hand-written code: exclude generated output, `go.sum`,
  vendored files, and test fixtures from the estimate, but do not use their
  presence to argue a 3000-line PR is small.

  When a change genuinely cannot be small — a protocol migration, a
  cross-component rename — agree the split in the ticket **before** writing
  code, and land it as a sequence of PRs that each build, test, and make sense
  on their own. Propose that split to the user rather than opening one large PR
  and hoping.

  Prefer GitHub's stacked pull requests for such a sequence, rather than
  hand-managing base branches: open each PR against the branch below it instead of
  `main`, so every PR's diff shows only its own change. Merging a layer retargets
  the PRs above it, and branch protections and required checks on the base branch
  still apply to each one.

- **User-facing changes need a docs PR** in
  [netbirdio/docs](https://github.com/netbirdio/docs), linked from the PR
  description.

## After you push: CI and review bots

Opening the PR is not the end of the task. Watch the run, read what the bots
say, and drive the PR to green before you report the work as done.

```bash
gh pr checks <pr>            --watch    # all checks, live
gh run view <run-id> --log-failed       # only the failing steps
gh pr view <pr> --comments              # bot and human review comments
```

**Never report a change as finished while checks are pending or red**, and never
describe a red PR as passing. If you ran out of turn before CI finished, say
which checks were still running.

### The checks

- **Go tests** — `golang-test-{linux,darwin,windows,freebsd}.yml`, sharded per
  component. A failure in a component you did not touch is usually a real
  interaction, not noise; read the log before assuming flake.
- **golangci-lint** — `golangci-lint.yml` runs the full repository, while
  `make lint` only checks your diff. A clean local lint does not guarantee green
  CI on a large change.
- **PR Title Check** — `pr-title-check.yml`, see above.
- **Codecov** — uploaded from the Linux test workflow with per-component flags
  (`unit,client`, `unit,management`, `unit,relay`, `unit,proxy`, `unit,signal`,
  `integration,management`). Coverage on new code should not go backwards. Add
  tests for the paths you introduced; do not adjust thresholds or exclude files
  to clear the report.
- **CodeRabbit** — configured in [`.coderabbit.yaml`](.coderabbit.yaml): `chill`
  profile, auto-review on every non-draft PR, TypeScript/JavaScript/SVG paths
  filtered out. Chat auto-reply is on, so `@coderabbitai` in a comment reaches
  it.
- **SonarCloud** — project `netbirdio_netbird`, quality gate on new code (bugs,
  vulnerabilities, code smells, duplication, coverage).
- **Snyk** — dependency and code scanning.

Sonar and Snyk report as GitHub App checks rather than workflows in this
repository, so their detail lives on the PR check, not in the Actions logs.

### Handling bot findings

- **Read every comment and act on it.** Either fix it, or reply with the reason
  it does not apply. Do not bulk-resolve threads to clear the count, and do not
  silently ignore a finding because the check is advisory.
- **Bots are frequently wrong here.** NetBird has privileged, platform-specific,
  and concurrency-heavy code that static analysis reads poorly. A confident
  CodeRabbit or Sonar comment can still be nonsense. Verify the claim against
  the code before you change anything — never edit correct code just to silence
  a bot.
- **Security findings get the opposite default.** For a Snyk or Sonar
  vulnerability, or a CodeRabbit comment about authentication, authorization,
  certificate verification, or key handling, assume it is real until you have
  disproved it. Surface it to the user rather than dismissing it yourself.
- **A new vulnerable dependency is a stop.** Bumping or replacing dependencies
  needs the user's decision, as above.
- **Never change a workflow, threshold, lint exclusion, or bot config to make a
  check pass.** If a check is genuinely wrong, say so and let the user decide.
- **Do not paper over flakes with blind re-runs.** Identify the failure first. If
  it is a known flake, name it; if you cannot tell, report it as unresolved
  rather than re-running until it goes green.

## Discussion and support

- Discussions: <https://github.com/netbirdio/netbird/discussions>
- Slack: <https://docs.netbird.io/slack-url>
- Docs: <https://docs.netbird.io>
- Security: <https://github.com/netbirdio/netbird/security/policy> — never in public
- Contribution process: [CONTRIBUTING.md](CONTRIBUTING.md)
