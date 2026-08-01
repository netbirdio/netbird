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

- [NetBird Agent Guidelines](#netbird-agent-guidelines)
  - [Contents](#contents)
  - [STOP and ask the user before](#stop-and-ask-the-user-before)
  - [Quick reference](#quick-reference)
  - [Structure](#structure)
  - [Where to look](#where-to-look)
  - [Repo-wide principles](#repo-wide-principles)
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

## Repo-wide principles

1. **Run `go fmt` on every modified Go file.** Formatting is not optional.
2. **Zero unaddressed diagnostics.** Fix IDE and linter warnings on code you
   touch, and delete imports, helpers, and parameters your refactor orphaned.
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
8. **Concurrency: do a two-pass race analysis after every change** that adds
   shared state. Guard maps and slices with a mutex, keep critical sections
   short, and run `go test -race` on the touched packages.
9. **Cross-platform builds must keep working.** The agent targets Linux, macOS,
   Windows, FreeBSD, Android, and iOS. When you add a platform-specific file,
   add the counterpart or a build-tagged fallback for the others.
10. **Never hand-edit generated files.** Change the source and regenerate.
11. **Never log secrets** — private keys, setup keys, tokens, PAT values — and
    keep peer IPs and hostnames out of logs above debug level.

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

- **90 characters per line.** Wrap the comment, do not run past it.
- **250 characters per comment**, roughly three wrapped lines. Doc comments on
  exported identifiers may exceed it when the API genuinely needs the
  explanation; inline comments inside a function body may not.

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
  verified, and do not delete rows that do not apply.

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
