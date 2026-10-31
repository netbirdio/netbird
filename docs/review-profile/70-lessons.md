# 70 Lessons: what human reviewers keep asking for

Mined from human review threads on netbirdio/netbird pull requests (bots
excluded: CodeRabbit, cubic, Copilot, Sonar, Codecov, Snyk, GitHub Actions,
the Crowdin and sync bots). Roughly 55 control-plane PRs and 55 agent PRs
between 2024 and 2026, about 260 human threads in total. Each theme below is
a rule the team has already enforced by hand, with the PRs where it happened,
so an agent can post it with a citation instead of an opinion.

Use this file for calibration: if an agent's findings on a PR do not look
like this list, the agent is probably reviewing the wrong things.

## Theme counts

| Rank | Control plane (threads) | Agent (threads) |
| --- | --- | --- |
| 1 | Logging discipline (16) | Lifecycle: leaks, Stop, cleanup on every exit (25) |
| 2 | Layering and scope (14) | Concurrency: unguarded fields, lock scope (20) |
| 3 | Locking strength and transactions (14) | Simplify: dead code, constants, exports (18) |
| 4 | Permissions and authorization (11) | Error context and log level (15) |
| 5 | Compatibility for existing deployments (10) | Fail-closed, partial apply, security gates (12) |
| 6 | Unnecessary DB work (9) | Tests that run in CI and prove the fix (10) |
| 7 | Missing or weak tests (8) | Platform parity and placement (9) |
| 8 | Context usage (8) | Behaviour change and compat (9) |
| 9 | Naming (8) | Go style: imports, file layout, no string IPs (8) |
| 10 | Error handling (7) | Process: description, scope, bots (8) |

Reviewer signatures, so an agent knows whose standard it is applying:
pascal-fischer (locking strength, no log-and-return, `log.WithContext`,
OpenAPI as source of truth, Sync owns the peer lifecycle), mlsmaycon
(module permissions, masked secrets, validation in the manager, single
purpose), lixmal (ctx and timeouts everywhere, lock scope, `%w` with context,
no string IPs, no "WireGuard" naming, hot-path cost, pushes back on wrong
bots), pappz (Stop waits and is idempotent, `WaitGroup.Add` before `go`,
v4/v6 cleanup symmetry, nftables batch order, import order and file layout,
"tests must run in CI", asks for kernel evidence), pnmcosta (store
performance, FKs and indexes, both engines), bcmmbaga (`log.WithContext`,
unused params, hoist work out of loops), riccardomanfrin (mobile Stop/Run
edge cases, iOS and Android parity, behaviour-change disclosure, scope).

## Rules, control plane

### LES-CP-001 Do not log and return; do not drop existing logs
Log where the error is handled. A refactor that removes or downgrades a log
line justifies each removal. Where a failure means something is seriously
wrong (built-in group missing, local DNS record write failing), log even
when the code continues. PRs 2867, 2461, 4367.

### LES-CP-002 Lock what you will write, inside the transaction
A read that precedes a write or delete of the same row uses
`LockingStrengthUpdate`; read-modify-write runs inside
`ExecuteInTransaction` or becomes a single UPDATE. When a comparison against
the old row decides whether to write, read it with update strength. Prefer
explicit `CreateX`/`UpdateX` over `SaveX` with ON CONFLICT. Do not add new
account-level locks; they are being removed. PRs 2867, 4384, 8404.

### LES-CP-003 Permissions through the manager, gates fail closed
Every new handler or manager method validates through the permissions
manager with a module and a CRUD operation; no `role ==` or `IsAdmin` in
business logic. RPCs acting on a peer's data verify the requesting peer owns
it. A request shape that skips a check (old client, missing field) is denied.
MDM-pinned values override caller-supplied values everywhere. PRs 5008,
4832, 3444, 7514.

### LES-CP-004 Call out what existing deployments will notice
A new empty data directory, an env var parsed differently, log-level
precedence, a filter silently not applied for a role, a migration: each is
named in the PR description. Store migrations prefer gorm index tags and are
tested on both engines. Environment-sourced secrets are never persisted into
on-disk config. PRs 7306, 4042, 4096, 8190.

### LES-CP-005 No per-entity DB calls, no DB on unauthenticated paths
Fetch once and filter in memory; avoid `IN (group_ids)` that grows with the
account; no DB call on unauthenticated endpoints (cache at construction);
do not fan out or bump the network serial when nothing changed. PRs 4096,
5008, 4479.

### LES-CP-006 Context: detach background work, never GORM `WithContext`
`go am.UpdateAccountPeers(...)` and events use `context.WithoutCancel`, not
the request context; long loops check `ctx.Done()`; store methods do not
take `WithContext(ctx)`, so a cancelled request cannot abort an in-flight
write. PRs 4384, 5627, 4832, 7514.

### LES-CP-007 Tests that fail when a field is added
`Equal`, `Copy`, and `Clone` get completeness tests; store changes run on
all engines; edge cases (dev and unknown versions, zero values, invalid
input) are covered; validation tests read the DB independently of the code
under test; test names describe the scenario. PRs 8404, 4042, 4479, 5008.

### LES-CP-008 Layering
Sync owns the peer lifecycle; no proto types below the gRPC layer; shared
helpers (pprof, crypt) live in one package; validation in the manager, not
the handler; export only what is needed; a dependency bump or a metrics
addition is its own PR. PRs 4367, 4428, 5008, 4971.

### LES-CP-009 Errors at the boundary
Handlers return through `util.WriteError` so NotFound and permission errors
map to the right status; wrap with `%w` and include the offending value; a
stream handler that fails on one message continues; persist the real failure
reason, not a generic one. PRs 4384, 3252, 4367.

### LES-CP-010 Spec and generated code
`types.gen.go`, `*.pb.go`, and mocks are never hand-edited; every handler
type is defined in `openapi.yml`; every scalar carries an example; demo
payloads do not ship in the schema. PRs 4384, 8190.

### LES-CP-011 Events and fan-out
Every activity constant has an `activityMap` code in present tense; the
payload describes what was requested; create and invite are distinct codes;
a settings change that peers consume triggers the fan-out carrying the
config, not nil. PRs 7514, 5008.

### LES-CP-012 Naming and leftovers
Types are named for their scope (`PeerJob`, not `Job`); PII helpers say so;
ports are `uint16`; unused parameters, stale metrics, commented leftovers,
and example code are removed before review. PRs 4384, 5008, 6105.

### LES-CP-013 Never return a secret, never persist one from the environment
Client secrets are masked in responses; a token from the environment is not
written back to the config file; an "insecure" bypass flag is not accepted
from an unprivileged caller. PRs 7306, 7514.

## Rules, agent

### LES-CL-001 Goroutines: ctx, bounded waits, tracked, values captured
Every goroutine takes a `ctx` and checks it; anything that can block (exec,
sudo prompt, HTTP, netlink) gets a timeout; `WaitGroup.Add` goes before
`go`; a field `Stop` nils is passed into the goroutine, not read inside it;
long goroutine bodies become named functions. PRs 4256, 4717, 7329.

### LES-CL-002 Stop waits, is idempotent, and has one owner
Cancelling the context is not stopping; `Stop` waits for its goroutines with
a bounded wait; a second `Stop` must not block; state is freed either by
`Stop` or by ctx cancellation, never both; `Run` without an interleaved
`Stop` is rejected or safe; state cleared in `Stop` is also cleared when
`Run` returns an error. A stop signal on an unbuffered channel can be
missed; channels closed from more than one path use `sync.Once`. PRs 4256,
4563, 7329, 5758, 8392.

### LES-CL-003 Partial start leaks the started half
"If the UDP ListenAndServe returns an error we leak the TCP listener": track
them together and tear down what started. On Windows a spawned helper needs
`WaitDelay` or a Job object. PRs 5758, 8052.

### LES-CL-004 Guard every field touched from two goroutines
A lock that only wraps the constructor protects nothing; copy values out
before leaving the critical section; do not reuse the network-map mutex on
the DNS resolution path; refcounted resources keyed by content (nftables
sets) must not be released by one rule's rollback while another depends on
them. PRs 4256, 4717, 4732, 6767, 3379, 7447.

### LES-CL-005 Never log a failure and report success
Roll back the installed part and return the error, or keep retrying, but the
caller must learn the ACL was not fully applied. Order netlink batches so set
deletes follow the rule deletes that reference them. Invalid input returns
an error rather than being clamped. Persist state after success, not before.
Check ownership before deleting a profile or record. PRs 7447, 5631, 4732,
7216.

### LES-CL-006 A privilege gate evaluates the condition the action uses
"uploadURL set, upload=false, uploadInsecure=true passes the gate" is a
bypass, and old CLI and UI binaries send exactly that shape. A management
setting change reaches online peers through the fan-out, not after
reconnect. Downloaded binaries are verified against a hash from management,
not from the same release page. PRs 7514, 4256.

### LES-CL-007 Tests must run in CI and the author must have run the change
A test file in a package excluded from every CI job has never executed;
tick "ran locally" only after doing it; a fix in a privileged area gets a
regression test that drives the real kernel path; tests do not mutate host
state they do not restore, and do not hang on platforms with interactive
tools; test helpers do not ship in the production build. PRs 7252, 7447,
8394, 5675.

### LES-CL-008 Platform parity and placement
Platform-only code lives in the `_<os>.go` file; architecture is considered
(arm64 Windows); localized OS error strings are never matched; Go APIs over
shelling out; the `netbird-ui` counterpart is handled; iOS and Android
behave the same unless documented; claims about platform commands are
verified on the real OS; every CI platform stays green. PRs 8052, 8394,
7528, 5706, 5688, 4256.

### LES-CL-009 v4 and v6 are symmetric
v4 and v6 routers do not keep separate counters for shared host state;
every cleanup that resets v4 resets v6 (`route6.Reset()`); unimplemented v6
placeholders are removed, not left as dead branches. PRs 5707, 5708, 4792.

### LES-CL-010 Behaviour changes are disclosed and isolated
A config file does not gain empty objects for unset features; fail-loud
startup changes and storage changes are called out; enabling one feature
does not silently change another (mTLS forcing WS-only relay); proto
changes bump the daemon proto version, use `optional`, and regenerate with
the pinned tools. PRs 5416, 7955, 7216, 5675, 5631.

### LES-CL-011 Simplify
Magic strings become constants; nothing is exported without an external
caller; pointless wrappers, dead placeholders, unused fields, and needless
assertions are deleted; duplicated logic with the engine becomes a function;
names describe behaviour (`ReadConfigOrDefault`, not `GenerateConfig`);
a two-step activate/deactivate that immediately tears down becomes one step.
PRs 4256, 4015, 4563, 7398, 6382, 7262.

### LES-CL-012 Error context and log levels
Every returned error carries short context in the repository's format;
ignored errors are logged; routine messages are debug with the data that
makes them useful; sibling log lines share a level; a stale log message is a
blocker; a PR about something else does not remove log lines or drop
returned errors. PRs 4256, 3379, 4717, 7528, 4367.

### LES-CL-013 Go style the reviewers enforce by hand
Import order std, third party, NetBird; file layout consts and vars, then
types, then methods, free functions last; no `string` for IP addresses; no
"WireGuard" in a transport-agnostic layer; experimental flags are marked
`[Experimental]` in help text. PRs 4256, 4563, 5707, 6382, 6767, 3379.

### LES-CL-014 Hot path cost
Parse env vars once in the constructor; no per-peer work for all peers when
only proxy peers need it; no `GetPeer` on the hit path; buffers allocated
outside the read loop; per-network-map work debounces internally. PRs 6767,
7705, 3379, 4256.

### LES-CL-015 Process
Update the description to match the final change before re-review; address
bot comments before asking for human review but push back with reasons when
they are wrong; keep scope tight ("preexisting, not a regression" is a valid
note, not a reason to grow the PR); rebase a branch hundreds of commits
behind. PRs 7447, 6779, 4700, 8380, 4367, 7549, 5416.

## What humans no longer comment on

Since early 2026 most inline review on core-maintainer PRs is bot-driven;
dense human review concentrates on community PRs and cross-reviews between
core members. Bots already cover "missing test case" and `Unmap()` reminders,
so humans rarely repeat them. The themes in the brief with no human hits in
the sample were netstack and userspace mode handling, DNS restore, route
cleanup, and config flags added without a daemon RPC field. Those remain
rules (50-client.md) because the code makes them necessary, not because a
reviewer had to say them recently.
