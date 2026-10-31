# 40 Control plane: Management, Signal, Relay, Proxy

Management is a multi-tenant service with two SQL engines, two account
loaders, an in-process event store, and a fleet of released agents that must
keep working after every upgrade. Most logic bugs here are one of five
things: a permission check in the wrong place, a write outside a transaction,
a field that one loader forgot, a change that never reached connected peers,
or a wire change an old agent cannot read. The rules below are ordered that
way. Line references are to OSS `main` at the time of writing.

## HTTP handlers (`management/server/http/handlers/**`, `management/internals/modules/*/manager/api.go`)

### MGMT-H-001 Handler shape is fixed
severity: should
scope: new or changed handler functions
check: the sequence deviates from: (1) `nbcontext.GetUserAuthFromContext(r.Context())`
and `util.WriteError` on failure; (2) path params from `mux.Vars(r)["<entity>Id"]`,
empty rejected with `status.Errorf(status.InvalidArgument, ...)`; (3) body decoded
into the generated `api.<Op>JSONRequestBody`, failure answered with
`util.WriteErrorResponse("couldn't parse JSON request", http.StatusBadRequest, w)`;
(4) one manager call `(r.Context(), userAuth.AccountId, userAuth.UserId, ...)`;
(5) `util.WriteError(r.Context(), err, w)`; (6) `util.WriteJSONObject(...)`,
`util.EmptyObject{}` for DELETE.
why: `management/internals/modules/zones/manager/api.go`,
`handlers/groups/groups_handler.go`. A hand-rolled request struct instead of
the `api.*` type means the OpenAPI spec and the handler can drift.

### MGMT-H-002 No business logic or permission check in a handler
severity: should (blocker when the check is missing everywhere)
scope: handlers
check: `ValidateUserPermissions`, role comparisons, cross-entity validation,
or `store.Store` access in a handler. Existing exceptions
(`peers_handler.go` GetAccessiblePeers, `proxytoken/handler.go`) are not
templates.
say: "Move this to the manager; handlers decode, delegate, encode."
why: reviewers repeatedly asked for validation in the manager, not the
handler (PRs 4428, 5008 in the lessons file).

### MGMT-H-003 Errors reaching `util.WriteError` are `*status.Error`
severity: should
scope: managers and handlers
check: `fmt.Errorf` returned from a manager method to a handler (becomes 500
"internal server error" and logs "unhandled error code"); a status message that
leaks SQL text, another tenant's ID, or internal paths (the message is sent to
the client lowercased). Mapping: InvalidArgument 422, BadRequest 400, NotFound
404, PermissionDenied 403, Unauthorized 401, AlreadyExists 409,
PreconditionFailed 412, TooManyRequests 429, Internal 500. `Unauthenticated`
is currently unmapped and falls to 500; do not rely on it.

### MGMT-H-004 Do not log and then `WriteError`
severity: nit
scope: handlers
check: `log.Errorf(...)` immediately before `util.WriteError` (which logs
again); `http.Redirect(..., 500)` on a missing auth context instead of
`WriteError`.

### MGMT-H-005 Route registration and bypass
severity: blocker for bypass, nit otherwise
scope: `management/server/http/handler.go`, `AddEndpoints`/`RegisterEndpoints`
check: a route without `.Methods("<VERB>", "OPTIONS")`; a new path added to
`bypass.AddBypassPath` (unauthenticated) without a security justification in
the PR; a path param not `{<entity>Id}`.
say: "Adding an unauthenticated route is a security-review item; who signed
off?"

### MGMT-H-006 `activity.SystemInitiator` is a bypass, not a convenience
severity: blocker
scope: any call passing `activity.SystemInitiator` as the user ID
check: a request-path call that passes it before an authorization for the
same account happened in that request.
why: `permissions/manager.go` allows everything for it.

### MGMT-H-007 Two API trees
severity: should
scope: peers and users behaviour
check: a behaviour change in `/api` (`handlers/`) not mirrored in
`management/server/api/v1alpha1/` where that resource exists there, or vice
versa.

### MGMT-H-008 Request bodies are bounded by validation
severity: should
scope: endpoints accepting arrays or free text
check: no length check on arrays or strings in the manager validation;
there is no global `MaxBytesReader`.

## Managers and mutations (`management/server/*.go`, `management/internals/modules/*/manager`)

### MGMT-M-001 Permission check is the first statement of every exported manager method
severity: blocker
scope: exported methods on `DefaultAccountManager` and module managers
check: the canonical block is missing, or its error is wrapped with
`fmt.Errorf` instead of `status.NewPermissionValidationError(err)`, or the
`ctx` it returns is discarded:
```go
allowed, ctx, err := m.permissionsManager.ValidateUserPermissions(ctx, accountID, userID, modules.X, operations.Y)
if err != nil { return status.NewPermissionValidationError(err) }
if !allowed { return status.NewPermissionDeniedError() }
```
A new legacy-style role check (`IsAdminOrServiceUser`, `HasAdminPower`,
`Role ==`) is not accepted; use modules and operations.
why: `policy.go:40`, `zones/manager/manager.go:59`; reviewers asked for
module+CRUD permissions on PRs 5008, 4832, 7514.

### MGMT-M-002 Mutation template
severity: blocker
scope: any method that writes
check: the write is outside `Store.ExecuteInTransaction`; the closure uses
`am.Store` instead of the `transaction` argument; rows that will be modified
are read without `LockingStrengthUpdate`; `affectedpeers.Load` is missing or
runs after a delete; `IncrementNetworkSerial` is missing; activity events are
stored inside the closure instead of collected as `[]func()` and run after
commit; the fan-out call is missing.
why: `policy.go:55-105`, `group.go:75-126`, `networks/resources/manager.go:104-135`.
The single most frequent human review theme on management PRs is locking
strength and get+save inside one transaction (PRs 2867, 4384, 8404).

### MGMT-M-003 A row lock outside a transaction locks nothing
severity: blocker
scope: `LockingStrengthUpdate` / `LockingStrengthShare` arguments
check: a getter called with a lock strength on `am.Store`/`m.store` outside
`ExecuteInTransaction` (autocommit releases it immediately). Six such call
sites exist today (user invite accept, networks and groups managers,
agentnetwork manager); do not add a seventh, and fix them when touched.

### MGMT-M-004 Fan-out after every network-map-affecting change
severity: blocker
scope: changes to peers, groups, policies, routes, DNS, network resources,
settings peers consume, posture checks
check: a committed change with no `ExpandAndUpdateAffected` (targeted,
default), no `UpdateAccountPeers` (account-wide, always
`go am.UpdateAccountPeers(context.WithoutCancel(ctx), ...)`), and no
`BufferUpdateAccountPeers` (high-frequency login/sync paths). A synchronous
`UpdateAccountPeers(ctx, ...)` on the request context is wrong (the request
cancel aborts the push).
say: "Which peers see this change, and when? Nothing here pushes a new
network map."
why: reviewers on PRs 7514 ("settings must reach online peers") and crn4's
"reuse BufferUpdateAccountPeers".

### MGMT-M-005 New network-map dependency extends the resolver and its coverage matrix
severity: should
scope: `management/server/affectedpeers/**`, new entity types referenced by
the network map
check: a new relation that influences which peers are affected without a
`Change` field, `Load`/`Expand` handling, a row in
`TestAffectedPeers_DependencyCoverageMatrix`, and a green
`affected_peers_querycount_test.go`. Affected sets must be computed from the
old state and the new state together.

### MGMT-M-006 Activity events after commit, codes append-only
severity: should
scope: `StoreEvent`, `activity/codes.go`
check: `StoreEvent` inside a transaction closure; a mutation with no event;
a new code that is not the next free integer or has no `activityMap` entry
with a dotted string code; a settings toggle without an Enabled/Disabled
pair through `handleXSettings`; a describer passed to `StoreEvent` that is
not `activity.Activity` (the assertion is unchecked and runs in a goroutine).

### MGMT-M-007 Settings field checklist
severity: should
scope: `types.Settings`, `ExtraSettings`
check: a new field missing any of: `gorm:"default:..."`, `Settings.Copy`,
the pgx `accountQuery` + `Scan`, API conversion in both directions
(`accounts_handler.go`), `validateSettingsUpdate`, the activity pair, and
the peer-push trigger list in `UpdateAccountSettings` if peers consume it.
`ExtraSettings.Flow*` are `gorm:"-"` and belong to the external
`extra_settings.Manager`.

### MGMT-M-008 No `SaveAccount`, no whole-account loads on request paths
severity: should
scope: managers
check: `Store.SaveAccount` (deprecated); `Store.GetAccount` in a request
handler path where a targeted getter exists; network-map paths not going
through `requestBuffer.GetAccountWithBackpressure`.

### MGMT-M-009 No per-entity store calls in loops
severity: should
scope: managers
check: a store getter inside a `for` over peers, groups, or policies; an
`IN (...)` that grows with account size without a batch; a DB call on an
unauthenticated endpoint.
why: query-count tests and benchmarks pin these; reviewers flagged per-peer
store calls on PRs 4096, 5008, 4479.

### MGMT-M-010 In-process locks do not serialise across instances
severity: should
scope: `AcquireGlobalLock`, package-level mutexes, `sync.Map` caches
check: correctness that depends on a process-local lock for a multi-instance
deployment; a cache (`peerLocks`) that grows without pruning.

### MGMT-M-011 Request context: `WithoutCancel`, never `Background`
severity: should
scope: managers
check: `context.Background()` inside a transaction or request path (drops
request, account, and user log fields); work that must outlive the request
(events, fan-out, JWT group sync) started with the request context instead of
`context.WithoutCancel(ctx)`; a long loop that never checks `ctx.Done()`.

### MGMT-M-012 Integration hooks keep their contract
severity: ask
scope: `integrated_validator.IntegratedValidator`, `extra_settings.Manager`,
`account.DeletionHook`, `GRPCExtension`, `proxytoken.RevocationGuard`,
`affectedpeers.SetAgentNetworkSynthesizer`, `activity.RegisterActivityMap`,
`settings.Manager`, `idp.Manager`, the DI container (`Create/Inject`)
check: a signature or semantic change to any of these.
say: "netbird-cloud implements this; is the cloud PR open, and does it merge
after this one?"

## Store (`management/server/store/**`)

### MGMT-S-001 Every query is account-scoped
severity: blocker
scope: `sql_store_*.go`
check: a `Where` on an entity ID without `account_id` (use the shared
`accountAndIDQueryCondition` constants); a lookup by public ID without the
ID-or-PublicID condition.
say: "Cross-tenant read: scope by account ID."

### MGMT-S-002 New column or relation reaches every loader
severity: blocker
scope: `types/*.go` models, `sql_store_account.go`, `network_map_db/**`
check: a new persisted field missing any of: gorm tags; `AutoMigrate` list;
`Preload` in `getAccountGorm`; the pgx `SELECT` and `Scan` in the matching
`getX` (Postgres outside a transaction takes this path and silently loads
zero values otherwise); the `errChan` buffer size when a loader goroutine is
added; the network-map twin store (`network_map_db/{sqlite,pgsql}`) and twin
converters when the network map reads it; `Copy()`; upsert column allowlists
(`groupUpsertColumns`); `DeleteAccount` cascade for non-association tables;
`TestGetAccount_ComprehensiveFieldValidation`, `TestAccount_Copy`, and the
pgx column-parity test where one exists.
why: AGENTS.md Pitfalls "two account loaders"; only `Service`/`Target` have
parity tests today.

### MGMT-S-003 Store error convention
severity: nit
scope: `sql_store_*.go`
check: `gorm.ErrRecordNotFound`/`pgx.ErrNoRows` not mapped to the typed
`status.NewXNotFoundError`; other errors not logged with
`log.WithContext(ctx)` and returned as a generic `status.Errorf(status.Internal, "failed to get X from store")`;
a swallowed `_ = json.Unmarshal` in a pgx scan.

### MGMT-S-004 Create and Update, not `Save`/upsert, unless the column list is explicit
severity: should
scope: `sql_store_*.go`
check: `db.Save(...)` on an entity (clobbers columns the caller did not set,
including `PublicID`); an upsert without an explicit `DoUpdates` column list
that excludes `public_id` and `account_id`.
why: PRs 238 (cloud), 714 (cloud), and the `groupUpsertColumns` comment.

### MGMT-S-005 gorm tags and IDs
severity: nit
scope: new models
check: `ID` without `gorm:"primaryKey"`; `AccountID` without
`json:"-" gorm:"index"`; a slice or struct column without
`gorm:"serializer:json"`; a frequently filtered column without an index; a
server-generated ID not from `xid.New().String()` (users, setup keys, and
jobs are the documented exceptions); `PublicID` reset from an API payload.

### MGMT-S-006 Engine portability
severity: should
scope: raw SQL, gorm clauses
check: SQL that only works on SQLite or only on Postgres (`datetime()`,
`ILIKE`, `NULLS FIRST`, JSON operators, `RETURNING`); a Postgres-heavy index
without `option:CONCURRENTLY`; `NETBIRD_STORE_ENGINE=mysql` assumed to run
MySQL in tests (it silently runs SQLite). MySQL is rejected at open.

### MGMT-S-007 Encrypted-at-rest fields are decrypted on every read path
severity: blocker
scope: user, invite, provider fields using `fieldEncrypt`
check: a new read path (including pgx) that returns the field without
`DecryptSensitiveData`; a write without `EncryptSensitiveData`.

### MGMT-S-008 Client-reported strings are sanitised before persistence
severity: should
scope: anything persisted from peer meta or login
check: a string from the agent stored without `cleanClientString` (Postgres
rejects NUL and invalid UTF-8).

### MGMT-S-009 Argument order at every call with two or more string IDs
severity: should
scope: call sites of store and manager getters
check: the store signature is `(ctx, lockStrength, accountID, entityID)`;
the outlier `GetNameServerGroupByID(ctx, lock, nsGroupID, accountID)` and the
manager's `GetGroupByName(ctx, name, accountID, userID)` vs
`GetGroup(ctx, accountID, groupID, userID)` make swaps easy. New module APIs
use typed IDs (10-go-style GO-TYPE-001).

### MGMT-S-010 No `WithContext` on GORM calls inside the store
severity: skip
scope: `sql_store_*.go`
check: do not ask for `db.WithContext(ctx)` on GORM calls; the maintainers
decided against it (cloud PRs 742, 642 pushed back on the bot). Context goes
to `log.WithContext`, not to GORM.

## Migrations (`management/server/store/store.go` lists, `management/server/migration/**`)

### MGMT-MG-001 Append-only, idempotent, tested on both engines
severity: blocker
scope: `getMigrationsPreAuto`, `getMigrationsPostAuto`, `migration/*.go`
check: a shipped entry edited or reordered; a new step without
`HasTable`/`HasColumn`/`HasIndex` guards and a "no migration needed" debug
exit; a row rewrite not wrapped in `db.Transaction`; a destructive step before
the data move succeeded; no test in `migration_test.go` with pre-migration
data and a second run for idempotency. Pre-auto is for type and encoding
rewrites and backfills; post-auto is for indexes and JSON-to-table moves.
`CreateIndexIfNotExists` always creates a UNIQUE index.
why: AGENTS.md "STOP and ask before writing a store migration"; migrations
are one-way in the field.

### MGMT-MG-002 A migration or persisted-model change is confirmed with the user
severity: ask
scope: as above, plus any `types/*.go` struct tag change
check: present in the diff. Ask whether both the GORM and pgx paths were
considered and whether the release notes mention it.

## Permissions (`management/server/permissions/**`)

### MGMT-P-001 New module: constant, `modules.All`, and per-role review
severity: should
scope: `modules/module.go`, `roles/*.go`
check: a new module not in `modules.All` (the dashboard reads
`GetPermissionsByRole`); no decision recorded on whether Admin should be
restricted (as `Accounts` is); roles with `AutoAllowNew: false` (user,
network_admin, agent_network_admin, usage_viewer, billing_admin) not granted
explicitly where intended; a test in `permissions/manager_test.go` and the
HTTP role-matrix integration test (regular, admin, owner, service user,
service admin, blocked, other-account, invalid token) for the new endpoint.

### MGMT-P-002 Service users read everything; design around it
severity: ask
scope: new read endpoints exposing sensitive data
check: a read endpoint that a service user should not see; the current
resolver grants Read on every module to service users.

## gRPC server (`management/internals/shared/grpc/**`)

### MGMT-G-001 Errors to agents go through `mapError`
severity: should
scope: `Login`, `Sync`, `GetServerKey`, proxy service RPCs
check: a raw sentinel or `status.Error` returned to the client without
`mapError` (agents key off PermissionDenied for re-login, FailedPrecondition
for version gates; everything else is Internal).

### MGMT-G-002 Peer meta is sanitised and version gates are named constants
severity: should
scope: `extractPeerMeta`, anything reading `peer.Meta`
check: a new meta string not passed through `cleanClientString`; an inline
version string; a gate without the development-version bypass.

### MGMT-G-003 Both wire formats stay equivalent
severity: blocker
scope: `conversion.go`, `components_encoder.go`,
`shared/management/networkmap/**`, `types/legacynmap/**`
check: a change to `ToSyncResponse` without the matching change to the
component network map (or the reverse); `*IsEmpty` booleans not maintained
beside repeated fields; deprecated top-level `RemotePeers` no longer
populated for agents older than the cut-off; no run of the `nmapequiv`
equivalence tests mentioned in the PR.
say: "Legacy and component network maps must encode the same state; which
tests prove that here?"

### MGMT-G-004 Sync owns the peer lifecycle
severity: should
scope: `Sync`, `Login`, peer update handler
check: peer connect/disconnect state changed from outside the `Sync` stream
handler; a failure after `OnPeerConnected` that does not call the
cancel-peer-routines path; the stream aborted on a single bad update instead
of continuing.
why: pascal-fischer's recurring review on PRs 4367, 4428.

### MGMT-G-005 Proto types stop at the gRPC layer
severity: should
scope: managers, store
check: a `proto.*` type used below `management/internals/shared/grpc` or
`shared/management/networkmap`; proto structs built inside account-manager
code.

## Logging and metrics

### MGMT-L-001 `log.WithContext(ctx)` everywhere a ctx exists
severity: nit
scope: `management/**`
check: a bare `log.Infof` in request-path code (loses request ID, account,
user, peer fields added by the formatter hook). Boot and background code
without a ctx is exempt.
why: the most frequent single human review theme on management PRs (16
threads).

### MGMT-L-002 Levels and secrets
severity: should
scope: `management/**`
check: peer IPs above debug; user emails above debug without
`types.MaskEmail`; setup keys without `types.HiddenKey`; a DSN or token in a
log; `Error` on a path that also returns the error; `Info` inside a per-peer
or per-request loop.

### MGMT-L-003 Metrics are nil-guarded, named by convention, low cardinality
severity: should
scope: `telemetry.AppMetrics` users
check: a metric call without `if m.appMetrics != nil`; a name not
`management.<area>.<thing>.<counter|duration|...>` with a unit; an account
ID or peer ID as an attribute on a published metric (use the account
aggregator).

## Signal, Relay, Proxy

The same Go, concurrency, and compatibility rules apply. Component-specific
checks:

### SIG-001 Signal is stateless and version-tolerant
severity: should
scope: `signal/**`, `shared/signal/proto`
check: per-peer state that would break multi-instance deployment; a new
message field not `optional` so absence is detectable; a change that needs
both peers to be new without a `featuresSupported` gate.

### RELAY-001 Relay frames carry the version byte; auth stays fail-closed
severity: blocker
scope: `relay/**`, `shared/relay/messages/**`
check: a frame layout change without bumping or branching on the protocol
version; an auth envelope path that accepts a message when validation errors
(`ErrUnsupportedVersion` and auth failures must reject); timeouts missing on
reads from untrusted peers.

### PROXY-001 Identity-aware proxy: every request is authorised, access logs are complete
severity: blocker
scope: `proxy/**`
check: a route added without the auth middleware; an access-log field
dropped; TLS verification relaxed for an upstream; a secret (session code,
token) logged.

### CP-001 Config and flag compatibility
severity: blocker
scope: `management/cmd/**`, `signal/cmd/**`, `relay/cmd/**`, `proxy/cmd/**`,
config structs, env var names
check: a flag renamed or default changed; a config field renamed, retyped,
or moved; a secret read from the environment and then persisted to disk; a
config loaded in a way that an existing deployment's file no longer parses.
say: "Existing deployments carry the old config; keep the old key readable
and document the change."
why: PRs 7306, 4042 in the lessons file; AGENTS.md high-risk areas.
