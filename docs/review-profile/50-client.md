# 50 Client: the agent

The agent runs as root, rewrites the host's routing, firewall, DNS, and
interface, and has to do the same thing on Linux, macOS, Windows, FreeBSD,
Android, iOS, and in WASM. Review here is about three questions: does it
build and behave on every platform, does every host mutation get undone on
every exit path, and does the concurrency hold up under Stop. Line references
are to OSS `main` at the time of writing.

## Platform files and build tags

### CLI-PLAT-001 `_linux.go` builds on Android, `_darwin.go` builds on iOS
severity: blocker
scope: `client/**`, `util/**`, `sharedsock/**`, `route/**`, `dns/**`
check: a new `_linux.go` file in a package Android imports without
`//go:build !android` (or `linux && !android`); a `_darwin.go` file that must
not build on iOS without `!ios`; a `_unix.go` file with no tag at all
(`_unix` is not an implicit constraint).
why: Go treats android as linux and ios as darwin for suffixes. 47 of 95
`_linux` files carry `!android`; the rest live in packages mobile never
imports. Mobile CI only builds `./client/android/...` and `./client/ios/...`
(`mobile-build-validation.yml`), so a mistake surfaces at release.

### CLI-PLAT-002 The fallback file is the exact complement
severity: blocker
scope: pairs of `<name>_<os>.go` and `<name>.go` / `<name>_other.go` / `<name>_non<os>.go`
check: the fallback's tag is not the boolean complement of the specific
file's effective constraint including the filename. Canonical pairs:
`client/firewall/create.go` `!linux || android` with `create_linux.go`
`!android`; `client/server/state_generic.go` with `state_linux.go`;
`client/iface/iface_new.go` `!linux && !ios && !android && !js` with its four
siblings. Prefer `_other.go` for a catch-all and `_non<os>.go` for a
single-OS complement; `_generic.go` already means three different things and
should not be reused without a tag that matches the name.

### CLI-PLAT-003 Platform-split types without a shared interface change together
severity: should
scope: `client/server/state_{linux,generic}.go`,
`client/internal/iface{,_windows}.go`, `client/internal/dns/wgiface{,_windows}.go`,
`client/internal/routemanager/iface/iface{,_windows}.go`,
`routemanager/notifier/notifier_{android,ios,other}.go`,
`client/net/{dialer,listener}_init_*.go`, `client/net/env_*.go`,
`client/iface/iface_{new,create,destroy}_*.go`,
`client/internal/dns/{host,server,upstream,unclean_shutdown}_*.go`,
`client/internal/engine_{generic,js}.go`, `engine_stdnet{,_android}.go`,
`engine_sessionwatch{,_android,_js}.go`
check: one file of a set changed without its siblings; a method added to
`wgIfaceBase` in `client/internal/iface_common.go` without updating
`MockWGIface` in `engine_test.go`. The Windows DNS `wgiface` is a hand copy
that already lacks `ToInterface`; do not widen the drift.
say: "`<sibling>` has the same method set with no interface; mobile builds
break only at release time. Update it in this PR."

### CLI-PLAT-004 Ask for mobile and WASM builds on platform changes
severity: ask
scope: any `//go:build` change, any `_android`/`_ios`/`_js`/`_mobile` file
check: present in the diff.
say: "Please paste the output of `GOOS=android go build ./client/android/...`,
`GOOS=ios go build ./client/ios/...`, and the WASM build; CI compiles only
those entry points."

### CLI-PLAT-005 `runtime.GOOS` switches do not replace file splits
severity: nit
scope: `client/**`
check: a new `switch runtime.GOOS` in a package that already splits by file
suffix; platform-only code in a file with no constraint.

## The three networking modes

### CLI-MODE-001 Say what the change does in kernel, userspace, and netstack
severity: should (blocker for firewall and routing paths)
scope: `client/firewall/**`, `client/internal/dns/**`,
`client/internal/routemanager/**`, `client/internal/engine_ssh.go`,
`client/iface/**`, `client/internal/netflow/**`
check: a change on one side of an `IsUserspaceBind()`, `GetNet() != nil`, or
`netstack.IsEnabled()` branch without a statement in the PR about the other
two. Mode is decided in `client/iface/iface_new_linux.go`: netstack env,
then kernel module present, then userspace TUN; every other OS is always
userspace bind.
say: "Which mode did you run this in? What happens in the other two?"

### CLI-MODE-002 Userspace bind on Linux still uses the kernel firewall
severity: should
scope: `client/firewall/create_linux.go`, `client/firewall/uspfilter/**`
check: a change described as "for userspace mode" made only in uspfilter.
Linux userspace bind with working nftables or iptables uses the native
backend plus a `HooksFilter` for in-memory DNS; uspfilter does ACLs and
routing only on non-Linux, forced (`NB_FORCE_USERSPACE_FIREWALL`,
`NB_FORCE_USERSPACE_ROUTER`), native-unavailable, and netstack hosts.

### CLI-MODE-003 Kernel mode has no fallback; netstack has no kernel
severity: blocker
scope: `createNativeFirewall`, anything calling netlink, nftables, iptables,
sysctl, route tables, firewalld, the interface monitor
check: a new failure path in native firewall creation (fails `Start` on
every kernel-mode host); a kernel facility called without a
`netstack.IsEnabled()` skip (netstack has no interface, no
`InterfaceAllower`, no route table, no fwmark).

### CLI-MODE-004 Optional firewall capabilities are type-asserted, not added to `Manager`
severity: nit
scope: `client/firewall/manager/firewall.go`
check: a method added to the `Manager` interface that only one backend
implements. Follow `localIpUpdater` and `RegisterNetstackService`: define a
small interface and assert on `e.firewall`.

## Engine lifecycle

### CLI-LIFE-001 New components go into `Start` and into `stopLocked`, nil-guarded
severity: blocker
scope: `client/internal/engine.go`
check: a component created in `Start` without a stop in `stopLocked`;
a stop in `stopLocked` that panics when `Start` failed before creating it;
the `started` guard moved after the deferred `cancel(); stopLocked()`.
why: `stopLocked` serves both a failed `Start` and `Stop`. Order matters:
conn manager, network monitor (first, so it cannot restart the engine),
SSH, watchers, status reset, peers, routes, DNS forwarder, DNS (before the
interface goes down), job executor, interface and firewall close, flow
(after the interface), state manager persist.

### CLI-LIFE-002 Sync step order is load-bearing
severity: blocker
scope: `updateNetworkMap`, `handleSync`
check: a step reordered or inserted without a reason in the PR. Peer config
applies before the serial check (the IP can change without a serial bump);
firewall local IPs and the legacy flag toggle before routes; the lazy
connection HA map is updated before routes apply; `SetExcludeList` runs
after peers are added; the serial advances last. A nil `PeerConfig` must not
reset the cached lazy flag, a nil `NetworkMap` must not clear posture
checks, and a legacy map must not clobber cached components.

### CLI-LIFE-003 `syncMsgMux` is the big lock
severity: should
scope: engine callbacks
check: a callback that takes `syncMsgMux` without re-checking `e.ctx.Err()`
inside it; an uncancellable or long call under it without a timeout
(system info is bounded to 15 s, DNS forwarder stop to 2 s); a recovery
path (`SetPerformance`) that blocks on it.

### CLI-LIFE-004 Engine goroutines are tracked and capture by value
severity: should
scope: `go func` in the engine and its managers
check: a goroutine without `shutdownWg.Add(1)` before `go` and
`defer Done()` inside; a receiver field read inside the goroutine that
`Stop` nils (pass `e.ctx`, the interface name, the client, as parameters).

### CLI-LIFE-005 Stop waits outside the lock, is bounded, and is idempotent
severity: blocker
scope: every `Stop`/`Close` in `client/**`
check: a `wg.Wait()` under a mutex that the waited goroutines take; an
unbounded wait on a goroutine that may never return (mobile reviewers flag
this often); a second `Stop` that double-closes; a `Stop` that reports
"stopped" before the work finished.
why: `Engine.Stop` waits on `shutdownWg` after unlocking, with a timeout of
10 s plus 100 ms per peer, capped at 30 s. The lessons file lists five
distinct shutdown deadlocks found in review.

### CLI-LIFE-006 Every host mutation has a crash-recovery state
severity: blocker
scope: routing, firewall, DNS, port-forward, interface code
check: a new host mutation without a `ShutdownState` type implementing
`Name()` and `Cleanup()`, registered in both `client/server/state_linux.go`
and `state_generic.go`; `UpdateState` called after the mutation rather than
before or with it; `DeleteState` called before cleanup fully succeeded
(iptables skips it on failure, correctly; nftables deletes unconditionally,
do not copy that).
why: `RestoreResidualState` runs at daemon start and on `netbird down`; a
failed cleanup keeps the state for a retry.

### CLI-LIFE-007 Status recorder: snapshot under the lock, notify outside
severity: should
scope: `client/internal/peer/status.go`
check: a notifier or event dispatch called while `d.mux` is held; peer-list
changes during sync without `FinishPeerListModifications()` at the end;
user-visible state changes not published through `PublishEvent`.

### CLI-LIFE-008 Connect loop invariants
severity: should
scope: `client/internal/connect.go`
check: a login `PermissionDenied` that does not set `StatusNeedsLogin` and
`backoff.Permanent`; a path on `engineCtx.Done()` that skips
`engine.Stop()`, `ClientTeardown`, or `backOff.Reset()`; a cancelled context
returned as an error.

## Firewall

### CLI-FW-001 Backend inventory and naming
severity: nit
scope: `client/firewall/**`
check: a new chain not following the backend's case (`netbird-*` lowercase
in nftables, `NETBIRD-*` uppercase in iptables); a set name not derived
from the hash helper; a rule ID not typed `RuleID`. Backends in the tree:
iptables, nftables, uspfilter. There is no pf or WFP backend; macOS,
Windows, FreeBSD, and mobile use uspfilter.

### CLI-FW-002 Sources: one family, never empty for "any"
severity: should
scope: `AddFilterRule`, `AddRouteFiltering`, callers
check: mixed v4 and v6 sources in one rule; an empty source slice meaning
"any" (returns `ErrNoSources`; use an explicit `/0`); a prefix not passed
through `UnmapPrefix`; a batch of adds without a `Flush()`.

### CLI-FW-003 Close accumulates and keeps state on failure
severity: should
scope: backend `Close(stateManager)`
check: an early return in `Close` (must `multierror` through reset families,
backend extras, firewalld untrust); v6 reset not gated on `hasIPv6()`;
`DeleteState` after a failed step.

### CLI-FW-004 Content-deduplicated rules alias
severity: ask
scope: ACL changes, BlockLANAccess
check: a rule added whose content could equal an existing rule's (backends
dedupe by content; a later delete removes both). Ask the author to confirm.

### CLI-FW-005 Privileged tests, not `Geteuid` skips
severity: should
scope: `client/firewall/**/*_test.go`
check: a test with `os.Geteuid() != 0` skip instead of the `privileged`
tag; a uspfilter test that needs root (uspfilter tests are in-process and
unprivileged by design).

## Routing

### CLI-RT-001 Marks, tables, and rules are constants
severity: blocker
scope: `client/net/fwmark.go`, `routemanager/systemops/**`
check: a hard-coded fwmark (new marks are offsets from the base in
`fwmark.go`, overridable through `NB_FWMARK_BASE`); a hard-coded table ID
or rule priority (table `0x1BD0`, rules 105 and 110); a `SetupRouting` step
without the matching `CleanupRouting` rollback; a sysctl changed without
recording the original.

### CLI-RT-002 Kernel routes go through the refcounter
severity: blocker
scope: `routemanager/**`
check: a direct netlink or `route add` call outside `refcounter.Counter`;
a route or allowed-IP mutation without persisted `ShutdownState`.

### CLI-RT-003 Route ranking and switch reasons stay in sync
severity: should
scope: `routemanager/client/client.go`
check: a change to the ranking (connected, metric, direct over relayed,
latency) without updating `tierCompare`, `switchReasonOver`, the hysteresis
holds, and `relayed_switch_test.go`; a switch without a `switchReason`.

### CLI-RT-004 Exit node rules
severity: should
scope: `routemanager/manager.go` exit node selection
check: more than one exit node selectable; the `-v6` partner not inheriting
the v4 selection; a persisted user selection overridden by a management
auto-apply route; selection not persisted through `SelectorState`.

### CLI-RT-005 Notifier methods exist in all three files
severity: should
scope: `routemanager/notifier/**`
check: a method added to one of `notifier_{android,ios,other}.go` only.

## DNS

### CLI-DNS-001 Restore before the interface goes down, delete state only on success
severity: blocker
scope: `client/internal/dns/**`
check: `restoreHostDNS` ordered after interface close; state deleted when
restore failed; a new host manager without `restoreUncleanShutdownDNS` on
Unix and a `"dns_state"` `ShutdownState` for its platform; a Windows NRPT
rule not prefixed with `NRPTKeyPrefix` (cleanup enumerates by it).

### CLI-DNS-002 Handler chain priorities are the existing constants
severity: should
scope: `handler_chain.go`, new handlers
check: a literal priority; a handler that does not pass to the next by
writing NXDOMAIN with the `Zero` bit; a new match-only domain path that
bypasses `DomainConfig.MatchOnly`.

### CLI-DNS-003 Mode-aware listener and upstream
severity: should
scope: `server.go`, `service_listener.go`, `upstream_*.go`, `dnsfwd`
check: a socket listener assumed in userspace bind (it is the in-memory
service); a custom port on a host manager without `supportCustomPort`
leaving `RouteAll` on; an upstream dial that ignores `wgIface.GetNet()` in
netstack.

### CLI-DNS-004 Domain lists stay at debug
severity: should
scope: host managers
check: full search or match domain lists logged at Info (they are customer
hostnames). Existing violations in the systemd, NetworkManager, resolvconf,
file, and Windows managers are fixed when touched, not copied.

## Daemon IPC and config

### CLI-IPC-001 Privileged RPCs gate on kernel-derived identity, in the handler
severity: blocker
scope: `client/server/**`, `client/internal/ipcauth/**`
check: a new RPC that changes privileged state (management URL, SSH
server or root login, remote jobs, metrics address, deregistration,
file paths, URLs the daemon fetches) without `ipcauth.IsPrivilegedCaller`
or `CallerIdentity` in the handler; identity taken from a request field;
"could not determine identity" treated as allowed; a caller path opened as
root instead of through `ipcauth.OpenOwnedFile`; an `http://` URL accepted.
Each gated area has `*_gate.go` plus `*_gate_test.go`; follow that layout.
why: AGENTS.md Security, "Daemon RPC input is untrusted".

### CLI-IPC-002 Privileged and MDM-controlled config fields are enumerated
severity: blocker
scope: `client/server/ssh_gate.go` `privilegedConfigChange`, `client/server/mdm.go`
check: a new config field that affects who can become root or who
authorises SSH not listed in `privilegedConfigChange`; an MDM-controllable
field not in the `ConflictBool` checks; a lock acquisition that takes
`s.mutex` before `guardedConfigMu` (`lock_order_test.go`).

### CLI-IPC-003 A config field fans out to all layers
severity: should
scope: new daemon config field or CLI flag
check: fewer than roughly a dozen files touched. The full set: three proto
messages (`LoginRequest` optional, `GetConfigResponse`, `SetConfigRequest`
optional) and regeneration; `ConfigInput`, `Config`, and `apply()` with a
change log in `profilemanager/config.go` (plus `applyMDMPolicy` and `mdm`
keys when managed); `SetConfig`, `GetConfig`, and login in
`client/server/server.go`; the flag constant in `cmd/system.go` and the
three request builders in `cmd/up.go` guarded by `Flag(x).Changed`;
`createEngineConfig`, `loginToManagement`, `EngineConfig`; `system.Info`
flags and `applyInfoFlags`; the debug bundle config dump; `client/embed`
options; `client/ui/services/settings.go`; mobile bindings if exposed.
The usual misses are the debug bundle, `system.Info`, and one `up.go`
builder.

### CLI-IPC-004 UI and CLI tolerate an older daemon
severity: should
scope: `client/cmd/**`, `client/ui/**`
check: a new RPC called with no handling of `codes.Unimplemented`; a new
response field dereferenced without a zero-value default.

### CLI-IPC-005 Env-to-flag precedence is `NB_` over `WT_`
severity: nit
scope: `client/cmd/**`
check: a new env read that checks `WT_` first (`ssh.go` already inverts
the order; do not copy it) or drops the parse error.

## Peer connectivity

### CLI-PEER-001 Callback guard shape
severity: should
scope: `client/internal/peer/**`
check: a new callback that does not lock `conn.mu` and return on
`conn.ctx.Err() != nil` (and the per-attempt watcher ctx where one exists);
a helper that needs the lock not named `*Locked` or documented "Caller must
hold"; a wait for a goroutine that re-enters under the lock.

### CLI-PEER-002 Transport priority and fallback
severity: should
scope: `conn.go`, `worker_ice.go`, `worker_relay.go`, `conntype`
check: an ICE upgrade that does not pause the relay proxy and redirect the
endpoint; an ICE disconnect without relay fallback; `NB_FORCE_RELAY` or
`GOOS=js` paths that still start ICE; the `wgConfigWorkaround` 100 ms sleep
removed (WireGuard ignores a second endpoint update that arrives too soon).

### CLI-PEER-003 Lazy connections
severity: should
scope: `client/internal/lazyconn/**`, `conn_mgr.go`
check: `ConnMgr` accessed without `syncMsgMux` (only `ActivatePeer` has
its own lock); a lazy decision that ignores the env, MDM, management
precedence; the minimum peer version constant changed inline.

### CLI-PEER-004 Concurrency vocabulary
severity: nit
scope: `client/**`
check: a mutex field not named `mu` or `<thing>Mu`; a `sync/atomic` function
on a plain field instead of a typed atomic (client CI runs on 386, where
alignment matters); a new package-level mutable global.

## Environment variables

### CLI-ENV-001 Named constant, `ParseBool`, warn on bad value, read at use time
severity: should
scope: `client/**`, `util/**`
check: `os.Getenv("NB_...")` with a literal; `== "true"`, `EqualFold`, or
`ParseBool` with the error dropped; a read in `init()` or a package-level
var without a reason (it defeats `t.Setenv`); a second definition of an
existing name (`NB_DISABLE_NAT_MAPPER` is already defined twice).
why: AGENTS.md Environment variables. Known violators (`NB_WG_KERNEL_DISABLED`,
`NB_USE_NETSTACK_MODE`, `NB_SKIP_NFTABLES_CHECK`, `NB_FORCE_RELAY`, and
others) are fixed when touched; there is no shared helper, so three private
`parseBoolEnv` copies exist. A fourth copy is a `nit`; propose `util`.

## Testing (client-specific; see 60-testing.md)

### CLI-TEST-001 Ask for `-race` locally
severity: should
scope: any client concurrency change
check: present in the diff. Client CI runs with `-tags 'devcert privileged'
-p 1` as root on amd64 and 386, but without `-race`; only relay runs the
race detector.

### CLI-TEST-002 Userspace interfaces in tests via `t.Setenv`
severity: nit
scope: `client/**/*_test.go`
check: `os.Setenv`; a `defer t.Setenv(old)` after `t.Setenv` (redundant);
a test that needs a TUN without the `privileged` tag when
`t.Setenv("NB_WG_KERNEL_DISABLED", "true")` would give a userspace bind.

### CLI-TEST-003 Tests must actually run in CI and must not mutate the host
severity: should
scope: `client/**/*_test.go`
check: a test guarded by a skip that always fires in CI; a test that writes
to `/tmp` with a fixed name, changes permissions, or leaves an interface;
test-only code paths in production files.

## Logging

### CLI-LOG-001 Per-peer logger, not package log
severity: nit
scope: `client/internal/peer/**`
check: `log.Errorf` where `conn.Log`/`w.log` (with the `peer` field) is
available.

### CLI-LOG-002 Endpoints, overlay IPs, relay addresses stay at debug
severity: should
scope: `client/**`
check: Info or Warn lines interpolating a remote endpoint, an overlay IP,
a relay address, or a hostname. Known violations exist in `peer/conn.go`,
`handshaker.go`, `engine.go`, `connect.go`; do not add to them.

### CLI-LOG-003 Error wrapping: `%w`, no "failed to", `multierror` for accumulation
severity: nit
scope: `client/**`
check: `%v`/`%s` on a returned error; `fmt.Errorf("failed to ...`;
`errors.Join` where the surrounding code uses `multierror` with
`FormatErrorOrNil`.

## Known quirks to respect (do not "clean up")

- Windows: NRPT catch-all with the `.local` exemption and GPO precedence;
  an empty server list must still be written; gVisor RACK is disabled;
  loopback TCP carries no identity; `os.Open` lacks `FILE_SHARE_DELETE`.
- macOS: `IP_BOUND_IF` vs `IPV6_BOUND_IF` on dual-stack sockets; elevation
  via `AuthorizationExecuteWithPrivileges` reports no exit status.
- Android: every control-plane socket is protected through the VpnService
  callback; `net.Interfaces` is broken and interfaces come from the app; a
  local upstream resolver must not be protected.
- iOS: no nbnet hooks; the TUN fd comes from the packet tunnel provider;
  separate dial and listen paths.
- Linux: systemd-resolved is preferred when nss-resolve or the stub is
  active because file-mode writes would loop; iptables-nft detection is a
  heuristic; a zero-address `IntervalEnd` element is required in nft sets;
  a firewalld untrust failure keeps the shutdown state.
- Peer: `wgConfigWorkaround` sleep; one-slot latest-wins handshake channel;
  non-blocking guard event sends; ICE worker session ID renewal on close.
