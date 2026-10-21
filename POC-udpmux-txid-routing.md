# POC: route ICE STUN in the UDP mux without the candidate-pair ID

Branch: `poc/udpmux-txid-routing` in `netbirdio/netbird` (no PR, no ticket).
Progress log, written so the work can be resumed from it.

## Goal

Step 1 of removing the pion ICE fork (`github.com/netbirdio/ice/v4`): prove that
`client/iface/udpmux` can deliver inbound STUN to the right muxed connection
without the fork's `0x8100` candidate-pair ID attribute, while the fork, the
`cid` candidate extension and the wire format stay unchanged.

## Baseline

| Item | Value |
| --- | --- |
| Base commit (`origin/main`) | `1e63b68c4dc243a32fef823df1bc024c997a9c60` |
| Pion fork in `go.mod` | `github.com/netbirdio/ice/v4 v4.0.0-20250908184934-6202be846b51` (upstream v4.0.10 plus the pair ID, `cid`, prflx-ID and `GetConn(candidateID)` changes) |
| proxbird harness (`main`) | `a1abca530f93969ad81f11a9683dc6e89171a23c` |
| e2e selection | `peer-pairs,client-tests,recovery,connectivity-repair,connectivity-underlay,routing-ha,routing-overlap` (85 executions) |
| Baseline e2e run | [39588288742](https://github.com/netbirdio/proxbird-tests/actions/runs/39588288742), dispatched 2026-10-21 10:56 UTC, completed 12:06 UTC: **85/85 passed** |
| POC head for e2e | `37dab7d7124ea1de7a7e9bdfa5a3cd445f8413dc` (tree identical to `afdf67f`) |
| POC e2e run | [39597620276](https://github.com/netbirdio/proxbird-tests/actions/runs/39597620276), dispatched 2026-10-21 12:11 UTC, same inputs |

## What the routing does now (branch head)

| Inbound STUN | Baseline (`1e63b68`) | POC |
| --- | --- | --- |
| Success / error response | conn of the `0x8100` target candidate, else broadcast to every conn that wrote to the source address | the conn that wrote the request (transaction ID recorded on `udpMuxedConn.WriteTo`); unknown ID: as baseline |
| Request / indication with resolvable `0x8100` | conn of the target candidate | unchanged |
| Request / indication without it | broadcast: address-map conns plus the USERNAME ufrag conn | host conn of the USERNAME ufrag only; no such conn: as baseline |
| Anything else | address-map broadcast | unchanged |

Tracker (`client/iface/udpmux/transactions.go`): header-only parse of outgoing
requests (RFC 8489 section 5: class bits of the type, ID in bytes 8 to 20),
recorded before the socket write. Records are removed on the response, when
the write fails, on `RemoveConnByUfrag`, on mux `Close`, and after
`transactionTTL` (5 s); a closed conn is never recorded. At most
`maxTransactions` (4096) outstanding requests are kept, the oldest outstanding
one evicted first. A FIFO queue in insertion order (equal to expiry order, the
TTL being constant) drives expiry and eviction; answered or resent records
left in it are skipped and compacted away at twice the cap, so memory is
bounded by the cap, not by the send rate. Its own mutex, a leaf lock never
held across I/O.

## Decisions

1. Branch name and push target follow the task (`poc/udpmux-txid-routing`), not
   the session's default branch; the task names that branch explicitly.
2. The baseline e2e run was dispatched before any code change so it runs while
   the change is developed. The POC run uses the identical selection and inputs.
3. **Pair-ID routing is kept as the first step for requests** (the task's
   fallback design). Measured with the unit tests below, on vnet NAT, selected
   pair as local/remote type, controlling side then controlled side:

   | Routing | peers stamp `0x8100` | peers do not |
   | --- | --- | --- |
   | Baseline | srflx/srflx, srflx/srflx | srflx/srflx or host/srflx, host/srflx (varies by run) |
   | POC, pair ID kept for requests (head) | host/srflx, srflx/srflx | host/srflx, host/srflx |
   | Pair ID removed entirely (measured, not committed) | host/srflx, host/srflx | host/srflx, host/srflx |

   Removing it also passes every routing test, but it changes the controlled
   side's reported local candidate type for peers that stamp the attribute,
   which keeping it does not. The task allows removal only with identical
   behavior, so `candidateConnMap` and `findCandidateConnection` stay.
4. A response whose transaction ID is unknown (evicted, expired, a duplicate
   answer, or a request not written by a muxed conn) goes through the
   baseline path unchanged: pair ID, then address map. This keeps every case the
   new rules cannot place identical to baseline.
5. TTL 5 s: the agent drops a pending binding request after
   `maxBindingRequestTimeout` (4 s, fork `agent_config.go:55`), so a longer TTL
   buys nothing. The fork never resends a transaction ID (every check, keepalive
   and nomination builds a new message, `selection.go:174`, `:210`); the tracker
   still refreshes a record if a client ever does (tested).
6. A record can outlive its conn if `RemoveConnByUfrag` runs between
   `WriteTo`'s closed check and the record; delivery skips a closed conn and
   falls back, so nothing is written to a dead buffer.
7. Test 2 (overlapping agents) uses distinct ufrags. NetBird reuses one ufrag
   for every agent it recreates for a peer (`worker_ice.go:112-117`, `:247`),
   but `OnNewOffer` closes the old agent (up to 3 s) before creating the new
   one, and pion removes the ufrag's conns on close. Only after a close timeout
   would two agents share one ufrag, and then they share one muxed conn before
   the mux routes anything; no mux routing can split that (pre-existing).
8. `go fmt ./...` on `origin/main` reformats 26 files outside `udpmux`
   (pre-existing). They were reverted, not committed, to stay in scope.
9. `make lint` (fixed `--timeout=2m`) timed out loading packages on this
   4-CPU session while tests ran; the identical command with `--timeout=20m`
   reports no issue in the diff. Its only two findings are `typecheck` errors in
   `client/ui` (GTK/WebKit headers not installed here), unrelated to the change.
10. The session's network policy blocks `datatracker.ietf.org` and
    `www.rfc-editor.org`, so the RFC sections cited here (RFC 8489 sections 5,
    14 and 14.7; RFC 8445 sections 6.1.2.4 and 7.3.1.4) were not re-read against
    the published text. They are cited from knowledge and cross-checked only
    against pion/stun's own comments (comprehension ranges). Verify before
    relying on them in a design document.
11. The policy also blocks `*.blob.core.windows.net`, where GitHub serves
    Actions artifacts and raw job logs. Per-case reports (`result.json`,
    `status-detail.txt`, debug bundles) therefore cannot be downloaded here.
    Pass/fail and step durations come from the jobs API; controller timing
    lines come from job logs fetched through the GitHub MCP server, which reads
    them server-side.

12. **Parallel run on the same branch.** While this run was validating, the
    branch received three commits from a parallel run of the same task
    (`553908d`, `b204c66`, `405edfe`, 10:54 to 11:02 UTC). That run measured the
    same srflx-to-host change on the controlling side, treated it as the
    hard stop, and could not reach the GitHub API for e2e. The user said to
    ignore it. Since force-pushing is ruled out, `37dab7d` is an `-s ours`
    merge: those commits stay in history, none of their files are in the tree.
13. **The srflx-to-host change is reported, not treated as a hard stop.** The
    task lists the reported local candidate type under behavior to record and
    says to call a change such as "srflx shown as host" out explicitly with
    evidence. It is a direct consequence of the mandated response routing
    (see "What the change does to candidate selection" below), and it changes
    no packet on the wire. The e2e comparison decides whether anything else
    differs.
14a. The parallel run kept pushing to this branch: nine more commits
    (`f6095c0` to `42b087a`, 12:44 to 13:28 UTC), built on `2b97cd1`. They
    rewrite the tracker's `forget` contract, add a per-mux expiry goroutine,
    change about 110 lines of `mux.go`, add lifecycle tests and edit
    `client/internal/peer/wg_watcher_test.go` and
    `client/iface/bind/ice_bind_test.go` (outside the task's scope). None of it
    is in `37dab7d`, the commit both e2e comparisons built. Following the
    user's instruction to ignore the parallel run, `27531b6` is again an
    `-s ours` merge: the commits stay in history, the tree under `client/` is
    byte-identical to `37dab7d`. Whoever continues should stop one of the two
    runs first; two writers on one branch cannot both be validated.
14. To let the pre-push hook's `make lint` typecheck `client/ui` as CI does,
    the session installed the packages CI installs
    (`libgtk-4-dev libwebkitgtk-6.0-dev libsoup-3.0-dev libgl1-mesa-dev
    xorg-dev libpcap-dev`) and created the ignored placeholder
    `client/ui/frontend/dist/.embed-placeholder`, as the lint workflow does.
    `make lint` then passes in the hook. No hook was bypassed.

## What the change does to candidate selection

Behind NAT, an agent's host and srflx candidates send checks from the same
socket, so both leave with the srflx mapping as source. The remote looks the
sender up by address (fork `agent.go:961-977`), finds our srflx candidate, and
stamps it as the pair ID target of its response (`candidatepair.go:127-135`).
On baseline that response goes to the srflx conn even when the host conn sent
the check; pion accepts it there (pending requests are agent-wide,
`agent.go:1050-1062`) and marks `(srflx, R)` succeeded. `(host, R)` never
succeeds, so the selected pair is srflx-local.

With transaction-ID routing `(host, R)` succeeds as well. It has the higher
priority, so the **controlling** agent nominates it and reports local `host`
where baseline reported `srflx`. The **controlled** agent selects the pair its
nominating request arrives on; that request's pair ID still names our srflx
candidate, and it is still routed by it, so the controlled side keeps reporting
`srflx` for peers that stamp the attribute. With peers that do not stamp it the
request goes to the host conn and the controlled side reports `host` too.

Nothing on the wire changes: same socket, same 5-tuple, same WireGuard
endpoint (taken from the remote candidate). NetBird uses the local candidate
type only for display (`netbird status -d`, UI, mobile) and debug logs; relay
detection, route selection and connection priority use the relay flag and the
remote endpoint. The local endpoint shown becomes the interface address
instead of the public mapping. proxbird's NAT check accepts srflx or prflx on
either side, so it still passes when the remote side is reflexive.

Two side effects follow from host conns being shared (pre-existing, not
caused by the routing):

- With several host candidates of one family (unspecified bind on a host
  with several interface addresses, common with IPv6), all share the ufrag's
  host conn and each runs its own read loop on it. Which candidate processes a
  response is a race, so a selected host-local pair can see some of its
  keepalive responses credited to a sibling pair, updating its RTT less often.
  Baseline already had this for host-host paths (LAN, direct); the POC extends
  host-local selection to NAT paths.
- udp4 and udp6 srflx candidates share one conn (`GetConnForURL` keys by
  `ufrag+url` on the v4 map), so the same race exists between them; the review
  showed srflx-pair success is never lower than on baseline.

## Unit tests (`client/iface/udpmux`)

Real pion agents (the fork in `go.mod`) on NetBird's `UniversalUDPMuxDefault`,
wired as the engine does (`UDPMux: mux.SingleSocketUDPMux`, `UDPMuxSrflx: mux`),
over a `pion/transport/v3` vnet: each host behind its own endpoint-independent
mapping, port-restricted NAT, a stun/v3 binding responder on the "internet". No
new dependency. A passive observer between agent and mux records which conn
writes and reads every STUN message by transaction ID. Each agent scenario
runs twice: peers stamp `0x8100`, and peers whose socket strips it (as an agent
without the fork sends; the fork appends it after FINGERPRINT, so removal
restores the original message).

| Test (task item) | What it asserts |
| --- | --- |
| `TestRouting_HostAndSrflxOnOneMux` (1) | one agent per host with host+srflx: every response read only by the conn that wrote the request; every request read once, by its USERNAME's agent, answered at most once; agents connect |
| `TestRouting_OverlappingAgentsSameRemote` (2) | two agents per mux, both talking to the same remote socket at once |
| `TestRouting_ManyAgentsPerMux` (3) | 20 agent pairs, roles alternating, on one mux per side |
| `TestTransactionTracker_*`, `TestUniversalUDPMux_TransactionsBoundedAndReleased`, `TestUniversalUDPMux_ResponseFollowsRequest` (4) | same-ID resend matched; TTL expiry; resend refreshes; removal per conn and on conn close; map capped at `maxTransactions`, oldest evicted, queue bounded; unknown ID keeps the address fallback |
| `TestRouting_MixedPairIDPeers` (5) | one host connects at once to a stamping peer and a non-stamping peer |
| `TestUniversalUDPMux_RequestFollowsUsername` | request without pair ID reaches only its ufrag's conn although another conn wrote to the same address |
| `TestUniversalUDPMux_PairIDRouting` | a request whose pair ID names the srflx candidate reaches the srflx conn although USERNAME alone would pick the host conn; an unknown-ID response is routed by its pair ID |
| `TestTransactionTracker_AnsweredRequestsDoNotEvict`, `_Forget`, `TestUniversalUDPMux_CloseForgetsTransactions`, `_RefusedWriteIsNotTracked` | the cap counts outstanding requests only; failed writes and mux close release records (added after review) |
| `TestSTUNRequestTransactionID` | only requests are tracked; responses, indications, short and non-STUN buffers are not |

### Before (baseline mux, `routing_test.go` of `3d8b652` copied onto `1e63b68`)

`routing_test.go` at `3d8b652` uses only APIs that exist on the baseline, so it
can be copied onto `1e63b68` and run there. From `3539d30` on it uses the new
`transactionID` type and no longer compiles on the baseline.

Every routing test fails, for the reason expected; all agents still connect:

- With the pair ID: a check sent from the host conn is read by the srflx conn
  (`controlling host: 3 of 5 responses not delivered to exactly the requesting
  conn`, `controlled host: 4 of 8`, many agents: `66 of 149`). The remote
  identifies the sender by source address, which is the srflx mapping, and
  stamps the srflx candidate as target.
- Without the pair ID: requests are read by the host and the srflx conn of the
  agent and answered by both (`12 of 12 requests delivered or answered more
  than once`), and each response is read four times (two answers, each
  broadcast to both conns).
- Socket level: `connB must not receive the response to connA's request`,
  `connB must not receive connA's request`.

### After

- Commit `d8e7f21` (responses by transaction ID only): all with-pair-ID
  scenarios pass; without-pair-ID scenarios still fail on duplicated requests.
- Commit `cb20fec` (requests by USERNAME): all pass.
- `go test -race -count=10 ./client/iface/udpmux/`: pass, no race reports.

### Repository checks

| Check | Result |
| --- | --- |
| `go fmt` on changed files | clean (`go fmt ./...` also touches 26 pre-existing unrelated files; reverted, see decision 8) |
| `make lint` (diff vs `origin/main`) | no findings in the diff; 2 `typecheck` errors in `client/ui` from missing GTK/WebKit headers (environment) |
| `golangci-lint run ./client/iface/udpmux/...` (whole package) | 0 issues |
| `make test-unit` | same failure set as baseline `1e63b68` run in the same environment: 25 identical `FAIL` lines, none new, none in `udpmux`. All are environmental: testcontainers without Docker (`rootless Docker not found`), `client/ui` without GTK, DNS tests needing real resolvers, `sharedsock` raw sockets, `TestICEBind_OpenDoesNotDiscoverInterfaces` (`Open(0)` returns port 0 in this sandbox) |
| `go test -race ./client/iface/udpmux/... ./client/iface/bind/... ./client/internal/peer/...` | `udpmux` ok. `bind`: the same `TestICEBind_OpenDoesNotDiscoverInterfaces` environmental failure as baseline. `peer`: a data race between `TestWGWatcher_CheckSuccessCallback`'s leftover goroutine and `TestWGWatcher_EnableWgWatcher` writing package-level `checkPeriod`; reproduces on baseline in 5 of 6 `-race` runs (POC tree 2 of 6), unrelated to the mux, queued as a separate task. `peer/guard`, `peer/ice` ok |
| `go test -race -count=10 ./client/iface/udpmux/` | ok (also `-count=5` after the review fixes) |
| After the review fixes (`3539d30`, `c058965`): `go test -tags devcert` over the 66 packages that import `udpmux` | failures only from the baseline set (`TestICEBind_OpenDoesNotDiscoverInterfaces`, `TestModuleStatus`, `TestUpstreamResolver_ServeDNS`, `client/ui` setup) |
| Cross-builds of `udpmux`: `GOOS=windows/darwin/linux go vet`, `GOOS=js GOARCH=wasm`, `GOOS=android` build | ok. `GOOS=freebsd go vet` fails in `wgctrl` (`wgfreebsd.New` needs cgo), identically on baseline; FreeBSD clients are built natively by proxbird |
| GitHub workflows on branch push | none triggered (netbird push workflows target `main`/`release-*` only) |

### Adversarial review (5 lenses, each finding verified by a skeptic)

Lenses: routing equivalence, concurrency/lifecycle, test validity, AGENTS.md
conventions, security. Acted on in `3539d30` and `c058965`:

| Finding | Verdict | Action |
| --- | --- | --- |
| Cap counted answered records still queued: a live request was evicted after 4096 later sends (reproduced: one live record, 4096 record+take pairs, live record lost) | real, minor | eviction now counts outstanding requests, skips stale records; queue compacted at 2x the cap; `TestTransactionTracker_AnsweredRequestsDoNotEvict` |
| A request delivered to exactly one conn of the wrong agent passed the trace (mutant rerouting 1 in 3 requests stayed green) | real, minor | trace checks the reader belongs to the USERNAME's agent |
| Swapping pair ID and USERNAME order for requests changed the controlled side's selection with all tests green | real, minor | `TestUniversalUDPMux_PairIDRouting` |
| Pair ID fallback for unknown-transaction-ID responses untested (mutant returning nil stayed green) | nit | same test |
| Record could be added for a conn after `removeConn`/`Close` passed | nit | `record` checks `isClosed` under the tracker lock |
| Failed write (overlay refusal) held a slot for the TTL | nit | `forget` on write error; `TestUniversalUDPMux_RefusedWriteIsNotTracked` |
| `Close` clearing records untested; counts and listings snapshotted separately; `require` used for the condition under test; alias map key; duplicated mux start helper; `pending()` only used by tests | nits | fixed |
| Dual-stack: udp4 and udp6 srflx candidates share one muxed conn (keyed `ufrag+url` on the v4 map), so a response routed to it is read by the wrong-family candidate about half the time | rejected as a regression (pre-existing, srflx pair success never lower than baseline, host pairs unaffected) | recorded under "Not covered / caveats" |
| "At most one response per request" not "exactly one" | rejected (any realistic loss is caught by misdelivery or connect failure) | none |

The seven mutants the reviewers and I built (order swap, no pair ID
fallback, queue-based eviction, no `forget`, no `clear`, no closed check,
wrong-agent delivery) all fail the suite now.

### Cross-version check (scratch only, not committed)

proxbird has no case that pairs the candidate build with a current release
peer (its references are 0.28.9 and 0.30.1, both older than pair-ID routing,
which shipped in v0.57.0 with #4430). To cover "POC against current release" at
unit level, a throwaway worktree (`git worktree add --detach cb20fec`) got a
renamed copy of the baseline mux (`git show 1e63b68:client/iface/udpmux/{mux,conn,universal,mux_generic}.go`
as package `baselinemux`) and a test connecting a POC-mux host to a
baseline-mux host over the same vnet NAT, two agent pairs at once, POC
controlling and controlled. The peer variant "baseline mux, stamps pair ID" is
v0.57+ behavior; "baseline mux, pair ID stripped" exercises the broadcast
routing that pre-0.57 clients use.

| Peer | POC role | Connected | POC host routing | Selected (POC / peer) |
| --- | --- | --- | --- | --- |
| baseline mux, pair ID | controlling | yes | clean | host/srflx / srflx/srflx |
| baseline mux, pair ID | controlled | yes | clean | srflx/srflx / srflx/srflx |
| baseline mux, no pair ID | controlling | yes | clean | host/srflx / srflx/srflx |
| baseline mux, no pair ID | controlled | yes | clean | host/srflx / srflx/srflx |

Three runs each, all pass. The baseline side still misroutes its own
responses (5 to 8 of 9 to 16 per run), which is its pre-existing behavior; it
receives no duplicate answers from the POC side (0 duplicated requests).

## History (why pair-ID routing exists)

- #4430 "Fix/v4 stun routing" (9e81e782, first in v0.57.0, 2025-09-11) added the
  `cid` extension, `0x8100` stamping and `candidateConnMap`. Its description:
  pion "responded from all candidates for every STUN message" because all
  candidates share the socket. Before it, the mux only broadcast
  (`addressMap` plus ufrag), from #779 (v0.16.0).
- Pair-ID routing still misses for: host candidates after the first per
  ufrag and family (only the first ID is registered), the receiver-side extra
  srflx (random ID), port-forwarded candidates (`cid` gets a doubled
  `candidate:` prefix, `worker_ice.go:551-557`), and every pre-0.57 peer. All of
  those took the broadcast; with the POC they take the transaction-ID and
  USERNAME rules.
- The fork appends `0x8100` after FINGERPRINT, outside MESSAGE-INTEGRITY; RFC
  8489 section 14.7 wants FINGERPRINT last. Nothing in pion or NetBird checks
  FINGERPRINT on inbound traffic. 0x8100 is comprehension-optional (RFC 8489
  section 14), so legacy agents ignore it.

## Log

- 2026-10-21 10:56 UTC: branch created from `origin/main` and pushed; baseline
  e2e dispatched (run 39588288742).
- 11:08 UTC: routing tests written; baseline failures recorded above.
- 11:20 to 11:45 UTC: commits `3d8b652` (tests), `d8e7f21` (responses),
  `cb20fec` (requests).
- 11:45 to 12:00 UTC: review workflow; fixes in `3539d30` (tests) and
  `c058965` (tracker).
- 12:06 UTC: baseline e2e completed, 85/85 passed.
- 12:10 UTC: `-s ours` merge of the parallel run's commits (`37dab7d`), push,
  POC e2e dispatched (run 39597620276); it built `37dab7d` with
  `source-build` (confirmed in its `resolve-client` log, `PINNED_SHA`), as the
  baseline built `1e63b68`.

## E2E comparison, full selection (baseline run 39588288742 vs POC run 39597620276)

Both runs: proxbird harness `a1abca5`, `client_source=netbird-main`,
`lab_source=source-build`, same 85-case selection, attempt 1, no retries.
**Baseline 85/85 passed, POC 85/85 passed.** No case was re-run.

"P2P/relay" is the path proxbird asserts for the case; a pass proves it held
in that run. Setup convergence is defined under "Resuming" below. Candidate
types could not be collected (decision 11).

### Setup convergence by group (paired: same case, baseline vs POC)

| Group/profile | cases | median baseline (s) | median POC (s) | median paired diff (s) | POC slower / faster |
| --- | --- | --- | --- | --- | --- |
| client/nat | 20 | 3.4 | 3.4 | +0.1 | 12 / 8 |
| connectivity-repair/nat | 4 | 6.9 | 7.3 | +0.1 | 3 / 1 |
| connectivity-underlay/nat | 1 | 6.1 | 6.2 | +0.0 | 1 / 0 |
| peer-pairs/direct | 5 | 7.4 | 7.5 | +0.1 | 3 / 2 |
| peer-pairs/nat | 5 | 7.3 | 7.0 | -0.3 | 1 / 4 |
| peer-pairs/relay | 5 | 7.3 | 8.5 | +0.1 | 3 / 2 |
| peer-pairs/slow | 5 | 8.7 | 8.7 | +0.2 | 4 / 1 |
| recovery/nat | 8 | 7.3 | 6.8 | +0.0 | 4 / 4 |
| routing-ha/nat | 8 | 10.8 | 10.8 | +0.0 | 4 / 4 |
| routing-ha/relay | 8 | 11.5 | 10.6 | -0.5 | 0 / 8 |
| routing-overlap/nat | 8 | 10.7 | 11.2 | +0.1 | 4 / 4 |
| routing-overlap/relay | 8 | 11.3 | 11.7 | -0.0 | 4 / 4 |

All paired cases (n=85): median baseline 8.0s, median POC 8.4s, median paired difference +0.00s, POC slower in 43, faster in 42


Large single-case values (20 to 32 s) appear in both runs at about the same
rate: baseline `recovery-macos-nat-path-failure` 30.4 s,
`routing-ha-freebsd-linux-nat-router-ha` 31.7 s,
`client-windows-nat-allowed-ports` 24.4 s, `client-windows-nat-dns` 22.4 s;
POC `client-windows-nat-dns` 32.1 s, `client-linux-nat-connect-relay` 30.7 s,
`routing-ha-freebsd-linux-nat-router-ha` 28.7 s. One sample per case cannot
separate these from the change, and `connect-legacy` (0.28.9 reference) is
about 2.5 s (one extra status poll) slower on FreeBSD, Linux and macOS in this
run. The `client-tests` suite is therefore repeated twice more per commit
(next section).

### Per case

| Case | Baseline | POC | P2P/relay (asserted, both runs) | Setup convergence baseline / POC (s) | Local/remote candidate types |
| --- | --- | --- | --- | --- | --- |
| `client-freebsd-nat-allowed-ports` | success | success | P2P | 3.2 / 1.3 | not collected (artifacts blocked) |
| `client-freebsd-nat-connect-legacy` | success | success | P2P | 0.7 / 3.2 | not collected (artifacts blocked) |
| `client-freebsd-nat-connect-relay` | success | success | P2P | 3.2 / 3.3 | not collected (artifacts blocked) |
| `client-freebsd-nat-dns` | success | success | P2P | 3.2 / 3.4 | not collected (artifacts blocked) |
| `client-freebsd-nat-exit-node` | success | success | P2P | 3.0 / 3.4 | not collected (artifacts blocked) |
| `client-linux-nat-allowed-ports` | success | success | P2P | 3.6 / 4.1 | not collected (artifacts blocked) |
| `client-linux-nat-connect-legacy` | success | success | P2P | 3.4 / 6.3 | not collected (artifacts blocked) |
| `client-linux-nat-connect-relay` | success | success | P2P | 3.7 / 30.7 | not collected (artifacts blocked) |
| `client-linux-nat-dns` | success | success | P2P | 3.4 / 3.4 | not collected (artifacts blocked) |
| `client-linux-nat-exit-node` | success | success | P2P | 3.6 / 3.5 | not collected (artifacts blocked) |
| `client-macos-nat-allowed-ports` | success | success | P2P | 4.7 / 3.5 | not collected (artifacts blocked) |
| `client-macos-nat-connect-legacy` | success | success | P2P | 4.1 / 6.4 | not collected (artifacts blocked) |
| `client-macos-nat-connect-relay` | success | success | P2P | 3.4 / 3.3 | not collected (artifacts blocked) |
| `client-macos-nat-dns` | success | success | P2P | 3.2 / 3.4 | not collected (artifacts blocked) |
| `client-macos-nat-exit-node` | success | success | P2P | 3.4 / 3.4 | not collected (artifacts blocked) |
| `client-windows-nat-allowed-ports` | success | success | P2P | 24.4 / 3.2 | not collected (artifacts blocked) |
| `client-windows-nat-connect-legacy` | success | success | P2P | 14.1 / 12.6 | not collected (artifacts blocked) |
| `client-windows-nat-connect-relay` | success | success | P2P | 3.2 / 3.9 | not collected (artifacts blocked) |
| `client-windows-nat-dns` | success | success | P2P | 22.4 / 32.1 | not collected (artifacts blocked) |
| `client-windows-nat-exit-node` | success | success | P2P | 3.4 / 3.4 | not collected (artifacts blocked) |
| `connectivity-repair-freebsd-nat-path-repair` | success | success | Relayed while blocked; P2P or Relayed after repair | 7.5 / 7.1 | not collected (artifacts blocked) |
| `connectivity-repair-linux-nat-path-repair` | success | success | Relayed while blocked; P2P or Relayed after repair | 6.4 / 11.2 | not collected (artifacts blocked) |
| `connectivity-repair-macos-nat-path-repair` | success | success | Relayed while blocked; P2P or Relayed after repair | 5.9 / 6.0 | not collected (artifacts blocked) |
| `connectivity-repair-windows-nat-path-repair` | success | success | Relayed while blocked; P2P or Relayed after repair | 7.5 / 7.5 | not collected (artifacts blocked) |
| `connectivity-underlay-linux-nat-underlay-change` | success | success | P2P before and after the move | 6.1 / 6.2 | not collected (artifacts blocked) |
| `freebsd-freebsd-direct` | success | success | P2P | 7.3 / 7.1 | not collected (artifacts blocked) |
| `freebsd-freebsd-nat` | success | success | P2P | 5.7 / 5.2 | not collected (artifacts blocked) |
| `freebsd-freebsd-relay` | success | success | Relayed | 7.7 / 5.6 | not collected (artifacts blocked) |
| `freebsd-freebsd-slow` | success | success | P2P | 8.5 / 6.0 | not collected (artifacts blocked) |
| `macos-macos-direct` | success | success | P2P | 5.9 / 5.6 | not collected (artifacts blocked) |
| `macos-macos-nat` | success | success | P2P | 5.9 / 5.6 | not collected (artifacts blocked) |
| `macos-macos-relay` | success | success | Relayed | 5.8 / 8.5 | not collected (artifacts blocked) |
| `macos-macos-slow` | success | success | P2P | 6.0 / 6.2 | not collected (artifacts blocked) |
| `macos-windows-direct` | success | success | P2P | 7.4 / 7.5 | not collected (artifacts blocked) |
| `macos-windows-nat` | success | success | P2P | 7.4 / 7.6 | not collected (artifacts blocked) |
| `macos-windows-relay` | success | success | Relayed | 7.3 / 7.5 | not collected (artifacts blocked) |
| `macos-windows-slow` | success | success | P2P | 8.7 / 8.7 | not collected (artifacts blocked) |
| `recovery-freebsd-nat-daemon-restart` | success | success | P2P before and after restart | 7.7 / 7.6 | not collected (artifacts blocked) |
| `recovery-freebsd-nat-path-failure` | success | success | P2P, then Relayed while blocked | 7.7 / 7.8 | not collected (artifacts blocked) |
| `recovery-linux-nat-daemon-restart` | success | success | P2P before and after restart | 6.2 / 6.4 | not collected (artifacts blocked) |
| `recovery-linux-nat-path-failure` | success | success | P2P, then Relayed while blocked | 6.1 / 6.2 | not collected (artifacts blocked) |
| `recovery-macos-nat-daemon-restart` | success | success | P2P before and after restart | 6.2 / 5.9 | not collected (artifacts blocked) |
| `recovery-macos-nat-path-failure` | success | success | P2P, then Relayed while blocked | 30.4 / 6.0 | not collected (artifacts blocked) |
| `recovery-windows-nat-daemon-restart` | success | success | P2P before and after restart | 7.2 / 7.2 | not collected (artifacts blocked) |
| `recovery-windows-nat-path-failure` | success | success | P2P, then Relayed while blocked | 7.3 / 7.4 | not collected (artifacts blocked) |
| `routing-ha-freebsd-freebsd-nat-router-ha` | success | success | client-routers P2P, router-router P2P | 8.0 / 8.4 | not collected (artifacts blocked) |
| `routing-ha-freebsd-freebsd-relay-router-ha` | success | success | client-routers Relayed, router-router P2P | 17.0 / 13.4 | not collected (artifacts blocked) |
| `routing-ha-freebsd-linux-nat-router-ha` | success | success | client-routers P2P, router-router P2P | 31.7 / 28.7 | not collected (artifacts blocked) |
| `routing-ha-freebsd-linux-relay-router-ha` | success | success | client-routers Relayed, router-router P2P | 16.6 / 9.0 | not collected (artifacts blocked) |
| `routing-ha-freebsd-macos-nat-router-ha` | success | success | client-routers P2P, router-router P2P | 10.0 / 8.3 | not collected (artifacts blocked) |
| `routing-ha-freebsd-macos-relay-router-ha` | success | success | client-routers Relayed, router-router P2P | 8.5 / 8.4 | not collected (artifacts blocked) |
| `routing-ha-freebsd-windows-nat-router-ha` | success | success | client-routers P2P, router-router P2P | 9.4 / 10.2 | not collected (artifacts blocked) |
| `routing-ha-freebsd-windows-relay-router-ha` | success | success | client-routers Relayed, router-router P2P | 9.7 / 9.2 | not collected (artifacts blocked) |
| `routing-ha-linux-freebsd-nat-router-ha` | success | success | client-routers P2P, router-router P2P | 10.8 / 10.8 | not collected (artifacts blocked) |
| `routing-ha-linux-freebsd-relay-router-ha` | success | success | client-routers Relayed, router-router P2P | 10.4 / 10.1 | not collected (artifacts blocked) |
| `routing-ha-linux-linux-nat-router-ha` | success | success | client-routers P2P, router-router P2P | 11.2 / 11.5 | not collected (artifacts blocked) |
| `routing-ha-linux-linux-relay-router-ha` | success | success | client-routers Relayed, router-router P2P | 11.8 / 11.4 | not collected (artifacts blocked) |
| `routing-ha-linux-macos-nat-router-ha` | success | success | client-routers P2P, router-router P2P | 10.7 / 10.7 | not collected (artifacts blocked) |
| `routing-ha-linux-macos-relay-router-ha` | success | success | client-routers Relayed, router-router P2P | 11.1 / 11.0 | not collected (artifacts blocked) |
| `routing-ha-linux-windows-nat-router-ha` | success | success | client-routers P2P, router-router P2P | 12.1 / 12.1 | not collected (artifacts blocked) |
| `routing-ha-linux-windows-relay-router-ha` | success | success | client-routers Relayed, router-router P2P | 12.7 / 11.4 | not collected (artifacts blocked) |
| `routing-overlap-freebsd-freebsd-nat-overlap` | success | success | client-routers P2P, router-router P2P | 14.1 / 13.7 | not collected (artifacts blocked) |
| `routing-overlap-freebsd-freebsd-relay-overlap` | success | success | client-routers Relayed, router-router P2P | 12.0 / 15.8 | not collected (artifacts blocked) |
| `routing-overlap-freebsd-linux-nat-overlap` | success | success | client-routers P2P, router-router P2P | 9.3 / 9.2 | not collected (artifacts blocked) |
| `routing-overlap-freebsd-linux-relay-overlap` | success | success | client-routers Relayed, router-router P2P | 25.4 / 25.3 | not collected (artifacts blocked) |
| `routing-overlap-freebsd-macos-nat-overlap` | success | success | client-routers P2P, router-router P2P | 8.4 / 8.6 | not collected (artifacts blocked) |
| `routing-overlap-freebsd-macos-relay-overlap` | success | success | client-routers Relayed, router-router P2P | 8.8 / 8.5 | not collected (artifacts blocked) |
| `routing-overlap-freebsd-windows-nat-overlap` | success | success | client-routers P2P, router-router P2P | 10.1 / 13.2 | not collected (artifacts blocked) |
| `routing-overlap-freebsd-windows-relay-overlap` | success | success | client-routers Relayed, router-router P2P | 9.4 / 9.3 | not collected (artifacts blocked) |
| `routing-overlap-linux-freebsd-nat-overlap` | success | success | client-routers P2P, router-router P2P | 10.5 / 10.3 | not collected (artifacts blocked) |
| `routing-overlap-linux-freebsd-relay-overlap` | success | success | client-routers Relayed, router-router P2P | 10.5 / 10.3 | not collected (artifacts blocked) |
| `routing-overlap-linux-linux-nat-overlap` | success | success | client-routers P2P, router-router P2P | 11.4 / 11.7 | not collected (artifacts blocked) |
| `routing-overlap-linux-linux-relay-overlap` | success | success | client-routers Relayed, router-router P2P | 11.7 / 12.1 | not collected (artifacts blocked) |
| `routing-overlap-linux-macos-nat-overlap` | success | success | client-routers P2P, router-router P2P | 10.8 / 10.8 | not collected (artifacts blocked) |
| `routing-overlap-linux-macos-relay-overlap` | success | success | client-routers Relayed, router-router P2P | 11.1 / 14.5 | not collected (artifacts blocked) |
| `routing-overlap-linux-windows-nat-overlap` | success | success | client-routers P2P, router-router P2P | 11.3 / 11.7 | not collected (artifacts blocked) |
| `routing-overlap-linux-windows-relay-overlap` | success | success | client-routers Relayed, router-router P2P | 11.4 / 11.4 | not collected (artifacts blocked) |
| `windows-macos-direct` | success | success | P2P | 8.0 / 8.3 | not collected (artifacts blocked) |
| `windows-macos-nat` | success | success | P2P | 7.3 / 7.0 | not collected (artifacts blocked) |
| `windows-macos-relay` | success | success | Relayed | 7.1 / 18.0 | not collected (artifacts blocked) |
| `windows-macos-slow` | success | success | P2P | 8.7 / 9.2 | not collected (artifacts blocked) |
| `windows-windows-direct` | success | success | P2P | 8.7 / 9.2 | not collected (artifacts blocked) |
| `windows-windows-nat` | success | success | P2P | 9.5 / 8.9 | not collected (artifacts blocked) |
| `windows-windows-relay` | success | success | Relayed | 9.0 / 8.8 | not collected (artifacts blocked) |
| `windows-windows-slow` | success | success | P2P | 10.7 / 11.1 | not collected (artifacts blocked) |


## E2E repetitions of `client-tests` (pending)

Dispatched 2026-10-21 13:28 UTC in balanced order, same inputs, selection
`client-tests` (20 cases: five behaviors on four OSes against the 0.28.9 and
0.30.1 reference peers):

| Order | Commit | Run |
| --- | --- | --- |
| P2 | POC `37dab7d` | [39608305272](https://github.com/netbirdio/proxbird-tests/actions/runs/39608305272) |
| B2 | baseline `1e63b68` | [39608330203](https://github.com/netbirdio/proxbird-tests/actions/runs/39608330203) |
| B3 | baseline `1e63b68` | [39608353253](https://github.com/netbirdio/proxbird-tests/actions/runs/39608353253) |
| P3 | POC `37dab7d` | [39608375543](https://github.com/netbirdio/proxbird-tests/actions/runs/39608375543) |

## Resuming: how the e2e data is collected

The artifacts are blocked here (decision 11), so the comparison uses:

1. `gh api repos/netbirdio/proxbird-tests/actions/runs/RUN/attempts/1/jobs?per_page=100`
   for per-case status and conclusion.
2. Each scenario job's log, fetched through the GitHub MCP server
   (`get_job_logs`, `return_content`), keeping the controller lines
   `timing end phase=...` and `Remote scenario ... finished with exit code N`.
   One extraction was spot-checked against a direct fetch and matched
   byte for byte.
3. "Setup convergence" is the controller's first `assertions` phase: it starts
   after both peers are installed and enrolled and ends when every peer pair
   passes proxbird's status check (Connected, `P2P` or `Relayed` as the
   profile requires, srflx or prflx on one side for nat/slow, versions
   matching; `internal/lab/guest.go:165-199`). It polls with a 2 s pause, so its
   resolution is a few seconds. It is the closest per-case measure of time to
   connect available without the artifacts.

With the artifacts reachable, the candidate types per peer come from each case
artifact's `results/*/result.json` (`.peers[i].peers.details[]` with
`connectionType` and `iceCandidateType.{local,remote}`) or
`results/*/nodes/peer-N/status-detail.txt` (`ICE candidate (Local/Remote)`).
Artifacts expire 14 days after the runs (2026-11-04).

## Not covered / caveats

- **Candidate types in e2e**: not collected (artifacts blocked). The unit
  and cross-version tests above give the expected effect; the e2e runs prove
  the asserted P2P/relay outcome but not which local type each peer reported.
- **Current release peers**: no proxbird case pairs the candidate build with a
  current release; covered only by the scratch cross-version test.
- **Netstack (`client/embed`)**: no e2e case. It shares the ICEBind receive
  path with userspace mode (`client/iface/bind/ice_bind.go` calls the same
  `HandleSTUNMessage`), so only the routing code path is shared, not tested
  end to end.
- **Mobile (iOS, Android)**: not exercised; Android builds.
- **Pre-existing, unchanged**: `RemoveConnByUfrag` deletes the whole
  `addressMap[addr]` entry, including other conns on that address (#4154; the
  parallel run's `TestSTUNRemovedConnectionPreservesAddressFallback` shows it
  on baseline and POC alike); several host candidates of one family share one
  muxed conn; udp4 and udp6 srflx candidates share one conn; a recreated agent
  reuses its predecessor's ufrag.
- **Full pair-ID removal** (variant R) was measured only at unit level; no
  e2e run of it exists.
