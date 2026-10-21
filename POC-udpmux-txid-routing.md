# POC: route ICE STUN in the UDP mux without the candidate-pair ID

Branch: `poc/udpmux-txid-routing` in `netbirdio/netbird` (no PR, no ticket).
Progress log, written so the work can be resumed from it.

## Resumed work (2026-10-21)

The mux-only POC continues. The candidate-type difference is reported below;
it does not justify changing pion/ice in this task. The experimental mapped-
candidate/remote-affinity implementation was not adopted: a deterministic test
that holds Binding responses until nomination arrives can prevent it from
connecting. The request-sender transaction routing passes that ordering test.

The checkout was fast-forwarded from `405edfec` to `f1048acf`, preserving the
parallel implementation and its merge `37dab7d`. That merge deliberately retained
the implementation described below. The running Proxbird run tests `37dab7d`;
later lifecycle fixes need validation at their own source SHA.

Additional regression tests reproduced these defects before the fixes:

| Defect | Evidence and change |
| --- | --- |
| Removed connections can register transactions and addresses again | Real socket write after `RemoveConnByUfrag`; registration now verifies the current connection pointer under the same mux mutex as removal |
| Closing an old connection removes a replacement with the same ufrag | An incoming USERNAME request to the replacement was lost; close cleanup now runs synchronously and removes only matching pointers |
| Removing one connection erases a surviving connection's fallback address | Two real connections share one remote socket; removal now filters the removed pointers and retains other registrations |
| Parallel first writes register one connection more than once | Concurrent writers followed by one unknown-ID response; address registration now deduplicates under the mutex |
| Mux close retains candidate and address state | Close now clears all routing maps and waits for the transaction expiry worker, outside the mux mutex |
| Idle transactions remain allocated beyond their TTL | A virtual-time test observes the map without sending more packets; a periodic expiry worker releases entries within two TTLs, while lookup rejects them at the TTL |
| A delayed write error deletes a newer same-connection retransmission | Cleanup now checks the recorded generation as well as the connection pointer |
| A failed resend deletes the earlier successful request's mapping | A real UDP test expired the write deadline for the resend, then received the original response; a same-connection refresh is no longer rolled back on error |
| Invalid STUN length headers consume tracker entries | Header-only parsing now checks reserved bits, cookie, declared length and four-byte alignment, without decoding attributes |

The focused lifecycle, tracker, and NAT-agent tests pass with the race detector.
The added NAT cases cover both mixed pair-ID roles, nomination arriving before
buffered responses (and assert that responses were actually held), and old-agent
removal while a surviving agent receives at least three fresh check responses.
Response assertions still require the exact sending connection.

The failed-resend policy is deliberately conservative: an existing same-conn
registration is refreshed and has no rollback token. This retains an earlier
outstanding request even when a resend fails. Overlapping attempts that all fail
can retain an entry until five seconds after the last attempt (physical cleanup
within ten seconds); further attempts can refresh it. The 4096-entry cap still
applies. A failed first send, including overlay refusal, releases its entry.
This avoids restoring an old sequence whose expiry-queue record may already
have been discarded.

After that final change, `go test -race -count=1 ./client/iface/udpmux/...`
passes (10.120 s), including the real UDP resend-error regression. The second
review pass found no remaining tracker/lifecycle issue in this change.

Two test-only changes outside `udpmux` are necessary for the required race suite:

- `client/iface/bind/ice_bind_test.go`: the existing 500-packet burst saturated
  default receive buffers (256 IPv4 and 357 IPv6 packets, below the unchanged
  400-packet threshold). Giving the two test receivers 1 MiB buffers passes ten
  consecutive race runs; no production buffering or host settings changed.
- `client/internal/peer/wg_watcher_test.go`: tests now cancel and join watcher
  goroutines before restoring global timing settings. Previously the next test
  changed those settings while an old watcher still read them. Both packages
  pass their full race suites after these test-only fixes.

Two-pass shared-state review checked mutex order, connection identity, write-
error cleanup, expiry, and shutdown. Mux registration/removal holds `m.mu`
before the tracker or address-map locks; connection address locks are never
held while acquiring `m.mu`. Shutdown releases `m.mu` before joining the expiry
worker or closing connections. The inherited concurrent GetConn/Close window
and external address-removal-hook/re-registration ordering are not claimed as
fixed by these tests.

Full repository checks are being repeated in a disposable Ubuntu container
with the actual GTK/WebKit development libraries, Docker access, and normal
`/tmp` ownership. Baseline `make lint-all` passes with zero issues. Results from
the earlier restricted environment in the historical table below are not the
final validation of the resumed tree.

All 85 baseline Proxbird case artifacts were downloaded and audited: 2,575
evidence file hashes, 287 complete node diagnostics, 202 native debug bundles
and TRACE archives, and 85 server runtime identities. All cases passed at
`1e63b68c4dc243a32fef823df1bc024c997a9c60`; the status candidate fields match
the native bundle captures. Published case phase durations include work beyond
ICE and must not be described as time-to-P2P medians. The final comparison will
distinguish the intermediate `37dab7d` run from later lifecycle fixes.

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
| Revised implementation | `532e38be0da5855fe3b7f95f5612adf0783312c7` (lifecycle fixes and expanded regressions); no Proxbird run dispatched for this revision yet |

### Repeated local ICE timing on the revised implementation

Twenty-four samples per source and configuration, 192 samples total. Sources
alternate order each repetition. Both hosts gather and exchange all candidates
before a start barrier; the timer ends when every Dial/Accept completes. Exact
baseline `1e63b68` is compared with a snapshot whose mux source hashes match
`532e38be`. This is virtual NAT with real fork agents, not OS-mode or Proxbird
validation. All 96 POC samples pass the exact sender/receiver ownership checks.

| Agent pairs | Pair ID | Baseline median (ms) | POC median (ms) | Change (ms) | Baseline / POC range (ms) |
| --- | --- | ---: | ---: | ---: | --- |
| 1 | present | 602.545 | 602.643 | +0.098 | 601.930–604.714 / 601.832–605.414 |
| 1 | absent | 602.669 | 602.404 | -0.265 | 601.461–606.328 / 601.425–603.306 |
| 20 | present | 608.733 | 607.946 | -0.787 | 605.145–636.171 / 604.597–616.653 |
| 20 | absent | 621.794 | 608.266 | -13.528 | 615.435–645.919 / 605.871–610.914 |

The one positive median delta is 0.016% with overlapping ranges; this does not
prove a strict no-slowdown guarantee. With pair IDs, all baseline controlling
and controlled local candidates are srflx; all POC controlling locals are host
and controlled locals srflx (24 single-pair and 480 batched observations per
role). Without IDs, baseline local types vary while the POC consistently uses
host locally on both sides. Every remote candidate in these samples is srflx.
There are no relay candidates in this timing fixture.

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
an initial write fails, on `RemoveConnByUfrag`, on mux `Close`, and after
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
6. The original closed-connection check did not prevent recording after
   `RemoveConnByUfrag`, which does not itself close the connection. The resumed
   implementation checks the registered pointer while holding `m.mu` through
   tracker registration/removal, and rejects writes through retired conns.
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

### Earlier repository checks (before the resumed validation environment)

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
  `cb20fec` (requests). Review and full checks in progress.
