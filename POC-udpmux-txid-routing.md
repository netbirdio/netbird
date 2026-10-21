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
| Baseline e2e run | [39588288742](https://github.com/netbirdio/proxbird-tests/actions/runs/39588288742), dispatched 2026-10-21 10:56 UTC |

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
| `go test -race -count=10 ./client/iface/udpmux/` | ok |

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
