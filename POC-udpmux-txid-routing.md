# POC: route ICE STUN in the UDP mux without the candidate-pair ID

Branch: `work/admiring-planck-1l2xh2` in `netbirdio/netbird` (no PR, no
ticket). Until `75a31b4` the work was on `poc/udpmux-txid-routing`, shared
with a parallel run; see decision 22.
Progress log, written so the work can be resumed from it. The final report is
the last section.

## Goal

Step 1 of removing the pion ICE fork (`github.com/netbirdio/ice/v4`): prove that
`client/iface/udpmux` can deliver inbound STUN to the right muxed connection
without the fork's `0x8100` candidate-pair ID attribute, while the fork, the
`cid` candidate extension and the wire format stay unchanged.

## Acceptance status

| Requirement | Status | Evidence (section) |
| --- | --- | --- |
| Responses delivered only to the requesting conn | proven, unit level | "Unit tests", before/after |
| Requests routed by USERNAME, no broadcast | proven, unit level | "Unit tests" |
| Unknown cases keep the address-map fallback | proven, unit level | `TestUniversalUDPMux_ResponseFollowsRequest`, `_PairIDRouting` |
| Same P2P vs relayed outcome | proven for the 85-case selection | "E2E comparison": 85/85 on both commits, 0 of 298 initial path snapshots differ |
| Time to P2P no worse | **not met in one case (hard stop)**: a controlled agent whose host conn is shared by several candidates loses the nomination from a pre-0.57 peer in some attempts (7 of 240 in scratch trials, 0 of 240 on baseline) and needs one more ICE attempt; otherwise unchanged | "Hard stop", paired setup convergence (85 cases), ICE dial-to-success (212 observations), `client-tests` three runs per commit, 60/60 on each; median of per-case medians 3.66 s vs 3.71 s; Windows tail, see "E2E repetitions" |
| No duplicate STUN responses | proven, unit level and against a real v0.30.1 agent | "Unit tests", "Cross-version checks"; not observable in e2e |
| Mixed versions connect P2P | proven for 0.28.9 / 0.30.1 reference peers (e2e, every run) and for v0.57+ behavior (unit, scratch); against pre-0.57 peers an attempt can fail and be retried (hard stop) | "Cross-version checks", e2e `client-tests`, "Hard stop" |
| Kernel, userspace, netstack keep working | kernel and userspace proven (e2e, and `connectivity-lazy`, which asserts the interface mode: 4/4 per run, two runs per commit); netstack proven by the repo's nblink e2e; userspace and netstack also in a local NAT lab with real clients, 228 trials per build and 10 mixed, all P2P, no difference in time to P2P or failed attempts | "E2E comparison", "Netstack e2e", "Real clients" |
| Candidate types recorded per peer, change called out | recorded (artifact audit by the parallel run, attributed); change called out | "What the change does to candidate selection" |
| Unit tests 1 to 5, real pion agents and vnet NAT, 1 to 3 failing before | done | "Unit tests" |
| Pre-push checks, `make lint-all`, repo `e2e/` | fmt clean; `make lint` passes in the pre-push hook; `make lint-all` 0 issues; `make test-unit` and the race suite fail only where baseline fails in the same environment; repo `e2e/`: the mux-relevant suites pass, the rest fail on infrastructure, identically on baseline | "Repository checks" |

## Hard-stop assessment

- **Dependency, `go.mod`, fork or wire change needed: no.** The branch diff
  against `1e63b68` outside this log touches only `client/iface/udpmux`
  (`conn.go`, `doc.go`, `mux.go`, new `transactions.go`, two new test files;
  about 290 hand-written lines plus tests). `go.mod`, `go.sum` and the fork
  are unchanged. No STUN attribute is added or removed and the fork still
  stamps `0x8100` and `cid`. What does change on the wire is a consequence of
  routing, not of format: a non-stamping peer's request is answered once
  instead of twice, and because more host-local checks succeed, the nominated
  pair and with it the PRIORITY and `0x8100` values of nomination checks can
  differ. The 5-tuple and the WireGuard endpoint do not change.
- **Security control weakened: no.** `universal.go` is byte-identical to the
  baseline, so the overlay write refusal and the overlay STUN drop are intact.
  `TestUniversalUDPMux_RefusedWriteIsNotTracked` exercises the refusal through
  the new tracking path.
- **Ineliminable behavior difference: yes, this is where the run stops.**
  Against a peer that does not stamp the pair ID (pre-0.57), a controlled
  agent whose host conn is shared by two or more host candidates of one
  family can lose the peer's only nomination, and the ICE attempt fails
  after 12 s while the peer reports success. Baseline's broadcast hid the
  race. Scratch trials with the real v0.30.1 agent: 7 of 240 attempts on the
  POC, 0 of 240 on baseline, 0 of 200 on the POC with one host candidate.
  Real clients on a four-address Linux host show the same shape only on the
  POC, 1 of 22 controlled trials against 0 of 24. It matches the e2e tail on
  Windows, where the code suggests every agent has a 127.0.0.1 host
  candidate. It cannot be removed within the mandated design (see "Hard
  stop"), so no further code was written after finding it.
- **A second, display-level difference is reported, not a stop.** The
  reported local candidate type of the selected pair changes (mostly srflx to
  host on the controlling side behind NAT). It follows from delivering
  responses to the conn that sent the request; the task names this exact case
  ("srflx shown as host") as one to call out with evidence (decision 13). No
  packet path or P2P/relay outcome changes with it.

## Hard stop: nominations lost against pre-0.57 peers

### Symptom in e2e

`client-tests` setup convergence on Windows, the only OS with a tail (all
samples, three runs per commit; the per-case table is in "E2E repetitions"):

| Case | B1 | B2 | B3 | median B | P1 | P2 | P3 | median P | P − B |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `client-windows-nat-allowed-ports` | 24.4 | 3.4 | 16.1 | 16.1 | 3.2 | 16.3 | 24.2 | 16.3 | +0.2 |
| `client-windows-nat-connect-legacy` | 14.1 | 16.5 | 16.2 | 16.2 | 12.6 | 32.1 | 34.7 | 32.1 | +15.8 |
| `client-windows-nat-connect-relay` | 3.2 | 3.2 | 24.1 | 3.2 | 3.9 | 3.3 | 19.0 | 3.9 | +0.7 |
| `client-windows-nat-dns` | 22.4 | 23.9 | 3.2 | 22.4 | 32.1 | 32.0 | 3.3 | 32.0 | +9.6 |
| `client-windows-nat-exit-node` | 3.4 | 3.3 | 3.2 | 3.3 | 3.4 | 24.0 | 21.5 | 21.5 | +18.1 |

| OS | samples B / P | median B / P (s) | above 10 s B / P | above 28 s B / P |
| --- | --- | --- | --- | --- |
| freebsd | 15 / 15 | 3.2 / 3.3 | 0 / 0 | 0 / 0 |
| linux | 15 / 15 | 3.7 / 3.5 | 0 / 1 | 0 / 1 |
| macos | 15 / 15 | 3.5 / 3.4 | 2 / 0 | 0 / 0 |
| windows | 15 / 15 | 14.1 / 19.0 | 8 / 10 | 0 / 4 |

Windows samples near 16 to 24 s are a second ICE attempt and occur on both
commits; samples above 28 s are a third attempt and occur only on the POC
(4 of 15 against 0 of 15, Fisher p ≈ 0.05 one-sided). Every `client-tests`
case pairs the build with a 0.28.9/0.30.1 reference peer. The parallel run's
log reading of the first one (`client-windows-nat-dns`, POC run) found the
0.30.1 peer reporting success within a second of the second attempt while
the Windows side stayed `Checking` until the attempt failed 12 s later. It
left the cause unresolved.

### Mechanism (reproduced, real v0.30.1 agent)

A controlled pion agent selects a pair only when a USE-CANDIDATE request
arrives for a pair that has succeeded, or, if it has not, when the triggered
check that the request starts succeeds on that same pair (fork
`selection.go:314` sets `nominateOnBindingSuccess` on the pair the request
arrived on, `:268` selects only that pair when its check succeeds). A
controlling v0.30.1 agent nominates once: after its nominating check succeeds
it sends only keepalives without USE-CANDIDATE.

All host candidates of one family share one muxed conn (pre-existing), and
each runs its own read loop on it, so which candidate reads a packet is a
race. With the POC, a request without the pair ID goes to the host conn only.
When the nominating request lands on host candidate A, A's triggered check is
answered into the host conn, and the response can be read by sibling B. Pion
consumes the transaction, marks (B, remote) succeeded, and never selects,
because the nominate flag sits on (A, remote). The peer has already selected
its pair and does not nominate again, so the attempt fails. On baseline the
same request was broadcast to the host conn and the srflx conn: the srflx
candidate, alone on its conn, flagged its own pair and ran its own check,
and that redundancy hid the race.

Trace of one failing trial (pion trace log of the POC agent, scratch test): the
only `useCandidate: true` request is read by host 10.1.0.2; every response to
10.1.0.2's checks is read by 127.0.0.1 or 10.1.0.3 (10.1.0.2 reads none); the
peer then sends
keepalives every 4 s (`useCandidate: false`) and the agent stays `Checking`.

Scratch trials (decision 17), NetBird's ICE timeouts (6 s failed and
disconnected, 4 s keepalive), modern side controlled, 12 s per attempt:

| Modern host | Mux | attempts failed (peer connected) | median connect |
| --- | --- | --- | --- |
| one address (one host candidate) | POC | 0 of 200 | 0.60 s |
| two addresses on an unspecified bind (three host candidates incl. loopback) | baseline | 0 of 240 | 0.60 s |
| same | POC | **7 of 240** | 0.60 s |

Fisher's exact test, 7/240 against 0/240: p ≈ 0.008 one-sided. As
controlling agent, both muxes connected 40 of 40 on the two-address host.
Against stamping peers (v0.57+) nothing changes: their requests carry the
pair ID, which names our srflx candidate, alone on its conn, as on baseline.

With real clients (a four-address Linux peer behind NAT against a 0.30.1
peer, pion trace on; "Real clients"), the POC lost 1 nomination in 22
controlled trials, in the same shape, and baseline 0 of 24. Too few to
measure a rate (p ≈ 0.48), but the loss appears only on the POC, as the
mechanism predicts.

### Who is exposed

A controlled agent (decided per peer pair by key order) whose host conn is
shared by two or more candidates of one family, connecting to a pre-0.57
peer. NetBird binds the mux to the unspecified address, so every interface
address becomes a host candidate on one conn: multi-homed hosts, IPv6 hosts
with several addresses on the v6 conn, and, by reading the code, every
Windows agent. Go names the Windows loopback adapter by its friendly name
("Loopback Pseudo-Interface 1", `net/interface_windows.go:62`), which the
`"lo"` prefix in `DefaultInterfaceBlacklist` and `stdnet.InterfaceFilter` does
not match, and `localInterfaces` is called with loopback included
(`mux.go:211`), so Windows agents gather a 127.0.0.1 host candidate next to
their LAN address. Linux `lo` and BSD/macOS `lo0` are filtered by name. This
is an inference from code, not observed here: the artifacts that list the
gathered candidates are blocked (decision 11). It would explain why the
third attempts appear only on Windows. The second attempts that Windows needs
on both commits come from a different, pre-existing cause the parallel run
found: a candidate that arrives before the agent exists is discarded.

### Why it is a stop

The difference is inherent in the mandated design. Restoring the redundancy
means broadcasting requests without the pair ID again, which brings back the
duplicate answers the task requires removing. Removing the race means
giving each candidate its own muxed conn, so that transaction routing
reaches the exact candidate: a new design in peer connectivity (conn
lifecycle, USERNAME target choice, `candidateConnMap` registration), which
`AGENTS.md` requires to be agreed before code. Neither is done here. No
packet path changes, and the next attempt connects, but an attempt costs
about 12 s.

For step 2 this matters more: without the fork no peer stamps the pair ID,
so the race would apply to every controlled agent with a shared host conn.
Per-candidate conns (or an equivalent) are a prerequisite for dropping the
fork.

## Baseline

| Item | Value |
| --- | --- |
| Base commit (`origin/main`) | `1e63b68c4dc243a32fef823df1bc024c997a9c60` |
| Pion fork in `go.mod` | `github.com/netbirdio/ice/v4 v4.0.0-20250908184934-6202be846b51` (upstream v4.0.10 plus the pair ID, `cid`, prflx-ID and `GetConn(candidateID)` changes, and role-conflict and selector-lock backports from v4.0.11) |
| proxbird harness (`main`) | `a1abca530f93969ad81f11a9683dc6e89171a23c` |
| e2e selection | `peer-pairs,client-tests,recovery,connectivity-repair,connectivity-underlay,routing-ha,routing-overlap` (85 executions) |
| Baseline e2e run | [39588288742](https://github.com/netbirdio/proxbird-tests/actions/runs/39588288742), dispatched 2026-10-21 10:56 UTC, completed 12:06 UTC: **85/85 passed** |
| POC commit for e2e | `37dab7d7124ea1de7a7e9bdfa5a3cd445f8413dc`; its tree under `client/` and `go.mod`/`go.sum` is identical to the branch head's |
| POC e2e run | [39597620276](https://github.com/netbirdio/proxbird-tests/actions/runs/39597620276), dispatched 2026-10-21 12:11 UTC, same inputs: **85/85 passed** |
| `client-tests` repetitions | B2, B3 on `1e63b68`; P2, P3 on `37dab7d` (see "E2E repetitions") |

Every run's `resolve-client` log shows the `PINNED_SHA` it built
(`source-build`), checked for each run listed here.

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
the write fails, on `RemoveConnByUfrag`, and on mux `Close`; a closed conn is
never recorded. Expiry is lazy: a record older than `transactionTTL` (5 s) is
never used for delivery and is dropped on the next `record` or `take`, not by a
timer. At most `maxTransactions` (4096) outstanding requests are kept, the
oldest outstanding one evicted first. A FIFO queue in insertion order (equal
to expiry order, the TTL being constant) drives expiry and eviction; answered
or resent records left in it are skipped and compacted away at twice the cap,
so memory is bounded by the cap, not by the send rate. Its own mutex, a leaf
lock never held across I/O.

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
   | Pair ID removed entirely (variant R, measured, not committed) | host/srflx, host/srflx | host/srflx, host/srflx |

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
6. A record can outlive its conn if a write lands between `RemoveConnByUfrag`
   and the conn's close. Pion cannot do that (see "Two-pass race analysis"),
   and delivery skips a closed conn and falls back, so nothing is written to a
   dead buffer.
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
   reported no issue in the diff. Superseded by decision 14.
10. The session's network policy blocks `datatracker.ietf.org` and
    `www.rfc-editor.org`, so the RFC sections cited here (RFC 8489 sections 5,
    14 and 14.7; RFC 8445 sections 6.1.2.4 and 7.3.1.4) were not re-read against
    the published text. They are cited from knowledge and cross-checked only
    against pion/stun's own comments (comprehension ranges). Verify before
    relying on them in a design document.
11. The policy also blocks `*.blob.core.windows.net`, where GitHub serves
    Actions artifacts and raw job logs. Per-case reports (`result.json`,
    `status-detail.txt`, debug bundles) cannot be downloaded here. Pass/fail and
    step durations come from the jobs API; controller timing lines come from
    job logs fetched through the GitHub MCP server, which reads them
    server-side. The job logs carry no candidate types (checked on one full
    log). Candidate types and ICE timings in this log come from the parallel
    run's artifact audit (decision 15), attributed where used.
12. **Parallel run on the same branch.** While this run was validating, the
    branch received three commits from a parallel run of the same task
    (`553908d`, `b204c66`, `405edfe`, 10:54 to 11:02 UTC). That run measured the
    same srflx-to-host change on the controlling side and treated it as the
    hard stop. The user said to ignore it. Since force-pushing is ruled out,
    `37dab7d` is an `-s ours` merge: those commits stay in history, none of
    their files are in the tree.
13. **The srflx-to-host change is reported, not treated as a hard stop** (see
    "Hard-stop assessment"). The task lists the reported local candidate type
    under behavior to record and says to call a change such as "srflx shown as
    host" out explicitly with evidence. It is a direct consequence of the
    mandated response routing, and it changes no packet path. The e2e
    comparison decides whether anything else differs.
14. To let the pre-push hook's `make lint` typecheck `client/ui` as CI does,
    the session installed the packages CI installs
    (`libgtk-4-dev libwebkitgtk-6.0-dev libsoup-3.0-dev libgl1-mesa-dev
    xorg-dev libpcap-dev`) and created the ignored placeholder
    `client/ui/frontend/dist/.embed-placeholder`, as the lint workflow does.
    `make lint` then passes in the hook. No hook was bypassed.
15. The parallel run kept pushing to this branch: nine more commits
    (`f6095c0` to `42b087a`, 12:44 to 13:28 UTC), branched from `f1048ac`
    and merging `2b97cd1` on the way (`e42654b`). They rewrite the tracker's
    `forget` contract, add a per-mux expiry goroutine, change about 110 lines
    of `mux.go`, add lifecycle tests and edit
    `client/internal/peer/wg_watcher_test.go` and
    `client/iface/bind/ice_bind_test.go` (outside the task's scope). None of
    it is in `37dab7d`, the commit both e2e comparisons built. Following the
    user's instruction, `27531b6` is again an `-s ours` merge: the commits
    stay in history, the tree under `client/` is byte-identical to `37dab7d`.
    That run's artifact audit of runs 39588288742 and 39597620276 is the only
    source of candidate types and ICE timings here; its code changes are
    assessed in "Parallel run's defect claims". The real fix was separate
    branches, done at decision 22.
16. **Dup-follow not adopted.** Against a peer that answers every request
    twice (pre-0.57 broadcast muxes), the first answer consumes the record and
    the second goes through the unchanged fallback, which re-creates the
    misattribution for that peer. Keeping the record for a short time after
    the first answer and routing the duplicate the same way made the POC side
    select host-local 30 of 30 times against such a peer (v4 model below).
    It contradicts the task's "remove entries on response" rule, so it is
    listed as a step-2 option, not committed.
17. **Scratch cross-version tests use the real v0.30.1 code.** A throwaway
    worktree (never committed) adds `github.com/pion/ice/v3` (replaced by
    `netbirdio/ice/v3 v3.0.0-20240315174635-e72a50fcb64e`, as v0.30.1's
    `go.mod` does) and copies v0.30.1's `client/iface/bind/udp_mux*.go`. The
    branch's `go.mod` is untouched. The same worktree holds the timing and
    trace trials of "Hard stop": NetBird's ICE timeouts on both agents, the
    v0.30.1 extra srflx candidate signalled as v0.30.1 does, a fresh vnet NAT
    lab per trial, 12 s per attempt. The worktree lives in the session's
    scratch space and is not preserved; this description is the record.
18. **The repo e2e suites ran with two sandbox workarounds** (see "Netstack
    e2e"): one harness capability dropped (this sandbox's Docker refuses
    `CAP_SYS_RESOURCE`) and a substitute client image (the Alpine mirror is
    blocked). Both live only in a scratch worktree and are not committed.
19. **Commit authorship.** The commits written by this run (`3d8b652` to
    `5804612`) carry the session environment's default git author identity,
    not the user's. Correcting them would rewrite pushed history, which the
    task rules out. Later commits are authored by Maycon Santos.
20. **Stopped at the lost-nomination finding.** Once the scratch trials and a
    pion trace confirmed it (see "Hard stop"), no code change was attempted:
    both fixes are outside the agreed design. Only this log was changed
    afterwards.
21. **Third merge of the parallel run's commits.** While this report was
    written the parallel run pushed nine more commits (`b01ed07` to
    `145a4ab`, 14:32 to 15:32 UTC). Among them, `993c5e1` ("Give each mux
    candidate its own read queue") and `f209580` ("Preserve candidate
    ownership for duplicate STUN responses") change `mux.go`, `conn.go` and
    `transactions.go` in the direction "Hard stop" names (per-candidate
    delivery, dup-follow). They were not read in detail, run or validated
    here, and per the user's instruction `7643575` is an `-s ours` merge:
    the tree under `client/` stays byte-identical to `37dab7d`. Anyone
    picking up step 1 of "Step 2" should evaluate those commits on their
    own SHA with the scratch trials and the e2e selection described here.
22. **Separate branches.** Both runs were given `poc/udpmux-txid-routing` by
    the same task text, and each kept pushing to it. Merging the other run's
    commits with `-s ours` kept this run's tree but left the other run's work
    reverted at the tip, so a plain pull on its side would have undone its
    `udpmux` changes. This run moved to its own branch,
    `work/admiring-planck-1l2xh2`, starting at `75a31b4` so every commit this
    log cites stays reachable, and returned `poc/udpmux-txid-routing` to the
    other run with `6f5ef8a`, a forward commit whose tree equals `145a4ab`,
    that run's last push. No history was rewritten; this run no longer writes
    to that branch.

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

The 5-tuple and the WireGuard endpoint (taken from the remote candidate) do
not change. NetBird uses the local candidate type only for display and logs:
`worker_ice.go:340-350` copies it into `ICEConnInfo`, `conn.go:758-768` into
the peer state, `client/status/status.go:335-338` prints it, and the UI and
mobile SDKs show it. Relay detection (`isRelayed`, `worker_ice.go:786-791`)
and connection priority look only at relay candidates. `netbird status -d`
shows `ICE candidate (Local/Remote): host/srflx` and the interface address as
the local endpoint where it showed `srflx/srflx` and the public mapping.
proxbird's NAT check accepts srflx or prflx on either side, so it still passes.

### In the e2e runs

From the parallel run's artifact audit of runs 39588288742 and 39597620276
(initial `start-clients` snapshot per directed peer observation; not
re-verified here, decision 11). 298 directed observations in 85 cases:

| Observations | count | local type unchanged | srflx → host | host → srflx |
| --- | --- | --- | --- | --- |
| 65 cases between source-built peers | 258 | 199 | 57 | 2 |
| 20 `client-tests` cases, modern peer reporting | 20 | 10 | 4 | 6 |
| 20 `client-tests` cases, 0.28.9/0.30.1 peer reporting | 20 | 12 | 0 | 8 |
| all | 298 | 221 | 61 | 16 |

Path/status: 0 of 298 initial observations differ. Between source-built
peers the change is the predicted one (57 of 59 are srflx to host). Against
the reference peers the reported types move both ways: the modern peer
reported host 16 of 20 on baseline and 14 of 20 on the POC; the reference peer
reported host 20 of 20 on baseline and 12 of 20 on the POC. Each case ran
once per commit, so the e2e data alone cannot tell a systematic shift from
noise.

### Against pre-0.57 peers (scratch trials, 30 connections per row)

Selected local type per side, one fresh NAT lab per trial, roles alternating:

| Modern client | Old peer model | client host / srflx | old peer host / srflx | client requests answered twice |
| --- | --- | --- | --- | --- |
| baseline mux | v4 fork on baseline mux, pair ID stripped both ways | 19 / 11 | 16 / 14 | not recorded |
| POC mux | same | 22 / 8 | 18 / 12 | not recorded |
| POC mux, dup-follow (decision 16) | same | 30 / 0 | 17 / 13 | not recorded |
| baseline mux | **real v0.30.1**: `netbirdio/ice/v3` on the v0.30.1 mux | 19 / 11 | 22 / 8 | 258 of 258 |
| POC mux | **real v0.30.1** | 20 / 10 | 23 / 7 | **0 of 259** |

Against pre-0.57 peers, selection is random on both commits and the
distributions match within the sample. The v0.30.1 trials do not reproduce
the e2e reference-peer shift (20/20 to 12/20 host): with the real agent the
old peer reports host 22 and 23 of 30. The e2e shift is therefore unexplained
and unproven as systematic; it is a display-level difference in any case, all
20 cases connected P2P on every run, and the repetitions passed. What the
POC does change against these peers is measurable: it answers each of their
requests once instead of twice.

Two side effects follow from host conns being shared (pre-existing, not
caused by the routing):

- With several host candidates of one family (unspecified bind on a host
  with several interface addresses, common with IPv6), all share the ufrag's
  host conn and each runs its own read loop on it. Which candidate processes a
  response is a race, so a selected host-local pair can see some of its
  keepalive responses credited to a sibling pair, updating its RTT less often.
  Baseline already had this for host-host paths (LAN, direct); the POC extends
  host-local selection to NAT paths. The same race is the root of the hard
  stop: it can also swallow a nomination.
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

| Test | with pair ID | without pair ID |
| --- | --- | --- |
| 1, host and srflx | responses not delivered to exactly the requesting conn: controlling host 3 of 5, controlled host 4 of 8 | responses 5 of 5 and 12 of 12; requests delivered or answered more than once 12 of 12 and 5 of 5 |
| 2, overlapping agents | responses: host A 5 of 9, host B 7 of 17 | responses: host A 9 of 9, host B 22 of 22; requests: host A 23 of 23, host B 9 of 9 |
| 3, 20 agent pairs | responses: host A 66 of 149, host B 64 of 148 | responses: host A 156 of 156, host B 164 of 164; requests: host A 164 of 164, host B 158 of 158 |
| Socket level | `connB must not receive the response to connA's request` | `connB must not receive connA's request` |

With the pair ID, a check sent from the host conn is read by the srflx conn:
the remote identifies the sender by source address, which is the srflx
mapping, and stamps the srflx candidate as target. Without it, requests are
read by the host and the srflx conn of the agent and answered by both, and
each response is read several times (two answers, each broadcast to both
conns).

### After

- Commit `d8e7f21` (responses by transaction ID only): all with-pair-ID
  scenarios pass; without-pair-ID scenarios still fail on duplicated requests.
- Commit `cb20fec` (requests by USERNAME): all pass.
- After the review fixes (`c058965`, the head's code):
  `go test -race -count=10 ./client/iface/udpmux/` passes, no race reports.
- Seven mutants built during review (order swap, no pair-ID fallback,
  queue-based eviction, no `forget`, no `clear`, no closed check, wrong-agent
  delivery) all fail the suite.
- Variant R (no pair-ID lookup in `findSTUNRecipient`, applied with
  `go test -overlay`): every test passes except
  `TestUniversalUDPMux_PairIDRouting`, which asserts the kept pair-ID behavior
  and fails by design.

### Repository checks

| Check | Result |
| --- | --- |
| `go fmt` on changed files | clean (`go fmt ./...` also touches 26 pre-existing unrelated files; reverted, decision 8) |
| `make lint` (diff vs `origin/main`, pre-push hook) | passes on every push since decision 14 |
| `make lint-all` | `0 issues` on the head's code (13:25 UTC; the only output besides that is golangci-lint's "unknown linters in //nolint" warning) |
| `golangci-lint run ./client/iface/udpmux/...` (whole package) | 0 issues |
| `make test-unit` | same failing packages as baseline `1e63b68` in the same environment, run at 15:00 UTC with Docker available: `client/iface/bind` (`TestICEBind_OpenDoesNotDiscoverInterfaces`, `Open(0)` returns port 0 in this sandbox), `client/iface/device` (`TestModuleStatus`, kernel module), `client/internal/dns` and `dns/mgmt` (resolver tests), `management/cmd` (`Test_LoadMgmtConfig`), `sharedsock` (raw sockets); baseline also fails `client/ui` setup (its scratch worktree lacks the frontend placeholder). One head-only failure, `management/server` `TestAffectedPeers_IPv4RangeChange_RefreshesWholeAccount` ("Timed out waiting for update message"), ran while e2e and trials loaded the machine; the package does not import `udpmux` and has no diff, and its one retry passed (1.3 s). The earlier runs without Docker (11:20 to 12:06 UTC, at `cb20fec` and, for the 66 dependent packages, `c058965`) had a different, equally environmental set |
| `go test -race ./client/iface/udpmux/... ./client/iface/bind/... ./client/internal/peer/...` | `udpmux`, `peer/guard`, `peer/ice` ok. `bind`: `TestICEBind_OpenDoesNotDiscoverInterfaces`, as in `make test-unit`, on baseline too. `peer`: a data race between `TestWGWatcher_CheckSuccessCallback`'s leftover goroutine and `TestWGWatcher_EnableWgWatcher` writing package-level `checkPeriod`; it reproduces on baseline (3 of 6 `-race` runs in the saved log, 5 of 6 in an earlier set), test-only, unrelated to the mux. Last run 15:10 UTC on the head |
| After the review fixes (`c058965`): `go test -tags devcert` over the 66 packages that import `udpmux` | failures only from the baseline set (`TestICEBind_OpenDoesNotDiscoverInterfaces`, `TestModuleStatus`, `TestUpstreamResolver_ServeDNS`, `client/ui` setup) |
| Cross-builds of `udpmux`: `GOOS=windows/darwin/linux go vet`, `GOOS=js GOARCH=wasm`, `GOOS=android` build | ok. `GOOS=freebsd go vet` fails in `wgctrl` (`wgfreebsd.New` needs cgo), identically on baseline; FreeBSD clients are built natively by proxbird |
| `universal.go`, `go.mod`, `go.sum` vs `1e63b68` | unchanged |
| GitHub workflows on branch push | none triggered (netbird push workflows target `main`/`release-*` only) |

### Two-pass race analysis

Shared state the change adds or reads:

- **Tracker** (`entries`, `queue`, `seq`): every method takes `t.mu`;
  `pruneExpired`, `evictOldest`, `popHead` and `compact` run only under it.
  Inside it the tracker calls only `conn.isClosed()`, a non-blocking channel
  select, so `t.mu` is a leaf. Callers: `WriteTo` (no mux or conn lock held;
  `c.mu` is released by `containsAddress`/`addAddress` before
  `trackRequest`), `HandleSTUNMessage` (no lock held), `RemoveConnByUfrag`
  (after `m.mu` is released) and `Close` (under `m.mu`). The only nesting is
  `m.mu` then `t.mu`; nothing takes `m.mu` under `t.mu`.
- **Reads of existing maps**: `findSTUNRecipient` reads `candidateConnMap`
  and `connsIPv4/6` under `m.mu` (inside `findCandidateConnection` and
  `findConnectionByUsername`) and `addressMap` under `addressMapMu` (inside
  `forwardToAllConnections`), as baseline does. The conn pointer it returns is
  used after the lock is released; a concurrent close makes `writePacket`
  return a closed-pipe error, as on baseline.
- **Second pass, lifecycle**: `record` checks `isClosed` under `t.mu`, and
  `removeConn` and `clear` run under `t.mu`, so a record cannot be added for a
  conn after its removal passed if the conn was already closed. Pion removes
  the ufrag from the mux and then closes the candidates in its loop's close
  function (fork `agent.go:304-306`), after the loop has stopped running
  tasks; checks, answers and keepalives are loop tasks, so no write reaches a
  muxed conn between removal and close. `conn.params.Mux` is set at
  construction and never reassigned.
- `go test -race -count=10 ./client/iface/udpmux/` passes on the head's code.

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

### Parallel run's defect claims, checked against the head

The parallel run (decision 15) listed nine defects and fixed them in
`532e38b` and later commits. Verdicts for the head's code:

| Claimed defect | Verdict for the head |
| --- | --- |
| Removed conns can register transactions and addresses again | Not reachable with pion's call order: removal and candidate close run back to back in the stopped agent loop (race analysis above). Address re-registration by a write after removal is baseline code. |
| Closing an old conn removes a replacement with the same ufrag | Pre-existing: closing a muxed conn does not touch the mux here; `RemoveConnByUfrag(ufrag)` removes whatever conn holds that ufrag, as on baseline (decision 7). |
| Removing one conn erases a surviving conn's fallback address | Pre-existing (#4154), unchanged. Less impact than on baseline: answered requests and USERNAME requests no longer depend on `addressMap`. |
| Parallel first writes register one conn twice | Pre-existing `containsAddress`/`addAddress` code; writes of one agent are serialized in its loop. |
| Mux close retains candidate and address maps | Pre-existing; `Close` clears the tracker. The mux is discarded after close. |
| Idle transactions stay allocated beyond the TTL | Deliberate: expiry is lazy, expired records are never used, memory is bounded by the cap, and no goroutine is added per mux. |
| A delayed write error deletes a newer same-conn retransmission | Not reachable: pion never resends a transaction ID (decision 5) and its writes are serialized. |
| A failed resend deletes the earlier request's mapping | Not reachable, same reason. |
| Invalid STUN length headers consume tracker entries | Not reachable from the network: only buffers that local pion agents write are parsed, and the cap bounds the entries. |

Its test-only changes outside `udpmux` (`ice_bind_test.go` receive buffers,
`wg_watcher_test.go` goroutine joins) address real pre-existing test races
(the `wg_watcher` one is reproduced below on baseline) but are outside this
task's scope.

## Cross-version checks (scratch only, not committed)

proxbird has no case that pairs the candidate build with a current release
peer (its references are 0.28.9 and 0.30.1, both older than pair-ID routing,
which shipped in v0.57.0 with #4430). A throwaway worktree got a renamed copy
of the baseline mux (`git show 1e63b68:client/iface/udpmux/{mux,conn,universal,mux_generic}.go`
as package `baselinemux`) and, for the v0.30.1 trials above, the real v0.30.1
mux and ICE v3 fork (decision 17). Each test connects a POC-mux host to the
other host over the same vnet NAT.

Baseline mux peer, two agent pairs at once, 5 runs per row:

| Peer | POC role | Connected | POC host routing | Selected (POC / peer), all runs |
| --- | --- | --- | --- | --- |
| baseline mux, stamps pair ID (v0.57+ behavior) | controlling | 5/5 | clean | host/srflx / srflx/srflx |
| baseline mux, stamps pair ID | controlled | 5/5 | clean | srflx/srflx / srflx/srflx |
| broadcast mux, no pair ID either way (pre-0.57 routing) | controlling | 5/5 | duplicates via fallback, see below | POC host/srflx or srflx/srflx; peer host/srflx |
| broadcast mux, no pair ID either way | controlled | 5/5 | duplicates via fallback | POC host/srflx; peer host/srflx or srflx/srflx |

Against the broadcast peer every response arrives twice, because that peer
answers each request from both its candidates. The first copy goes to the
requesting conn by transaction ID; the second has no record and goes through
the unchanged fallback to every conn that wrote to that address, so the strict
routing assertion fails on the POC host (7 to 13 of 7 to 13 responses). This is
the peer's duplicate, delivered as baseline delivers it; the POC side itself
answers every request exactly once (0 duplicated requests). Against the
stamping peer the POC host is clean and the peer receives no duplicate
answers; the baseline side still misroutes its own responses (5 to 8 of 9 to
16 per run), its pre-existing behavior.

An earlier version of this table showed the broadcast variant as clean: that
variant stripped the pair ID only from the peer's outgoing messages, so the
old mux still routed by the POC's pair IDs. Fixed by stripping both ways.

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
  section 14), so legacy agents ignore it. (RFC text not re-read, decision 10.)

## E2E comparison, full selection (baseline run 39588288742 vs POC run 39597620276)

Both runs: proxbird harness `a1abca5`, `client_source=netbird-main`,
`lab_source=source-build`, same 85-case selection, attempt 1, no retries.
**Baseline 85/85 passed, POC 85/85 passed.** No case was re-run. Per the
parallel run's audit of the same artifacts, both runs report Linux kernel
mode on 82 nodes and userspace mode on 56 FreeBSD, 32 macOS and 32 Windows
nodes, 16 nodes at 0.30.1 and 4 at 0.28.9; no current-release binary.

"P2P/relay" is the path proxbird asserts for the case; a pass proves it held
in that run. Setup convergence is defined under "Resuming" below.

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
| **all** | **85** | **8.0** | **8.4** | **+0.00** | **43 / 42** |

### ICE dial to success (parallel run's audit)

212 paired successful ICE observations (first dial to first success on one
node's clock, including failed attempts): median 0.605 s on both commits.
Above 1.5 s: 7 on baseline (13.9 to 22.4 s), 5 on the POC (13.1 to 29.1 s).
The parallel run traced the first failed attempts of the POC episodes to
candidates arriving before the agent existed (`worker_ice.go:181-193` discards
them), which also occurs on baseline edges. It left one unexplained,
`client-windows-nat-dns` against 0.30.1: the Windows side stayed `Checking` on
its second attempt while the old peer reported success. That is the signature
of the lost nomination in "Hard stop". LAN host/host edges (direct cases and
router to router) are bimodal, about 2 ms or about 1 s (one more check round):
of 37 such edges, 11 went fast to slow and 8 slow to fast, median 0.003 s on
both commits. Apart from that episode, with one sample per case none of these
is attributable to the mux.

### Per case

Columns 5 to 7 come from the parallel run's artifact audit and were not
re-verified here (decision 11). `1>2` is peer-1 reporting peer-2, `2R` a
replacement peer; `→` separates baseline from POC, `(both)` marks equal
values; types are local/remote from the initial `start-clients` snapshot;
`-/-` is a relayed pair. Artifacts expire on 2026-11-04.

| Case | Baseline / POC | P2P/relay asserted | Setup convergence B / P (s) | First ICE dial to success B → P (s)¹ | Local/remote candidate types, initial snapshot B → P¹ | Artifacts¹ |
| --- | --- | --- | --- | --- | --- | --- |
| `client-freebsd-nat-allowed-ports` | success / success | P2P | 3.2 / 1.3 | 1>2:0.604→0.625; 2:legacy peer not measured | 1>2:host/srflx; 2>1:host/srflx → 1>2:srflx/srflx; 2>1:host/srflx | B [12340654721](https://github.com/netbirdio/proxbird-tests/actions/runs/39588288742/artifacts/12340654721)<br>P [12344594476](https://github.com/netbirdio/proxbird-tests/actions/runs/39597620276/artifacts/12344594476) |
| `client-freebsd-nat-connect-legacy` | success / success | P2P | 0.7 / 3.2 | 1>2:0.604→0.604; 2:legacy peer not measured | 1>2:host/srflx; 2>1:host/srflx (both) | B [12342305010](https://github.com/netbirdio/proxbird-tests/actions/runs/39588288742/artifacts/12342305010)<br>P [12345956309](https://github.com/netbirdio/proxbird-tests/actions/runs/39597620276/artifacts/12345956309) |
| `client-freebsd-nat-connect-relay` | success / success | P2P | 3.2 / 3.3 | 1>2:0.613→0.603; 2:legacy peer not measured | 1>2:srflx/srflx; 2>1:host/srflx → 1>2:host/srflx; 2>1:host/srflx | B [12341165873](https://github.com/netbirdio/proxbird-tests/actions/runs/39588288742/artifacts/12341165873)<br>P [12345452007](https://github.com/netbirdio/proxbird-tests/actions/runs/39597620276/artifacts/12345452007) |
| `client-freebsd-nat-dns` | success / success | P2P | 3.2 / 3.4 | 1>2:0.605→0.605; 2:legacy peer not measured | 1>2:host/srflx; 2>1:host/srflx (both) | B [12341410760](https://github.com/netbirdio/proxbird-tests/actions/runs/39588288742/artifacts/12341410760)<br>P [12345532811](https://github.com/netbirdio/proxbird-tests/actions/runs/39597620276/artifacts/12345532811) |
| `client-freebsd-nat-exit-node` | success / success | P2P | 3.0 / 3.4 | 1>2:0.615→0.605; 2:legacy peer not measured | 1>2:host/srflx; 2>1:host/srflx → 1>2:srflx/srflx; 2>1:srflx/srflx | B [12341420754](https://github.com/netbirdio/proxbird-tests/actions/runs/39588288742/artifacts/12341420754)<br>P [12345242992](https://github.com/netbirdio/proxbird-tests/actions/runs/39597620276/artifacts/12345242992) |
| `client-linux-nat-allowed-ports` | success / success | P2P | 3.6 / 4.1 | 1>2:0.606→0.606; 2:legacy peer not measured | 1>2:host/srflx; 2>1:host/srflx (both) | B [12341094768](https://github.com/netbirdio/proxbird-tests/actions/runs/39588288742/artifacts/12341094768)<br>P [12345252179](https://github.com/netbirdio/proxbird-tests/actions/runs/39597620276/artifacts/12345252179) |
| `client-linux-nat-connect-legacy` | success / success | P2P | 3.4 / 6.3 | 1>2:0.603→0.605; 2:legacy peer not measured | 1>2:srflx/srflx; 2>1:host/srflx → 1>2:host/srflx; 2>1:host/srflx | B [12341034872](https://github.com/netbirdio/proxbird-tests/actions/runs/39588288742/artifacts/12341034872)<br>P [12344703617](https://github.com/netbirdio/proxbird-tests/actions/runs/39597620276/artifacts/12344703617) |
| `client-linux-nat-connect-relay` | success / success | P2P | 3.7 / 30.7 | 1>2:0.605→29.127; 2:legacy peer not measured | 1>2:host/srflx; 2>1:host/srflx → 1>2:host/prflx; 2>1:srflx/srflx | B [12341850071](https://github.com/netbirdio/proxbird-tests/actions/runs/39588288742/artifacts/12341850071)<br>P [12345292351](https://github.com/netbirdio/proxbird-tests/actions/runs/39597620276/artifacts/12345292351) |
| `client-linux-nat-dns` | success / success | P2P | 3.4 / 3.4 | 1>2:0.605→0.605; 2:legacy peer not measured | 1>2:host/srflx; 2>1:host/srflx (both) | B [12341540836](https://github.com/netbirdio/proxbird-tests/actions/runs/39588288742/artifacts/12341540836)<br>P [12345198908](https://github.com/netbirdio/proxbird-tests/actions/runs/39597620276/artifacts/12345198908) |
| `client-linux-nat-exit-node` | success / success | P2P | 3.6 / 3.5 | 1>2:0.606→0.605; 2:legacy peer not measured | 1>2:host/srflx; 2>1:host/srflx → 1>2:srflx/srflx; 2>1:srflx/srflx | B [12341545883](https://github.com/netbirdio/proxbird-tests/actions/runs/39588288742/artifacts/12341545883)<br>P [12346200603](https://github.com/netbirdio/proxbird-tests/actions/runs/39597620276/artifacts/12346200603) |
| `client-macos-nat-allowed-ports` | success / success | P2P | 4.7 / 3.5 | 1>2:0.606→0.606; 2:legacy peer not measured | 1>2:host/srflx; 2>1:host/srflx (both) | B [12342480775](https://github.com/netbirdio/proxbird-tests/actions/runs/39588288742/artifacts/12342480775)<br>P [12345992075](https://github.com/netbirdio/proxbird-tests/actions/runs/39597620276/artifacts/12345992075) |
| `client-macos-nat-connect-legacy` | success / success | P2P | 4.1 / 6.4 | 1>2:0.605→0.604; 2:legacy peer not measured | 1>2:host/srflx; 2>1:host/srflx → 1>2:host/srflx; 2>1:srflx/srflx | B [12342625657](https://github.com/netbirdio/proxbird-tests/actions/runs/39588288742/artifacts/12342625657)<br>P [12346062221](https://github.com/netbirdio/proxbird-tests/actions/runs/39597620276/artifacts/12346062221) |
| `client-macos-nat-connect-relay` | success / success | P2P | 3.4 / 3.3 | 1>2:0.604→0.605; 2:legacy peer not measured | 1>2:host/srflx; 2>1:host/srflx → 1>2:srflx/srflx; 2>1:host/srflx | B [12342735708](https://github.com/netbirdio/proxbird-tests/actions/runs/39588288742/artifacts/12342735708)<br>P [12344833609](https://github.com/netbirdio/proxbird-tests/actions/runs/39597620276/artifacts/12344833609) |
| `client-macos-nat-dns` | success / success | P2P | 3.2 / 3.4 | 1>2:0.606→0.603; 2:legacy peer not measured | 1>2:srflx/srflx; 2>1:host/srflx → 1>2:host/srflx; 2>1:host/srflx | B [12341906028](https://github.com/netbirdio/proxbird-tests/actions/runs/39588288742/artifacts/12341906028)<br>P [12345443406](https://github.com/netbirdio/proxbird-tests/actions/runs/39597620276/artifacts/12345443406) |
| `client-macos-nat-exit-node` | success / success | P2P | 3.4 / 3.4 | 1>2:0.605→0.605; 2:legacy peer not measured | 1>2:srflx/srflx; 2>1:host/srflx → 1>2:host/srflx; 2>1:host/srflx | B [12341841039](https://github.com/netbirdio/proxbird-tests/actions/runs/39588288742/artifacts/12341841039)<br>P [12345398159](https://github.com/netbirdio/proxbird-tests/actions/runs/39597620276/artifacts/12345398159) |
| `client-windows-nat-allowed-ports` | success / success | P2P | 24.4 / 3.2 | 1>2:21.180→0.605; 2:legacy peer not measured | 1>2:host/srflx; 2>1:host/prflx → 1>2:host/srflx; 2>1:host/srflx | B [12341137187](https://github.com/netbirdio/proxbird-tests/actions/runs/39588288742/artifacts/12341137187)<br>P [12344709817](https://github.com/netbirdio/proxbird-tests/actions/runs/39597620276/artifacts/12344709817) |
| `client-windows-nat-connect-legacy` | success / success | P2P | 14.1 / 12.6 | 1>2:13.882→13.142; 2:legacy peer not measured | 1>2:host/srflx; 2>1:host/srflx → 1>2:srflx/srflx; 2>1:srflx/srflx | B [12342086503](https://github.com/netbirdio/proxbird-tests/actions/runs/39588288742/artifacts/12342086503)<br>P [12346321422](https://github.com/netbirdio/proxbird-tests/actions/runs/39597620276/artifacts/12346321422) |
| `client-windows-nat-connect-relay` | success / success | P2P | 3.2 / 3.9 | 1>2:0.605→0.604; 2:legacy peer not measured | 1>2:host/srflx; 2>1:host/srflx → 1>2:srflx/srflx; 2>1:srflx/srflx | B [12342531334](https://github.com/netbirdio/proxbird-tests/actions/runs/39588288742/artifacts/12342531334)<br>P [12345963160](https://github.com/netbirdio/proxbird-tests/actions/runs/39597620276/artifacts/12345963160) |
| `client-windows-nat-dns` | success / success | P2P | 22.4 / 32.1 | 1>2:21.182→29.053; 2:legacy peer not measured | 1>2:host/srflx; 2>1:host/prflx → 1>2:host/prflx; 2>1:srflx/srflx | B [12341942075](https://github.com/netbirdio/proxbird-tests/actions/runs/39588288742/artifacts/12341942075)<br>P [12346227132](https://github.com/netbirdio/proxbird-tests/actions/runs/39597620276/artifacts/12346227132) |
| `client-windows-nat-exit-node` | success / success | P2P | 3.4 / 3.4 | 1>2:0.609→0.607; 2:legacy peer not measured | 1>2:host/srflx; 2>1:host/srflx → 1>2:host/srflx; 2>1:srflx/srflx | B [12341566794](https://github.com/netbirdio/proxbird-tests/actions/runs/39588288742/artifacts/12341566794)<br>P [12345968342](https://github.com/netbirdio/proxbird-tests/actions/runs/39597620276/artifacts/12345968342) |
| `connectivity-repair-freebsd-nat-path-repair` | success / success | Relayed while blocked; P2P or Relayed after repair | 7.5 / 7.1 | 1>2:0.605→0.604; 2>1:0.606→0.605 | 1>2:srflx/srflx; 2>1:srflx/srflx → 1>2:srflx/srflx; 2>1:host/srflx | B [12341916838](https://github.com/netbirdio/proxbird-tests/actions/runs/39588288742/artifacts/12341916838)<br>P [12346216851](https://github.com/netbirdio/proxbird-tests/actions/runs/39597620276/artifacts/12346216851) |
| `connectivity-repair-linux-nat-path-repair` | success / success | Relayed while blocked; P2P or Relayed after repair | 6.4 / 11.2 | 1>2:0.604→0.603; 2>1:0.605→0.605 | 1>2:srflx/srflx; 2>1:srflx/srflx → 1>2:srflx/srflx; 2>1:host/srflx | B [12342606512](https://github.com/netbirdio/proxbird-tests/actions/runs/39588288742/artifacts/12342606512)<br>P [12344814457](https://github.com/netbirdio/proxbird-tests/actions/runs/39597620276/artifacts/12344814457) |
| `connectivity-repair-macos-nat-path-repair` | success / success | Relayed while blocked; P2P or Relayed after repair | 5.9 / 6.0 | 1>2:0.604→0.605; 2>1:0.605→0.605 | 1>2:srflx/srflx; 2>1:srflx/srflx → 1>2:host/srflx; 2>1:srflx/srflx | B [12342611591](https://github.com/netbirdio/proxbird-tests/actions/runs/39588288742/artifacts/12342611591)<br>P [12345154255](https://github.com/netbirdio/proxbird-tests/actions/runs/39597620276/artifacts/12345154255) |
| `connectivity-repair-windows-nat-path-repair` | success / success | Relayed while blocked; P2P or Relayed after repair | 7.5 / 7.5 | 1>2:0.605→0.603; 2>1:0.612→0.610 | 1>2:srflx/srflx; 2>1:srflx/srflx → 1>2:srflx/srflx; 2>1:host/srflx | B [12342246693](https://github.com/netbirdio/proxbird-tests/actions/runs/39588288742/artifacts/12342246693)<br>P [12345658989](https://github.com/netbirdio/proxbird-tests/actions/runs/39597620276/artifacts/12345658989) |
| `connectivity-underlay-linux-nat-underlay-change` | success / success | P2P before and after the move | 6.1 / 6.2 | 1>2:0.604→0.603; 2>1:0.604→0.604 | 1>2:srflx/srflx; 2>1:srflx/srflx → 1>2:host/srflx; 2>1:srflx/srflx | B [12341802157](https://github.com/netbirdio/proxbird-tests/actions/runs/39588288742/artifacts/12341802157)<br>P [12346103703](https://github.com/netbirdio/proxbird-tests/actions/runs/39597620276/artifacts/12346103703) |
| `freebsd-freebsd-direct` | success / success | P2P | 7.3 / 7.1 | 1>2:0.614→1.044; 2>1:0.614→1.044 | 1>2:srflx/srflx; 2>1:srflx/srflx → 1>2:host/host; 2>1:host/prflx | B [12342671706](https://github.com/netbirdio/proxbird-tests/actions/runs/39588288742/artifacts/12342671706)<br>P [12346337131](https://github.com/netbirdio/proxbird-tests/actions/runs/39597620276/artifacts/12346337131) |
| `freebsd-freebsd-nat` | success / success | P2P | 5.7 / 5.2 | 1>2:0.620→0.623; 2>1:0.621→0.624 | 1>2:srflx/srflx; 2>1:srflx/srflx → 1>2:srflx/srflx; 2>1:host/srflx | B [12341192628](https://github.com/netbirdio/proxbird-tests/actions/runs/39588288742/artifacts/12341192628)<br>P [12345644301](https://github.com/netbirdio/proxbird-tests/actions/runs/39597620276/artifacts/12345644301) |
| `freebsd-freebsd-relay` | success / success | Relayed | 7.7 / 5.6 | 1>2:unmeasured→unmeasured; 2>1:unmeasured→unmeasured | 1>2:-/-; 2>1:-/- (both) | B [12341387476](https://github.com/netbirdio/proxbird-tests/actions/runs/39588288742/artifacts/12341387476)<br>P [12346371707](https://github.com/netbirdio/proxbird-tests/actions/runs/39597620276/artifacts/12346371707) |
| `freebsd-freebsd-slow` | success / success | P2P | 8.5 / 6.0 | 1>2:0.903→0.704; 2>1:0.903→0.905 | 1>2:srflx/srflx; 2>1:srflx/srflx → 1>2:srflx/srflx; 2>1:host/srflx | B [12341258342](https://github.com/netbirdio/proxbird-tests/actions/runs/39588288742/artifacts/12341258342)<br>P [12345059832](https://github.com/netbirdio/proxbird-tests/actions/runs/39597620276/artifacts/12345059832) |
| `macos-macos-direct` | success / success | P2P | 5.9 / 5.6 | 1>2:1.008→0.603; 2>1:1.011→0.604 | 1>2:host/srflx; 2>1:srflx/prflx → 1>2:host/srflx; 2>1:srflx/host | B [12341522480](https://github.com/netbirdio/proxbird-tests/actions/runs/39588288742/artifacts/12341522480)<br>P [12345889105](https://github.com/netbirdio/proxbird-tests/actions/runs/39597620276/artifacts/12345889105) |
| `macos-macos-nat` | success / success | P2P | 5.9 / 5.6 | 1>2:0.607→0.629; 2>1:0.607→0.628 | 1>2:srflx/srflx; 2>1:srflx/srflx → 1>2:host/srflx; 2>1:srflx/srflx | B [12342402445](https://github.com/netbirdio/proxbird-tests/actions/runs/39588288742/artifacts/12342402445)<br>P [12345808790](https://github.com/netbirdio/proxbird-tests/actions/runs/39597620276/artifacts/12345808790) |
| `macos-macos-relay` | success / success | Relayed | 5.8 / 8.5 | 1>2:unmeasured→unmeasured; 2>1:unmeasured→unmeasured | 1>2:-/-; 2>1:-/- (both) | B [12342342613](https://github.com/netbirdio/proxbird-tests/actions/runs/39588288742/artifacts/12342342613)<br>P [12345834542](https://github.com/netbirdio/proxbird-tests/actions/runs/39597620276/artifacts/12345834542) |
| `macos-macos-slow` | success / success | P2P | 6.0 / 6.2 | 1>2:0.703→0.704; 2>1:0.905→0.905 | 1>2:srflx/srflx; 2>1:srflx/srflx → 1>2:srflx/srflx; 2>1:host/srflx | B [12341573505](https://github.com/netbirdio/proxbird-tests/actions/runs/39588288742/artifacts/12341573505)<br>P [12345329898](https://github.com/netbirdio/proxbird-tests/actions/runs/39597620276/artifacts/12345329898) |
| `macos-windows-direct` | success / success | P2P | 7.4 / 7.5 | 1>2:1.011→0.015; 2>1:1.004→0.002 | 1>2:host/prflx; 2>1:host/host (both) | B [12341193306](https://github.com/netbirdio/proxbird-tests/actions/runs/39588288742/artifacts/12341193306)<br>P [12345564980](https://github.com/netbirdio/proxbird-tests/actions/runs/39597620276/artifacts/12345564980) |
| `macos-windows-nat` | success / success | P2P | 7.4 / 7.6 | 1>2:0.612→0.611; 2>1:0.605→0.604 | 1>2:srflx/srflx; 2>1:srflx/srflx → 1>2:host/srflx; 2>1:srflx/srflx | B [12342137990](https://github.com/netbirdio/proxbird-tests/actions/runs/39588288742/artifacts/12342137990)<br>P [12346880490](https://github.com/netbirdio/proxbird-tests/actions/runs/39597620276/artifacts/12346880490) |
| `macos-windows-relay` | success / success | Relayed | 7.3 / 7.5 | 1>2:unmeasured→unmeasured; 2>1:unmeasured→unmeasured | 1>2:-/-; 2>1:-/- (both) | B [12341732793](https://github.com/netbirdio/proxbird-tests/actions/runs/39588288742/artifacts/12341732793)<br>P [12345934164](https://github.com/netbirdio/proxbird-tests/actions/runs/39597620276/artifacts/12345934164) |
| `macos-windows-slow` | success / success | P2P | 8.7 / 8.7 | 1>2:0.707→0.702; 2>1:0.704→0.899 | 1>2:srflx/srflx; 2>1:srflx/srflx → 1>2:srflx/srflx; 2>1:host/srflx | B [12342112840](https://github.com/netbirdio/proxbird-tests/actions/runs/39588288742/artifacts/12342112840)<br>P [12346422368](https://github.com/netbirdio/proxbird-tests/actions/runs/39597620276/artifacts/12346422368) |
| `recovery-freebsd-nat-daemon-restart` | success / success | P2P before and after restart | 7.7 / 7.6 | 1>2:0.604→0.615; 2>1:0.604→0.616 | 1>2:srflx/srflx; 2>1:srflx/srflx → 1>2:host/srflx; 2>1:srflx/srflx | B [12341379155](https://github.com/netbirdio/proxbird-tests/actions/runs/39588288742/artifacts/12341379155)<br>P [12346258720](https://github.com/netbirdio/proxbird-tests/actions/runs/39597620276/artifacts/12346258720) |
| `recovery-freebsd-nat-path-failure` | success / success | P2P, then Relayed while blocked | 7.7 / 7.8 | 1>2:0.603→0.603; 2>1:0.605→0.605 | 1>2:srflx/srflx; 2>1:srflx/srflx → 1>2:srflx/srflx; 2>1:host/srflx | B [12341608003](https://github.com/netbirdio/proxbird-tests/actions/runs/39588288742/artifacts/12341608003)<br>P [12347185358](https://github.com/netbirdio/proxbird-tests/actions/runs/39597620276/artifacts/12347185358) |
| `recovery-linux-nat-daemon-restart` | success / success | P2P before and after restart | 6.2 / 6.4 | 1>2:0.604→0.604; 2>1:0.605→0.605 | 1>2:srflx/srflx; 2>1:srflx/srflx → 1>2:srflx/srflx; 2>1:host/srflx | B [12341733274](https://github.com/netbirdio/proxbird-tests/actions/runs/39588288742/artifacts/12341733274)<br>P [12346114755](https://github.com/netbirdio/proxbird-tests/actions/runs/39597620276/artifacts/12346114755) |
| `recovery-linux-nat-path-failure` | success / success | P2P, then Relayed while blocked | 6.1 / 6.2 | 1>2:0.604→0.604; 2>1:0.605→0.605 | 1>2:srflx/srflx; 2>1:srflx/srflx → 1>2:host/srflx; 2>1:srflx/srflx | B [12341354543](https://github.com/netbirdio/proxbird-tests/actions/runs/39588288742/artifacts/12341354543)<br>P [12346841147](https://github.com/netbirdio/proxbird-tests/actions/runs/39597620276/artifacts/12346841147) |
| `recovery-macos-nat-daemon-restart` | success / success | P2P before and after restart | 6.2 / 5.9 | 1>2:0.604→0.604; 2>1:0.605→0.606 | 1>2:srflx/srflx; 2>1:srflx/srflx → 1>2:srflx/srflx; 2>1:host/srflx | B [12341808921](https://github.com/netbirdio/proxbird-tests/actions/runs/39588288742/artifacts/12341808921)<br>P [12347455296](https://github.com/netbirdio/proxbird-tests/actions/runs/39597620276/artifacts/12347455296) |
| `recovery-macos-nat-path-failure` | success / success | P2P, then Relayed while blocked | 30.4 / 6.0 | 1>2:22.425→0.606; 2>1:22.427→0.606 | 1>2:host/srflx; 2>1:srflx/prflx → 1>2:host/srflx; 2>1:srflx/srflx | B [12341264106](https://github.com/netbirdio/proxbird-tests/actions/runs/39588288742/artifacts/12341264106)<br>P [12346229646](https://github.com/netbirdio/proxbird-tests/actions/runs/39597620276/artifacts/12346229646) |
| `recovery-windows-nat-daemon-restart` | success / success | P2P before and after restart | 7.2 / 7.2 | 1>2:0.604→0.604; 2>1:0.611→0.612 | 1>2:srflx/srflx; 2>1:srflx/srflx → 1>2:srflx/srflx; 2>1:host/srflx | B [12341299068](https://github.com/netbirdio/proxbird-tests/actions/runs/39588288742/artifacts/12341299068)<br>P [12347655132](https://github.com/netbirdio/proxbird-tests/actions/runs/39597620276/artifacts/12347655132) |
| `recovery-windows-nat-path-failure` | success / success | P2P, then Relayed while blocked | 7.3 / 7.4 | 1>2:0.606→0.604; 2>1:0.610→0.611 | 1>2:srflx/srflx; 2>1:srflx/srflx → 1>2:srflx/srflx; 2>1:host/srflx | B [12342713738](https://github.com/netbirdio/proxbird-tests/actions/runs/39588288742/artifacts/12342713738)<br>P [12345899930](https://github.com/netbirdio/proxbird-tests/actions/runs/39597620276/artifacts/12345899930) |
| `routing-ha-freebsd-freebsd-nat-router-ha` | success / success | client-routers P2P, router-router P2P | 8.0 / 8.4 | 1>2:0.622→0.624; 1>2R:1.004→1.045; 1>3:0.612→0.623; 2>1:0.623→0.625; 2>3:0.002→1.032; 3>1:0.613→0.624; 3>2:0.002→1.032 | 1>2:srflx/srflx; 1>3:srflx/srflx; 2>1:srflx/srflx; 2>3:host/host; 3>1:srflx/srflx; 3>2:host/prflx → 1>2:host/srflx; 1>3:srflx/srflx; 2>1:srflx/srflx; 2>3:srflx/host; 3>1:host/srflx; 3>2:host/prflx | B [12342123979](https://github.com/netbirdio/proxbird-tests/actions/runs/39588288742/artifacts/12342123979)<br>P [12347226479](https://github.com/netbirdio/proxbird-tests/actions/runs/39597620276/artifacts/12347226479) |
| `routing-ha-freebsd-freebsd-relay-router-ha` | success / success | client-routers Relayed, router-router P2P | 17.0 / 13.4 | 1>2:unmeasured→unmeasured; 1>2R:unmeasured→unmeasured; 1>3:unmeasured→unmeasured; 2>1:unmeasured→unmeasured; 2>3:0.002→0.002; 3>1:unmeasured→unmeasured; 3>2:0.003→0.002 | 1>2:-/-; 1>3:-/-; 2>1:-/-; 2>3:host/host; 3>1:-/-; 3>2:host/prflx → 1>2:-/-; 1>3:-/-; 2>1:-/-; 2>3:host/host; 3>1:-/-; 3>2:host/host | B [12342244410](https://github.com/netbirdio/proxbird-tests/actions/runs/39588288742/artifacts/12342244410)<br>P [12347286224](https://github.com/netbirdio/proxbird-tests/actions/runs/39597620276/artifacts/12347286224) |
| `routing-ha-freebsd-linux-nat-router-ha` | success / success | client-routers P2P, router-router P2P | 31.7 / 28.7 | 1>2:0.603→21.147; 1>2R:0.603→0.603; 1>3:20.555→0.605; 2>1:0.605→21.149; 2>3:0.002→0.002; 3>1:20.557→0.604; 3>2:0.002→0.001 | 1>2:srflx/srflx; 1>3:srflx/srflx; 2>1:srflx/srflx; 2>3:host/host; 3>1:srflx/srflx; 3>2:host/host → 1>2:srflx/prflx; 1>3:host/srflx; 2>1:host/srflx; 2>3:host/host; 3>1:srflx/srflx; 3>2:host/host | B [12342674276](https://github.com/netbirdio/proxbird-tests/actions/runs/39588288742/artifacts/12342674276)<br>P [12347820615](https://github.com/netbirdio/proxbird-tests/actions/runs/39597620276/artifacts/12347820615) |
| `routing-ha-freebsd-linux-relay-router-ha` | success / success | client-routers Relayed, router-router P2P | 16.6 / 9.0 | 1>2:unmeasured→unmeasured; 1>2R:unmeasured→unmeasured; 1>3:unmeasured→unmeasured; 2>1:unmeasured→unmeasured; 2>3:0.001→0.001; 3>1:unmeasured→unmeasured; 3>2:0.002→0.002 | 1>2:-/-; 1>3:-/-; 2>1:-/-; 2>3:host/host; 3>1:-/-; 3>2:host/prflx (both) | B [12343020042](https://github.com/netbirdio/proxbird-tests/actions/runs/39588288742/artifacts/12343020042)<br>P [12347186988](https://github.com/netbirdio/proxbird-tests/actions/runs/39597620276/artifacts/12347186988) |
| `routing-ha-freebsd-macos-nat-router-ha` | success / success | client-routers P2P, router-router P2P | 10.0 / 8.3 | 1>2:0.604→0.620; 1>2R:0.604→1.016; 1>3:0.606→0.604; 2>1:0.606→0.621; 2>3:0.001→1.030; 3>1:0.607→0.605; 3>2:0.002→1.031 | 1>2:srflx/srflx; 1>3:srflx/srflx; 2>1:srflx/srflx; 2>3:host/host; 3>1:srflx/srflx; 3>2:host/host → 1>2:srflx/srflx; 1>3:host/srflx; 2>1:host/srflx; 2>3:host/prflx; 3>1:srflx/srflx; 3>2:host/host | B [12343280139](https://github.com/netbirdio/proxbird-tests/actions/runs/39588288742/artifacts/12343280139)<br>P [12346573922](https://github.com/netbirdio/proxbird-tests/actions/runs/39597620276/artifacts/12346573922) |
| `routing-ha-freebsd-macos-relay-router-ha` | success / success | client-routers Relayed, router-router P2P | 8.5 / 8.4 | 1>2:unmeasured→unmeasured; 1>2R:unmeasured→unmeasured; 1>3:unmeasured→unmeasured; 2>1:unmeasured→unmeasured; 2>3:0.002→0.002; 3>1:unmeasured→unmeasured; 3>2:0.001→0.003 | 1>2:-/-; 1>3:-/-; 2>1:-/-; 2>3:host/host; 3>1:-/-; 3>2:host/host (both) | B [12341719764](https://github.com/netbirdio/proxbird-tests/actions/runs/39588288742/artifacts/12341719764)<br>P [12347800971](https://github.com/netbirdio/proxbird-tests/actions/runs/39597620276/artifacts/12347800971) |
| `routing-ha-freebsd-windows-nat-router-ha` | success / success | client-routers P2P, router-router P2P | 9.4 / 10.2 | 1>2:0.605→0.604; 1>2R:1.094→0.656; 1>3:0.604→0.604; 2>1:0.610→0.611; 2>3:1.035→0.001; 3>1:0.610→0.610; 3>2:1.036→0.002 | 1>2:srflx/srflx; 1>3:srflx/srflx; 2>1:srflx/srflx; 2>3:srflx/host; 3>1:srflx/srflx; 3>2:host/prflx → 1>2:srflx/srflx; 1>3:srflx/srflx; 2>1:host/srflx; 2>3:host/host; 3>1:host/srflx; 3>2:host/prflx | B [12341979890](https://github.com/netbirdio/proxbird-tests/actions/runs/39588288742/artifacts/12341979890)<br>P [12347895788](https://github.com/netbirdio/proxbird-tests/actions/runs/39597620276/artifacts/12347895788) |
| `routing-ha-freebsd-windows-relay-router-ha` | success / success | client-routers Relayed, router-router P2P | 9.7 / 9.2 | 1>2:unmeasured→unmeasured; 1>2R:unmeasured→unmeasured; 1>3:unmeasured→unmeasured; 2>1:unmeasured→unmeasured; 2>3:0.001→0.001; 3>1:unmeasured→unmeasured; 3>2:0.002→0.002 | 1>2:-/-; 1>3:-/-; 2>1:-/-; 2>3:host/host; 3>1:-/-; 3>2:host/prflx (both) | B [12342459433](https://github.com/netbirdio/proxbird-tests/actions/runs/39588288742/artifacts/12342459433)<br>P [12347027288](https://github.com/netbirdio/proxbird-tests/actions/runs/39597620276/artifacts/12347027288) |
| `routing-ha-linux-freebsd-nat-router-ha` | success / success | client-routers P2P, router-router P2P | 10.8 / 10.8 | 1>2:0.604→0.624; 1>2R:0.603→0.603; 1>3:0.603→0.603; 2>1:0.605→0.625; 2>3:0.002→1.007; 3>1:0.604→0.604; 3>2:0.003→1.007 | 1>2:srflx/srflx; 1>3:srflx/srflx; 2>1:srflx/srflx; 2>3:host/prflx; 3>1:srflx/srflx; 3>2:host/host → 1>2:host/srflx; 1>3:srflx/srflx; 2>1:srflx/srflx; 2>3:srflx/host; 3>1:host/srflx; 3>2:host/prflx | B [12343895149](https://github.com/netbirdio/proxbird-tests/actions/runs/39588288742/artifacts/12343895149)<br>P [12347437155](https://github.com/netbirdio/proxbird-tests/actions/runs/39597620276/artifacts/12347437155) |
| `routing-ha-linux-freebsd-relay-router-ha` | success / success | client-routers Relayed, router-router P2P | 10.4 / 10.1 | 1>2:unmeasured→unmeasured; 1>2R:unmeasured→unmeasured; 1>3:unmeasured→unmeasured; 2>1:unmeasured→unmeasured; 2>3:1.006→0.002; 3>1:unmeasured→unmeasured; 3>2:1.006→0.004 | 1>2:-/-; 1>3:-/-; 2>1:-/-; 2>3:host/host; 3>1:-/-; 3>2:host/prflx → 1>2:-/-; 1>3:-/-; 2>1:-/-; 2>3:host/host; 3>1:-/-; 3>2:host/host | B [12342749776](https://github.com/netbirdio/proxbird-tests/actions/runs/39588288742/artifacts/12342749776)<br>P [12346902470](https://github.com/netbirdio/proxbird-tests/actions/runs/39597620276/artifacts/12346902470) |
| `routing-ha-linux-linux-nat-router-ha` | success / success | client-routers P2P, router-router P2P | 11.2 / 11.5 | 1>2:0.604→0.604; 1>2R:0.604→0.604; 1>3:0.604→0.603; 2>1:0.605→0.604; 2>3:0.001→1.007; 3>1:0.605→0.604; 3>2:0.003→1.008 | 1>2:srflx/srflx; 1>3:srflx/srflx; 2>1:srflx/srflx; 2>3:host/host; 3>1:srflx/srflx; 3>2:host/prflx → 1>2:host/srflx; 1>3:host/srflx; 2>1:srflx/srflx; 2>3:host/host; 3>1:srflx/srflx; 3>2:host/prflx | B [12343965299](https://github.com/netbirdio/proxbird-tests/actions/runs/39588288742/artifacts/12343965299)<br>P [12346778165](https://github.com/netbirdio/proxbird-tests/actions/runs/39597620276/artifacts/12346778165) |
| `routing-ha-linux-linux-relay-router-ha` | success / success | client-routers Relayed, router-router P2P | 11.8 / 11.4 | 1>2:unmeasured→unmeasured; 1>2R:unmeasured→unmeasured; 1>3:unmeasured→unmeasured; 2>1:unmeasured→unmeasured; 2>3:0.001→0.002; 3>1:unmeasured→unmeasured; 3>2:0.002→0.003 | 1>2:-/-; 1>3:-/-; 2>1:-/-; 2>3:host/host; 3>1:-/-; 3>2:host/prflx → 1>2:-/-; 1>3:-/-; 2>1:-/-; 2>3:host/host; 3>1:-/-; 3>2:host/host | B [12342996420](https://github.com/netbirdio/proxbird-tests/actions/runs/39588288742/artifacts/12342996420)<br>P [12346947945](https://github.com/netbirdio/proxbird-tests/actions/runs/39597620276/artifacts/12346947945) |
| `routing-ha-linux-macos-nat-router-ha` | success / success | client-routers P2P, router-router P2P | 10.7 / 10.7 | 1>2:0.610→0.604; 1>2R:0.605→0.604; 1>3:0.603→0.603; 2>1:0.611→0.606; 2>3:0.001→1.005; 3>1:0.605→0.603; 3>2:0.003→1.005 | 1>2:srflx/srflx; 1>3:srflx/srflx; 2>1:srflx/srflx; 2>3:host/host; 3>1:srflx/srflx; 3>2:host/prflx → 1>2:srflx/srflx; 1>3:srflx/srflx; 2>1:host/srflx; 2>3:host/host; 3>1:host/srflx; 3>2:host/prflx | B [12343681042](https://github.com/netbirdio/proxbird-tests/actions/runs/39588288742/artifacts/12343681042)<br>P [12346967941](https://github.com/netbirdio/proxbird-tests/actions/runs/39597620276/artifacts/12346967941) |
| `routing-ha-linux-macos-relay-router-ha` | success / success | client-routers Relayed, router-router P2P | 11.1 / 11.0 | 1>2:unmeasured→unmeasured; 1>2R:unmeasured→unmeasured; 1>3:unmeasured→unmeasured; 2>1:unmeasured→unmeasured; 2>3:0.001→0.001; 3>1:unmeasured→unmeasured; 3>2:0.003→0.003 | 1>2:-/-; 1>3:-/-; 2>1:-/-; 2>3:host/host; 3>1:-/-; 3>2:host/prflx → 1>2:-/-; 1>3:-/-; 2>1:-/-; 2>3:host/prflx; 3>1:-/-; 3>2:host/host | B [12342977038](https://github.com/netbirdio/proxbird-tests/actions/runs/39588288742/artifacts/12342977038)<br>P [12347058559](https://github.com/netbirdio/proxbird-tests/actions/runs/39597620276/artifacts/12347058559) |
| `routing-ha-linux-windows-nat-router-ha` | success / success | client-routers P2P, router-router P2P | 12.1 / 12.1 | 1>2:0.604→0.605; 1>2R:1.014→1.007; 1>3:0.604→0.603; 2>1:0.611→0.612; 2>3:0.002→1.006; 3>1:0.609→0.610; 3>2:0.002→1.006 | 1>2:srflx/srflx; 1>3:srflx/srflx; 2>1:srflx/srflx; 2>3:host/host; 3>1:srflx/srflx; 3>2:host/prflx → 1>2:srflx/srflx; 1>3:host/srflx; 2>1:host/srflx; 2>3:host/prflx; 3>1:srflx/srflx; 3>2:host/host | B [12343451472](https://github.com/netbirdio/proxbird-tests/actions/runs/39588288742/artifacts/12343451472)<br>P [12347657345](https://github.com/netbirdio/proxbird-tests/actions/runs/39597620276/artifacts/12347657345) |
| `routing-ha-linux-windows-relay-router-ha` | success / success | client-routers Relayed, router-router P2P | 12.7 / 11.4 | 1>2:unmeasured→unmeasured; 1>2R:unmeasured→unmeasured; 1>3:unmeasured→unmeasured; 2>1:unmeasured→unmeasured; 2>3:1.005→1.005; 3>1:unmeasured→unmeasured; 3>2:1.007→1.007 | 1>2:-/-; 1>3:-/-; 2>1:-/-; 2>3:host/host; 3>1:-/-; 3>2:host/prflx (both) | B [12344065894](https://github.com/netbirdio/proxbird-tests/actions/runs/39588288742/artifacts/12344065894)<br>P [12347697352](https://github.com/netbirdio/proxbird-tests/actions/runs/39597620276/artifacts/12347697352) |
| `routing-overlap-freebsd-freebsd-nat-overlap` | success / success | client-routers P2P, router-router P2P | 14.1 / 13.7 | 1>2:0.616→0.625; 1>3:0.614→0.623; 2>1:0.616→0.625; 2>3:0.002→0.001; 3>1:0.615→0.623; 3>2:0.003→0.002 | 1>2:srflx/srflx; 1>3:srflx/srflx; 2>1:srflx/srflx; 2>3:host/prflx; 3>1:srflx/srflx; 3>2:host/host → 1>2:srflx/srflx; 1>3:host/srflx; 2>1:host/srflx; 2>3:host/host; 3>1:srflx/srflx; 3>2:host/host | B [12343191665](https://github.com/netbirdio/proxbird-tests/actions/runs/39588288742/artifacts/12343191665)<br>P [12347902988](https://github.com/netbirdio/proxbird-tests/actions/runs/39597620276/artifacts/12347902988) |
| `routing-overlap-freebsd-freebsd-relay-overlap` | success / success | client-routers Relayed, router-router P2P | 12.0 / 15.8 | 1>2:unmeasured→unmeasured; 1>3:unmeasured→unmeasured; 2>1:unmeasured→unmeasured; 2>3:1.013→0.002; 3>1:unmeasured→unmeasured; 3>2:1.014→0.002 | 1>2:-/-; 1>3:-/-; 2>1:-/-; 2>3:host/host; 3>1:-/-; 3>2:host/prflx (both) | B [12343371900](https://github.com/netbirdio/proxbird-tests/actions/runs/39588288742/artifacts/12343371900)<br>P [12347632596](https://github.com/netbirdio/proxbird-tests/actions/runs/39597620276/artifacts/12347632596) |
| `routing-overlap-freebsd-linux-nat-overlap` | success / success | client-routers P2P, router-router P2P | 9.3 / 9.2 | 1>2:0.603→0.626; 1>3:0.605→0.633; 2>1:0.604→0.627; 2>3:0.001→1.013; 3>1:0.606→0.633; 3>2:0.002→1.014 | 1>2:srflx/srflx; 1>3:srflx/srflx; 2>1:srflx/srflx; 2>3:host/host; 3>1:srflx/srflx; 3>2:host/host → 1>2:srflx/srflx; 1>3:srflx/srflx; 2>1:host/srflx; 2>3:host/host; 3>1:host/srflx; 3>2:host/prflx | B [12343267256](https://github.com/netbirdio/proxbird-tests/actions/runs/39588288742/artifacts/12343267256)<br>P [12347872506](https://github.com/netbirdio/proxbird-tests/actions/runs/39597620276/artifacts/12347872506) |
| `routing-overlap-freebsd-linux-relay-overlap` | success / success | client-routers Relayed, router-router P2P | 25.4 / 25.3 | 1>2:unmeasured→unmeasured; 1>3:unmeasured→unmeasured; 2>1:unmeasured→unmeasured; 2>3:0.002→0.001; 3>1:unmeasured→unmeasured; 3>2:0.002→0.002 | 1>2:-/-; 1>3:-/-; 2>1:-/-; 2>3:host/host; 3>1:-/-; 3>2:host/host (both) | B [12344161343](https://github.com/netbirdio/proxbird-tests/actions/runs/39588288742/artifacts/12344161343)<br>P [12347498364](https://github.com/netbirdio/proxbird-tests/actions/runs/39597620276/artifacts/12347498364) |
| `routing-overlap-freebsd-macos-nat-overlap` | success / success | client-routers P2P, router-router P2P | 8.4 / 8.6 | 1>2:0.605→0.604; 1>3:0.605→0.605; 2>1:0.607→0.605; 2>3:1.006→0.002; 3>1:0.606→0.606; 3>2:1.006→0.003 | 1>2:srflx/srflx; 1>3:srflx/srflx; 2>1:srflx/srflx; 2>3:host/host; 3>1:srflx/srflx; 3>2:host/prflx → 1>2:host/srflx; 1>3:host/srflx; 2>1:srflx/srflx; 2>3:host/host; 3>1:srflx/srflx; 3>2:host/host | B [12343816858](https://github.com/netbirdio/proxbird-tests/actions/runs/39588288742/artifacts/12343816858)<br>P [12347738034](https://github.com/netbirdio/proxbird-tests/actions/runs/39597620276/artifacts/12347738034) |
| `routing-overlap-freebsd-macos-relay-overlap` | success / success | client-routers Relayed, router-router P2P | 8.8 / 8.5 | 1>2:unmeasured→unmeasured; 1>3:unmeasured→unmeasured; 2>1:unmeasured→unmeasured; 2>3:0.002→0.002; 3>1:unmeasured→unmeasured; 3>2:0.002→0.001 | 1>2:-/-; 1>3:-/-; 2>1:-/-; 2>3:host/host; 3>1:-/-; 3>2:host/host (both) | B [12343017710](https://github.com/netbirdio/proxbird-tests/actions/runs/39588288742/artifacts/12343017710)<br>P [12348402116](https://github.com/netbirdio/proxbird-tests/actions/runs/39597620276/artifacts/12348402116) |
| `routing-overlap-freebsd-windows-nat-overlap` | success / success | client-routers P2P, router-router P2P | 10.1 / 13.2 | 1>2:0.604→0.604; 1>3:0.606→0.603; 2>1:0.608→0.610; 2>3:0.002→1.024; 3>1:0.612→0.609; 3>2:0.002→1.025 | 1>2:srflx/srflx; 1>3:srflx/srflx; 2>1:srflx/srflx; 2>3:host/host; 3>1:srflx/srflx; 3>2:host/host → 1>2:srflx/srflx; 1>3:srflx/srflx; 2>1:host/srflx; 2>3:host/host; 3>1:host/srflx; 3>2:host/prflx | B [12343032979](https://github.com/netbirdio/proxbird-tests/actions/runs/39588288742/artifacts/12343032979)<br>P [12347504078](https://github.com/netbirdio/proxbird-tests/actions/runs/39597620276/artifacts/12347504078) |
| `routing-overlap-freebsd-windows-relay-overlap` | success / success | client-routers Relayed, router-router P2P | 9.4 / 9.3 | 1>2:unmeasured→unmeasured; 1>3:unmeasured→unmeasured; 2>1:unmeasured→unmeasured; 2>3:0.001→0.001; 3>1:unmeasured→unmeasured; 3>2:0.002→0.002 | 1>2:-/-; 1>3:-/-; 2>1:-/-; 2>3:host/host; 3>1:-/-; 3>2:host/host → 1>2:-/-; 1>3:-/-; 2>1:-/-; 2>3:host/host; 3>1:-/-; 3>2:host/prflx | B [12343043067](https://github.com/netbirdio/proxbird-tests/actions/runs/39588288742/artifacts/12343043067)<br>P [12347783703](https://github.com/netbirdio/proxbird-tests/actions/runs/39597620276/artifacts/12347783703) |
| `routing-overlap-linux-freebsd-nat-overlap` | success / success | client-routers P2P, router-router P2P | 10.5 / 10.3 | 1>2:0.604→0.602; 1>3:0.603→0.602; 2>1:0.606→0.604; 2>3:1.005→0.001; 3>1:0.604→0.604; 3>2:1.006→0.002 | 1>2:srflx/srflx; 1>3:srflx/srflx; 2>1:srflx/srflx; 2>3:host/host; 3>1:srflx/srflx; 3>2:host/prflx → 1>2:srflx/srflx; 1>3:srflx/srflx; 2>1:host/srflx; 2>3:host/host; 3>1:host/srflx; 3>2:host/prflx | B [12343827402](https://github.com/netbirdio/proxbird-tests/actions/runs/39588288742/artifacts/12343827402)<br>P [12348039055](https://github.com/netbirdio/proxbird-tests/actions/runs/39597620276/artifacts/12348039055) |
| `routing-overlap-linux-freebsd-relay-overlap` | success / success | client-routers Relayed, router-router P2P | 10.5 / 10.3 | 1>2:unmeasured→unmeasured; 1>3:unmeasured→unmeasured; 2>1:unmeasured→unmeasured; 2>3:1.005→1.007; 3>1:unmeasured→unmeasured; 3>2:1.006→1.008 | 1>2:-/-; 1>3:-/-; 2>1:-/-; 2>3:host/host; 3>1:-/-; 3>2:host/prflx (both) | B [12342939237](https://github.com/netbirdio/proxbird-tests/actions/runs/39588288742/artifacts/12342939237)<br>P [12348327878](https://github.com/netbirdio/proxbird-tests/actions/runs/39597620276/artifacts/12348327878) |
| `routing-overlap-linux-linux-nat-overlap` | success / success | client-routers P2P, router-router P2P | 11.4 / 11.7 | 1>2:0.605→0.603; 1>3:0.604→0.603; 2>1:0.605→0.605; 2>3:0.002→0.001; 3>1:0.605→0.605; 3>2:0.003→0.002 | 1>2:srflx/srflx; 1>3:srflx/srflx; 2>1:srflx/srflx; 2>3:host/prflx; 3>1:srflx/srflx; 3>2:host/host → 1>2:srflx/srflx; 1>3:srflx/srflx; 2>1:host/srflx; 2>3:host/host; 3>1:host/srflx; 3>2:host/host | B [12343907815](https://github.com/netbirdio/proxbird-tests/actions/runs/39588288742/artifacts/12343907815)<br>P [12348183660](https://github.com/netbirdio/proxbird-tests/actions/runs/39597620276/artifacts/12348183660) |
| `routing-overlap-linux-linux-relay-overlap` | success / success | client-routers Relayed, router-router P2P | 11.7 / 12.1 | 1>2:unmeasured→unmeasured; 1>3:unmeasured→unmeasured; 2>1:unmeasured→unmeasured; 2>3:1.005→0.001; 3>1:unmeasured→unmeasured; 3>2:1.006→0.002 | 1>2:-/-; 1>3:-/-; 2>1:-/-; 2>3:host/host; 3>1:-/-; 3>2:host/prflx (both) | B [12343882660](https://github.com/netbirdio/proxbird-tests/actions/runs/39588288742/artifacts/12343882660)<br>P [12347969793](https://github.com/netbirdio/proxbird-tests/actions/runs/39597620276/artifacts/12347969793) |
| `routing-overlap-linux-macos-nat-overlap` | success / success | client-routers P2P, router-router P2P | 10.8 / 10.8 | 1>2:0.605→0.605; 1>3:0.604→0.604; 2>1:0.606→0.605; 2>3:0.002→1.005; 3>1:0.605→0.605; 3>2:0.003→1.007 | 1>2:srflx/srflx; 1>3:srflx/srflx; 2>1:srflx/srflx; 2>3:host/host; 3>1:srflx/srflx; 3>2:host/host → 1>2:srflx/srflx; 1>3:srflx/srflx; 2>1:host/srflx; 2>3:host/host; 3>1:host/srflx; 3>2:host/prflx | B [12343863067](https://github.com/netbirdio/proxbird-tests/actions/runs/39588288742/artifacts/12343863067)<br>P [12348233740](https://github.com/netbirdio/proxbird-tests/actions/runs/39597620276/artifacts/12348233740) |
| `routing-overlap-linux-macos-relay-overlap` | success / success | client-routers Relayed, router-router P2P | 11.1 / 14.5 | 1>2:unmeasured→unmeasured; 1>3:unmeasured→unmeasured; 2>1:unmeasured→unmeasured; 2>3:0.002→1.005; 3>1:unmeasured→unmeasured; 3>2:0.004→1.007 | 1>2:-/-; 1>3:-/-; 2>1:-/-; 2>3:host/prflx; 3>1:-/-; 3>2:host/host → 1>2:-/-; 1>3:-/-; 2>1:-/-; 2>3:host/host; 3>1:-/-; 3>2:host/prflx | B [12344073381](https://github.com/netbirdio/proxbird-tests/actions/runs/39588288742/artifacts/12344073381)<br>P [12348194318](https://github.com/netbirdio/proxbird-tests/actions/runs/39597620276/artifacts/12348194318) |
| `routing-overlap-linux-windows-nat-overlap` | success / success | client-routers P2P, router-router P2P | 11.3 / 11.7 | 1>2:0.605→0.604; 1>3:0.606→0.604; 2>1:0.612→0.620; 2>3:0.001→0.001; 3>1:0.612→0.610; 3>2:0.003→0.002 | 1>2:srflx/srflx; 1>3:srflx/srflx; 2>1:srflx/srflx; 2>3:host/prflx; 3>1:srflx/srflx; 3>2:host/host → 1>2:srflx/srflx; 1>3:srflx/srflx; 2>1:host/srflx; 2>3:host/host; 3>1:host/srflx; 3>2:host/prflx | B [12344238383](https://github.com/netbirdio/proxbird-tests/actions/runs/39588288742/artifacts/12344238383)<br>P [12349231137](https://github.com/netbirdio/proxbird-tests/actions/runs/39597620276/artifacts/12349231137) |
| `routing-overlap-linux-windows-relay-overlap` | success / success | client-routers Relayed, router-router P2P | 11.4 / 11.4 | 1>2:unmeasured→unmeasured; 1>3:unmeasured→unmeasured; 2>1:unmeasured→unmeasured; 2>3:1.004→0.002; 3>1:unmeasured→unmeasured; 3>2:1.004→0.003 | 1>2:-/-; 1>3:-/-; 2>1:-/-; 2>3:host/host; 3>1:-/-; 3>2:host/prflx → 1>2:-/-; 1>3:-/-; 2>1:-/-; 2>3:host/host; 3>1:-/-; 3>2:host/host | B [12344213368](https://github.com/netbirdio/proxbird-tests/actions/runs/39588288742/artifacts/12344213368)<br>P [12349781408](https://github.com/netbirdio/proxbird-tests/actions/runs/39597620276/artifacts/12349781408) |
| `windows-macos-direct` | success / success | P2P | 8.0 / 8.3 | 1>2:1.005→1.004; 2>1:1.012→1.010 | 1>2:host/host; 2>1:host/prflx → 1>2:host/srflx; 2>1:host/prflx | B [12344470088](https://github.com/netbirdio/proxbird-tests/actions/runs/39588288742/artifacts/12344470088)<br>P [12347579605](https://github.com/netbirdio/proxbird-tests/actions/runs/39597620276/artifacts/12347579605) |
| `windows-macos-nat` | success / success | P2P | 7.3 / 7.0 | 1>2:0.604→0.603; 2>1:0.611→0.608 | 1>2:srflx/srflx; 2>1:srflx/srflx → 1>2:host/srflx; 2>1:srflx/srflx | B [12344267668](https://github.com/netbirdio/proxbird-tests/actions/runs/39588288742/artifacts/12344267668)<br>P [12347804255](https://github.com/netbirdio/proxbird-tests/actions/runs/39597620276/artifacts/12347804255) |
| `windows-macos-relay` | success / success | Relayed | 7.1 / 18.0 | 1>2:unmeasured→unmeasured; 2>1:unmeasured→unmeasured | 1>2:-/-; 2>1:-/- (both) | B [12343304366](https://github.com/netbirdio/proxbird-tests/actions/runs/39588288742/artifacts/12343304366)<br>P [12348154491](https://github.com/netbirdio/proxbird-tests/actions/runs/39597620276/artifacts/12348154491) |
| `windows-macos-slow` | success / success | P2P | 8.7 / 9.2 | 1>2:0.703→0.703; 2>1:0.709→0.909 | 1>2:srflx/srflx; 2>1:srflx/srflx → 1>2:srflx/srflx; 2>1:host/srflx | B [12343384214](https://github.com/netbirdio/proxbird-tests/actions/runs/39588288742/artifacts/12343384214)<br>P [12348601755](https://github.com/netbirdio/proxbird-tests/actions/runs/39597620276/artifacts/12348601755) |
| `windows-windows-direct` | success / success | P2P | 8.7 / 9.2 | 1>2:0.003→0.404; 2>1:0.003→0.403 | 1>2:host/host; 2>1:host/host (both) | B [12343094771](https://github.com/netbirdio/proxbird-tests/actions/runs/39588288742/artifacts/12343094771)<br>P [12348129502](https://github.com/netbirdio/proxbird-tests/actions/runs/39597620276/artifacts/12348129502) |
| `windows-windows-nat` | success / success | P2P | 9.5 / 8.9 | 1>2:0.607→0.605; 2>1:0.678→0.605 | 1>2:srflx/srflx; 2>1:srflx/srflx → 1>2:host/srflx; 2>1:srflx/srflx | B [12343848656](https://github.com/netbirdio/proxbird-tests/actions/runs/39588288742/artifacts/12343848656)<br>P [12349031398](https://github.com/netbirdio/proxbird-tests/actions/runs/39597620276/artifacts/12349031398) |
| `windows-windows-relay` | success / success | Relayed | 9.0 / 8.8 | 1>2:unmeasured→unmeasured; 2>1:unmeasured→unmeasured | 1>2:-/-; 2>1:-/- (both) | B [12344585735](https://github.com/netbirdio/proxbird-tests/actions/runs/39588288742/artifacts/12344585735)<br>P [12348661846](https://github.com/netbirdio/proxbird-tests/actions/runs/39597620276/artifacts/12348661846) |
| `windows-windows-slow` | success / success | P2P | 10.7 / 11.1 | 1>2:0.704→0.907; 2>1:0.906→0.908 | 1>2:srflx/srflx; 2>1:srflx/srflx → 1>2:host/srflx; 2>1:srflx/srflx | B [12344133648](https://github.com/netbirdio/proxbird-tests/actions/runs/39588288742/artifacts/12344133648)<br>P [12349041737](https://github.com/netbirdio/proxbird-tests/actions/runs/39597620276/artifacts/12349041737) |

## E2E repetitions of `client-tests`

Dispatched 2026-10-21 13:28 UTC in balanced order, same inputs, selection
`client-tests` (20 cases: five behaviors on four OSes against the 0.28.9 and
0.30.1 reference peers):

| Run | Commit | Run ID | Result |
| --- | --- | --- | --- |
| B1 | baseline `1e63b68` | [39588288742](https://github.com/netbirdio/proxbird-tests/actions/runs/39588288742) (full selection) | `client-tests` 20/20 |
| B2 | baseline `1e63b68` | [39608330203](https://github.com/netbirdio/proxbird-tests/actions/runs/39608330203) | 20/20 |
| B3 | baseline `1e63b68` | [39608353253](https://github.com/netbirdio/proxbird-tests/actions/runs/39608353253) | 20/20 |
| P1 | POC `37dab7d` | [39597620276](https://github.com/netbirdio/proxbird-tests/actions/runs/39597620276) (full selection) | `client-tests` 20/20 |
| P2 | POC `37dab7d` | [39608305272](https://github.com/netbirdio/proxbird-tests/actions/runs/39608305272) | 20/20 |
| P3 | POC `37dab7d` | [39608375543](https://github.com/netbirdio/proxbird-tests/actions/runs/39608375543) | 20/20 |

Setup convergence (s) per case and run; the medians are over three runs per
commit:

| Case | B1 | B2 | B3 | median B | P1 | P2 | P3 | median P | P − B |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `client-freebsd-nat-allowed-ports` | 3.2 | 6.2 | 3.5 | 3.5 | 1.3 | 3.7 | 3.3 | 3.3 | -0.2 |
| `client-freebsd-nat-connect-legacy` | 0.7 | 5.9 | 5.2 | 5.2 | 3.2 | 8.1 | 5.8 | 5.8 | +0.6 |
| `client-freebsd-nat-connect-relay` | 3.2 | 3.3 | 3.2 | 3.2 | 3.3 | 3.2 | 3.4 | 3.3 | +0.1 |
| `client-freebsd-nat-dns` | 3.2 | 3.2 | 3.0 | 3.2 | 3.4 | 3.1 | 3.9 | 3.4 | +0.2 |
| `client-freebsd-nat-exit-node` | 3.0 | 3.7 | 4.1 | 3.7 | 3.4 | 3.2 | 3.3 | 3.3 | -0.4 |
| `client-linux-nat-allowed-ports` | 3.6 | 3.4 | 4.2 | 3.6 | 4.1 | 4.2 | 4.3 | 4.2 | +0.6 |
| `client-linux-nat-connect-legacy` | 3.4 | 7.1 | 4.9 | 4.9 | 6.3 | 3.4 | 6.9 | 6.3 | +1.4 |
| `client-linux-nat-connect-relay` | 3.7 | 6.2 | 3.9 | 3.9 | 30.7 | 3.4 | 4.3 | 4.3 | +0.4 |
| `client-linux-nat-dns` | 3.4 | 3.4 | 3.6 | 3.4 | 3.4 | 3.4 | 3.4 | 3.4 | -0.0 |
| `client-linux-nat-exit-node` | 3.6 | 4.4 | 4.4 | 4.4 | 3.5 | 3.4 | 3.4 | 3.4 | -1.0 |
| `client-macos-nat-allowed-ports` | 4.7 | 25.9 | 3.4 | 4.7 | 3.5 | 3.2 | 3.4 | 3.4 | -1.3 |
| `client-macos-nat-connect-legacy` | 4.1 | 6.4 | 6.1 | 6.1 | 6.4 | 6.9 | 3.9 | 6.4 | +0.3 |
| `client-macos-nat-connect-relay` | 3.4 | 3.7 | 3.4 | 3.4 | 3.3 | 3.4 | 3.5 | 3.4 | -0.0 |
| `client-macos-nat-dns` | 3.2 | 3.4 | 3.5 | 3.4 | 3.4 | 5.4 | 3.5 | 3.5 | +0.1 |
| `client-macos-nat-exit-node` | 3.4 | 3.5 | 25.1 | 3.5 | 3.4 | 3.4 | 3.4 | 3.4 | -0.1 |
| `client-windows-nat-allowed-ports` | 24.4 | 3.4 | 16.1 | 16.1 | 3.2 | 16.3 | 24.2 | 16.3 | +0.2 |
| `client-windows-nat-connect-legacy` | 14.1 | 16.5 | 16.2 | 16.2 | 12.6 | 32.1 | 34.7 | 32.1 | +15.8 |
| `client-windows-nat-connect-relay` | 3.2 | 3.2 | 24.1 | 3.2 | 3.9 | 3.3 | 19.0 | 3.9 | +0.7 |
| `client-windows-nat-dns` | 22.4 | 23.9 | 3.2 | 22.4 | 32.1 | 32.0 | 3.3 | 32.0 | +9.6 |
| `client-windows-nat-exit-node` | 3.4 | 3.3 | 3.2 | 3.3 | 3.4 | 24.0 | 21.5 | 21.5 | +18.1 |

Over all 20 cases: 60 of 60 scenario executions passed per commit; median of
per-case medians 3.66 s on baseline and 3.71 s on the POC; median paired
difference +0.20 s (POC slower in 13 cases, faster in 7); median of all
samples 3.61 s and 3.48 s.

By OS (all samples):

| OS | samples B / P | median B / P (s) | above 10 s B / P | above 28 s B / P |
| --- | --- | --- | --- | --- |
| freebsd | 15 / 15 | 3.2 / 3.3 | 0 / 0 | 0 / 0 |
| linux | 15 / 15 | 3.7 / 3.5 | 0 / 1 | 0 / 1 |
| macos | 15 / 15 | 3.5 / 3.4 | 2 / 0 | 0 / 0 |
| windows | 15 / 15 | 14.1 / 19.0 | 8 / 10 | 0 / 4 |

FreeBSD, Linux and macOS are unchanged; their few slow samples (macOS
25.9 s and 25.1 s on baseline, Linux 30.7 s on the POC, the latter traced
by the parallel run to candidates arriving before the 0.30.1 agent existed)
occur on both sides. Windows is slow on both commits, but the third ICE
attempts (above 28 s) occur only on the POC; see "Hard stop".

## Netstack e2e

The repo's own `e2e/` suites run Docker containers against a combined server
built from source. `e2e/agentnetwork`'s nblink tests run two embedded clients
in netstack mode (nblink and the proxy; their logs show `create nbnetstack tun
interface` and `netstack mode, using userspace firewall`), so they exercise
the mux in the third mode.

Run from a scratch worktree at the head (`5804612`, code identical to
`c058965`) with two scratch-only deviations, neither committed:

- `e2e/harness/client.go` and `proxy.go` request `CAP_SYS_RESOURCE`, which
  this sandbox's Docker refuses (`invalid CapAdd: capability not supported
  by your kernel`); the capability was dropped. The first run failed on
  exactly that, before any client started.
- The harness's client image installs packages from the Alpine mirror,
  which the network policy blocks. An equivalent image on `ubuntu:24.04`
  (same builder stage and binary, `bash ca-certificates iproute2 iptables`
  from the Ubuntu archive over HTTPS through the agent proxy) was supplied
  through the harness's own `NB_E2E_CLIENT_IMAGE` override.

`TestNBLinkReachesAgentNetwork` passes (15 subtests), in both runs that got
past the capability error. Both embedded clients select an ICE pair and the
proxy reports the connection metric `ice_p2p`: netstack to netstack over ICE
through the mux, on the container network (no NAT in this harness). In the
rerun, nblink logged `selected candidate pair [udp4 host 172.19.0.5:51820 <->
udp4 prflx 172.19.0.4:40009]` and the proxy `[udp4 host 172.19.0.4:40009 <->
udp4 srflx 172.19.0.5:51820]`, then host/host after nblink's restart case.

The whole repo e2e tree (`go test -tags e2e ./e2e/...`) ran twice on the head,
with the same result at the top level: 22 passed, 24 failed, 7 skipped.

| Outcome | Tests | Classification |
| --- | --- | --- |
| passed in both runs | `TestNBLinkReachesAgentNetwork`, `TestNBLinkWithoutManagement`, `TestNBLinkCheck`, `e2e/reverseproxy` (2), `e2e/harness` (8), and 9 management/settings tests that need no client container | |
| skipped | 7 live-provider tests (`TestProvidersMatrix`, `TestLive*`, two allowlist tests) | need LLM provider keys (`~/.llm-keys`) |
| failed, run 1 | 23 `agentnetwork` tests and `TestRemoteJobsOptInAndBundleParams`: `build image netbird-client:e2e` (`apk add` cannot reach `dl-cdn.alpinelinux.org`, blocked by the network policy) | infrastructure |
| failed, run 2 (substitute image) | the same 24: `timed out waiting for "Management: Connected"` before any peer connection | infrastructure: baseline `1e63b68` fails identically with the same substitute image built from its own tree (`TestAccountDelete_RemovesAgentNetworkState`, checked once) |
| failed, both runs | `TestProviderLifecycle`: `the upstream url could not be reached: no such host` | infrastructure (provider creation resolves a public upstream) |

The management connection is gRPC over TCP and never reaches the UDP mux, so
none of the failures can come from this change, and baseline reproduces
them. The suites that exercise the mux and could run here pass.

## Real clients: kernel, userspace and netstack

### Builds under test

- `git diff 1e63b68 37dab7d` touches only `client/iface/udpmux` and this log,
  and `1e63b68` is an ancestor of `37dab7d`. The tree under `client/` at
  `37dab7d` is the one at the branch head.
- Every proxbird run cited in this log was dispatched with
  `client_source=netbird-main` and `lab_source=source-build`, so clients and
  server are compiled from `netbird_sha` and no published binary is used. Each
  run's `resolve-client` log was read for its `PINNED_SHA`.
- The local lab images were checked by rebuilding: `git archive` of each
  commit, built with the same Dockerfile (`CGO_ENABLED=0 go build ./client`),
  gives binaries byte-identical to the ones in the lab images (sha256
  `3fb73fe6…` for `37dab7d`, `abd958bc…` for `1e63b68`). The 0.30.1 peer is
  built from tag `v0.30.1` (`b237917`).

### Kernel and userspace in proxbird (`connectivity-lazy`)

This sandbox's kernel has no WireGuard module (`ip link add wg0 type
wireguard` in a container with `NET_ADMIN` fails with "Unknown device type"),
so kernel mode cannot run locally. Besides the Linux cases of the 85-case
selection, which run kernel mode, the lazy suite asserts the interface mode:
`lazy-cold` requires both peers on the kernel interface and `lazy-idle` on
userspace (`checkLazyPeerState`, `internal/lab/client_connection.go:96-101`
in proxbird-tests; the fixture sets `NB_WG_KERNEL_DISABLED` for idle). Both
peers are the candidate build. Each case activates a lazy connection, and the
idle case lets it go idle and wakes it again.

| Run | Commit | nat-lazy-cold | nat-lazy-idle | relay-lazy-cold | relay-lazy-idle |
| --- | --- | --- | --- | --- | --- |
| 39636145465 | `1e63b68` | pass | pass | pass | pass |
| 39636166317 | `37dab7d` | pass | pass | pass | pass |
| 39636186423 | `1e63b68` | pass | pass | pass | pass |
| 39636206718 | `37dab7d` | pass | pass | pass | pass |

### Local NAT lab (userspace, netstack)

Scratch only, not committed. Two client containers, each on its own Docker
`internal` LAN behind a router container with `MASQUERADE` on its WAN side,
`FORWARD` to other private ranges dropped, and new inbound connections to the
router dropped, so a peer is reachable only through the mapping its own
traffic created. The server is the repo e2e harness's combined image
(`netbird-combined:e2e`) on the WAN network, the same for both arms. Peers run
with `NB_WG_KERNEL_DISABLED=true` (userspace; netstack rows add
`NB_USE_NETSTACK_MODE=true`), `NB_LAZY_CONN=off` and `NB_RELAY_TRANSPORT=ws`.
Each trial gets new routers, new peer addresses and a clean peer list. Time
to P2P runs from the later `netbird up` return until both peers' `netbird
status -d` report `P2P`, polled every 0.5 s, 90 s deadline (60 s traced).
Baseline and POC trials are interleaved; trials 46 to 105 of `same`
alternate which goes first.

Four lab defects made both builds fail equally and were fixed before any
counted trial: Docker's raw-table anti-spoofing dropped LAN frames
addressed to WAN containers; idle lazy connections; unsolicited inbound
claiming the conntrack tuple a peer's mapping needed (port remap); and
Docker's own masquerade on bridged LAN frames plus stale host conntrack,
which added a hidden third NAT. Smoke and diagnosis trials from that phase
are excluded.

| Scenario | Peer A | Peer B | Trials | Both P2P | Time to P2P, median / max (s) | Trials with a failed attempt |
| --- | --- | --- | --- | --- | --- | --- |
| `same` | build | build | 105 / 105 | 105 / 105 | 1.33 / 46.7, 1.33 / 45.9 | 17 / 23 |
| `mix` | baseline, POC | POC, baseline | 5 + 5 | 10 | 1.37 / 46.4, 0.85 / 20.9 | 2, 1 |
| `netstack` | build | build | 8 / 8 | 8 / 8 | 1.14 / 1.41, 1.36 / 20.2 | 0 / 1 |
| `v0301` | build | 0.30.1 | 15 / 15 | 15 / 15 | 1.40 / 30.4, 1.15 / 21.2 | 2 / 1 |
| `multi-v0301` | build, four IPv4 addresses | 0.30.1 | 60 / 60 | 60 / 60 | 1.37 / 22.1, 1.37 / 22.4 | 4 / 4 |
| `trace-multi` | same, `PION_LOG_TRACE=ice` | 0.30.1 | 40 / 40 | 40 / 40 | 1.35 / 30.1, 1.36 / 23.0 | 3 / 4 |

Pairs are baseline / POC. `same` 17 / 23: Fisher p = 0.38 two-sided.

What the failed attempts are:

- **`same`, `mix`, `netstack`:** every failure event, 19 of 19 on baseline
  and 27 of 27 on the POC, follows a remote candidate that was dropped
  because it arrived before the ICE agent existed ("ICE Agent is not
  initialized yet", `worker_ice.go:186`). That is a signaling-order race in
  NetBird, outside the mux. Both peers stamp the pair ID here, so the hard
  stop's exposure does not apply.
- **`trace-multi`, A controlled:** the POC lost one nomination in 22 trials
  (1 of 23 nominations). The shape is the one in "Mechanism": host
  `10.10.1.33` read the only USE-CANDIDATE request, the response to its
  triggered check reached sibling `10.10.1.31` 1 ms later, and the attempt
  failed 11 s after; the next one connected. Baseline lost none of 24: there
  the broadcast copy reaches the srflx conn too. Baseline's two failed
  controlled trials had no nomination reaching A at all.
- **The rest** (`v0301`, `multi-v0301`, `trace-multi` with A controlling,
  baseline's no-nomination trials): the 0.30.1 peer's logs came out empty,
  so the cause is not known. They occur at similar rates on both builds.

A first count put baseline at 2 lost nominations; both were the second
broadcast copy of a nomination arriving after the first copy had already
selected the pair, in trials that connected on the first attempt. The
counter now ignores copies read after selection.

Candidate types match "What the change does to candidate selection" with real
clients. In `same`, the controlling side reports a host local candidate in 57
of 57 POC trials and 1 of 50 baseline trials; the controlled side reports
srflx in 47 of 48 and 54 of 55.

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
  POC e2e dispatched (run 39597620276); it built `37dab7d`.
- 13:24 UTC: POC e2e completed, 85/85 passed.
- 13:28 UTC: `client-tests` repetitions dispatched (P2, B2, B3, P3).
- 13:30 UTC: second `-s ours` merge (`27531b6`), log pushed (`5804612`).
- 13:50 to 14:30 UTC: cross-version tests rerun with the both-ways strip and
  with the real v0.30.1 agent; artifact audit joined into the per-case table.
- 13:54, 14:18, 14:41 UTC: repetitions P2, B2, B3 completed, 20/20 each;
  P3 completed 15:08 UTC, 20/20. Each run's `resolve-client` log was checked for
  its commit.
- 14:05 to 14:20 UTC: netstack e2e; the first run stopped on
  `CAP_SYS_RESOURCE` before any client started, the rerun without it passed.
- 14:20 to 14:45 UTC: the two-run repetition table shows POC-only ~32 s
  Windows samples; scratch timing trials against the real v0.30.1 agent.
- 14:45 to 15:05 UTC: the two-address host reproduces lost nominations (7 of
  240 attempts on the POC, 0 of 240 on baseline, 0 of 200 with one host
  candidate); a pion trace confirms the mechanism. Hard stop; no further code.
- 14:25 to 15:45 UTC: full repo `e2e/` run, then a rerun with the substitute
  client image.
- 15:00 to 15:50 UTC: `make test-unit` and the race suite rerun on the head and
  on baseline; e2e failures classified against baseline; log rewritten with
  the audit fixes, repetitions and hard stop. The push met nine new
  parallel commits; `-s ours` merge `7643575` (decision 21), then pushed.
- 14:40 to 16:10 UTC: local NAT lab built (client images, routers, 0.30.1
  image); lab defects fixed in smoke trials.
- 15:40 UTC: moved to `work/admiring-planck-1l2xh2` (decision 22).
- 16:35 UTC: `connectivity-lazy` dispatched twice per commit (runs
  39636145465, 39636166317, 39636186423, 39636206718), queued on the lab's
  slot limit; all four passed 4/4, the last at 17:44 UTC.
- 16:35 to 17:49 UTC: 466 lab trials (`same`, `mix`, `v0301`, `netstack`,
  `multi-v0301`, then extra `same` and traced `trace-multi`).
- 18:00 UTC: lab binaries rebuilt from both commits, byte-identical; baseline's
  two counted lost nominations found to be post-selection copies, counter
  fixed; "Real clients" written.

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

## Not covered / caveats

- **Candidate types and ICE timings** come from the parallel run's artifact
  audit, not from this run's own download (decision 11). Each e2e case ran
  once per commit for those; the repetitions add pass/fail and setup
  convergence only.
- **Current release peers**: no proxbird case pairs the candidate build with a
  current release; covered only by the scratch cross-version test against the
  baseline mux.
- **STUN-level behavior in e2e** (one answer per request, response
  ownership): not observable from the artifacts; proven at unit level and
  against the real v0.30.1 agent.
- **Mobile (iOS, Android)**: not exercised; Android builds.
- **Pre-existing, unchanged**: `RemoveConnByUfrag` deletes the whole
  `addressMap[addr]` entry, including other conns on that address (#4154);
  several host candidates of one family share one muxed conn; udp4 and udp6
  srflx candidates share one conn; a recreated agent reuses its predecessor's
  ufrag; `Close` leaves `addressMap` and `candidateConnMap` populated.
- **Full pair-ID removal** (variant R) was measured only at unit level; no
  e2e run of it exists.
- **RFC citations** not re-read against the published text (decision 10).
- **The Windows 127.0.0.1 host candidate** is inferred from code (Go's
  interface naming and the `"lo"` prefix filter), not observed: the artifacts
  that list gathered candidates are blocked here.
- **No fix for the hard stop** was tried, in particular not per-candidate
  conns (decision 20).
- **Kernel mode locally**: this sandbox has no kernel WireGuard, so the local
  NAT lab covers userspace and netstack only; kernel mode rests on proxbird
  (the selection's Linux cases and `lazy-cold`).
- **The local lab has one NAT type** (Linux `MASQUERADE`, no unsolicited
  inbound) and one OS; the 0.30.1 peer's logs came out empty there, so the
  failed attempts in which no nomination arrived are unexplained, on both
  builds.

## Final report

### What changed

All in `client/iface/udpmux`, plus this log. No dependency, `go.mod`, fork,
proto, config, flag or wire-format change; `GetConn`/`GetConnForURL` keep their
signatures; the fork still stamps `0x8100` and the `cid` extension;
`universal.go` is unchanged.

- `transactions.go` (new): a bounded transaction tracker. Outgoing STUN
  requests are recognised from the 20-byte header alone and recorded against
  the muxed conn that writes them, before the socket write. Records leave on
  the response, on a failed write, on conn removal and mux close; a record
  older than 5 s is never used and is dropped lazily; at most 4096
  outstanding requests are kept.
- `conn.go`: `WriteTo` records requests and forgets them when the write fails.
- `mux.go`: `findSTUNRecipient` decides delivery. Responses go to the
  recorded sender; requests and indications go to the pair ID's target conn,
  else to the USERNAME ufrag's host conn; anything else keeps the existing
  address-map broadcast. `candidateConnMap` and pair-ID routing stay
  (decision 3).
- `doc.go`: routing description updated.
- Tests: `routing_test.go` (real pion agents on vnet NAT, socket-level mux
  tests), `transactions_test.go` (tracker lifecycle and bounds).

### What was proven

- Response ownership: every response reaches only the conn that sent the
  request, with and without the pair ID, for 1, 2 overlapping and 20 agents per
  mux. Baseline fails the same tests: even with the pair ID, checks sent from
  the host conn were answered into the srflx conn.
- No duplicate answers: every request is read once, by its USERNAME's agent,
  and answered at most once. Baseline answers each request from a peer without
  the pair ID twice (the bug #4430 fixed, which remained for such peers);
  against the real v0.30.1 agent, baseline answered 258 of 258 requests twice,
  the POC 0 of 259.
- Same path outcome: 85/85 on both commits over the full selection (kernel
  Linux, userspace Windows/macOS/FreeBSD; NAT, direct, slow and relay
  profiles; recovery, path repair, underlay change, HA and overlapping routes
  with three peers), 0 of 298 initial path snapshots different, and
  `client-tests` passed 60/60 on each commit over three runs.
- Real clients behind NAT, local lab (userspace and netstack): 228 trials
  per build and 10 mixed, all P2P, same median time to P2P (1.33 s build
  against build); 17 against 23 of those 105 trials needed a second ICE
  attempt (p = 0.38), each after the pre-existing "agent not initialized"
  candidate drop. Kernel mode
  cannot run here; proxbird's `connectivity-lazy`, which asserts kernel
  (`lazy-cold`) and userspace (`lazy-idle`), passed 4/4 in each of two runs
  per commit. The lab binaries rebuild byte-identical from the two commits.
- Netstack: the repo's `e2e/agentnetwork` nblink tests pass on the head; both
  embedded clients selected ICE pairs through the mux (`ice_p2p`).
  The rest of the repo `e2e/` tree fails only on infrastructure, identically
  on baseline (see "Netstack e2e").
- Mixed versions: stamping and non-stamping peers connect at once to one
  mux; a POC mux connects to a baseline mux (v0.57+ behavior), to a
  broadcast mux without pair ID (pre-0.57 routing), and to the real v0.30.1
  agent and mux, in either ICE role (scratch tests; on a two-address host
  some attempts fail first, see the hard stop); proxbird's 20 `client-tests`
  cases against 0.28.9 and 0.30.1 reference peers pass on every run.
- Bounded state: the tracker cap counts outstanding requests, answered traffic
  cannot evict a waiting request, memory is bounded by the cap, conn removal
  and mux close drop the records they own, and a closed conn is never
  recorded. Race detector clean on `udpmux` (`-count=10`).

### Differences from baseline behavior

- **Reported local candidate type, controlling side, behind NAT: srflx becomes
  host.** Measured in unit tests and visible in the e2e artifacts (57 of 59
  type changes between source-built peers are srflx to host). The controlled
  side is unchanged for peers that stamp the pair ID and becomes host for
  peers that do not. Same socket, same 5-tuple, same WireGuard endpoint; the
  local type feeds only status display and logs. `netbird status -d` shows
  `ICE candidate (Local/Remote): host/srflx` and the interface address as the
  local endpoint where it showed `srflx/srflx` and the public mapping.
- **Against 0.28.9/0.30.1 peers the reported types move both ways** in the
  single-sample e2e snapshots (reference peer host 20/20 on baseline, 12/20
  on the POC). Scratch trials with the real v0.30.1 agent show the same random
  distribution on both commits, so this is unexplained and unproven as
  systematic.
- Requests without the pair ID reach one conn instead of being broadcast, so
  agents no longer answer them twice and no longer log "username mismatch" or
  "unknown TransactionID" for copies meant for others.
- **Lost nominations against pre-0.57 peers (the hard stop).** A controlled
  agent whose host conn is shared by two or more candidates of one family
  can lose the peer's only nomination, so that ICE attempt fails and the next
  one connects about 12 s later. Scratch trials with the real v0.30.1 agent:
  7 of 240 attempts on the POC, 0 of 240 on baseline. With real clients on
  a four-address Linux host: 1 of 22 controlled trials on the POC, 0 of 24
  on baseline. In e2e it shows as third ICE attempts on Windows against the
  reference peers: 4 of 15 Windows samples above 28 s on the POC, 0 of 15 on
  baseline. Not removable within the mandated design; see "Hard stop".

### What was not covered

See "Not covered / caveats". In short: candidate types and ICE timings only
from the parallel run's artifact audit (artifacts blocked here), one sample
per case for those; current-release peers only in scratch unit tests; mobile;
an e2e run of full pair-ID removal; the Windows loopback candidate (inferred,
not observed); kernel mode outside proxbird; any fix for the hard stop.

### Step 2: upstream pion/ice and dropping the fork

1. Fix conn granularity first. Without the fork no peer stamps the pair ID,
   so the lost-nomination race in "Hard stop" would hit every controlled
   agent with a shared host conn. Give each local candidate its own muxed
   conn (`GetConn` already receives the candidate's address and ID), route a
   USERNAME request to one of the ufrag's host conns, and let transaction
   routing reach the exact candidate; this also registers every candidate
   ID instead of the first. Agree the design in a ticket, then measure it with
   the scratch trials above and the e2e selection. Separately, drop loopback
   from the mux's unspecified-address enumeration (Windows), a pre-existing
   issue that this design exposes.
2. Decide the candidate-type semantics. Without the pair ID, inbound
   requests can only be placed by USERNAME, which names the agent, not the
   candidate; the RFC 8445 answer (section 7.3.1.4: the local candidate of a
   triggered check is the one whose transport address the request arrived on,
   the shared base) is host. Accept "host" for both sides, or change how
   status reports a host candidate whose traffic leaves through NAT.
3. Remove `candidateConnMap`/`findCandidateConnection` (variant R: every test
   passes except `TestUniversalUDPMux_PairIDRouting`, which pins the kept
   behavior and would be dropped with it; the controlled side then reports
   host) and run the same 85-case e2e selection against it before touching
   dependencies.
4. Pick the target. Upstream `pion/ice/v4` v4.4.8 and `pion/ice/v5`
   v5.0.0-rc.7 both need `pion/stun/v4`, `pion/transport/v5`, `pion/turn/v5`,
   `pion/dtls/v3` and `pion/mdns/v2`, where NetBird is on `stun/v3`,
   `transport/v3` and `turn/v3` today, so either is a dependency migration
   beyond ICE. v4.4.8 keeps `NewAgent(*AgentConfig)` next to
   `NewAgentWithOptions`; v5 has only functional options
   (`NewAgent(opts ...AgentOption)`). Both use `GetConn(ufrag, addr)` and
   `GetConnForURL(ufrag, url, addr)` without `candidateID`.
5. Replace the fork-only APIs: `ice.CandidatePairIDFromSTUN` in the mux
   (`AttrCandidatePairID` is used only by the new tests),
   `ice.ExtensionKeyCandidateID` and the `cid` handling in `worker_ice.go`
   (`shouldAddExtraCandidate` uses the extension to detect new peers; it needs
   another version signal), and the prflx ID taken from `0x8100`. Check that
   the fork's role-conflict and selector-lock backports exist in the chosen
   upstream version (they come from v4.0.11).
6. Mixed fleets: peers on v0.57+ route their responses by our pair ID; once
   we stop stamping it they fall back to their broadcast (works, but they
   misattribute and answer duplicates as pre-0.57 peers do). Ship the
   transaction-ID mux, with step 1 in place, one or more releases before
   dropping the stamp, so most peers route correctly without it. This POC
   alone is not shippable: it would bring the lost-nomination race to
   every pre-0.57 peer.
7. Optional, against pre-0.57 peers: "dup-follow" (decision 16) routes a
   peer's duplicate answer to the conn that got the first one, which made the
   POC side's selection deterministic against such peers in the v4 model.
8. Pre-existing issues to fix along the way: `RemoveConnByUfrag` deleting the
   whole `addressMap` entry (#4154), v4 and v6 srflx candidates sharing one
   muxed conn (step 1 covers it if srflx conns are split by family too), and
   the pair-ID misses for port-forwarded candidates (doubled `candidate:`
   prefix).
