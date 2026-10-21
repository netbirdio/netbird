# POC: route ICE STUN in the UDP mux without the candidate-pair ID

Branch: `poc/udpmux-txid-routing` in `netbirdio/netbird` (no PR, no ticket).
Progress log, written so the work can be resumed from it.

## Checks for the candidate-ownership revision

Executable source `49baccdab9b8e772889704037c71366efdbc6550` completes
`go fmt ./...`, `make lint`, `make lint-all`, and the exact required race command
successfully. Race package times: udpmux 11.894 s, bind 1.698 s, peer 8.696 s.
Windows amd64, Darwin arm64, Android arm64 and js/wasm package cross-builds also
pass; these are build checks, not platform runtime tests.

The complete `make test-unit` command finishes with 253 passing packages, 137
without tests and six failures (exit 2). All six are previously demonstrated
baseline/environment failure packages: `client/iface/device` (absent modules
metadata), `client/internal` (absent TUN followed by fixture panic),
`client/internal/dns` and `dns/mgmt` (public/OS DNS restrictions),
`management/cmd` (denied external discovery followed by fixture panic), and
`shared/relay/client` (the existing timeout-margin test). No new failing package
is observed. With the proven local-only proxy exclusions applied from the
start, full-suite management, signal and upload packages pass directly in
127.288 s, 0.318 s and 1.927 s. No test exclusions or thresholds change.

The checked source manifest remains unchanged throughout those commands.
Commit `24817004b0889477fee849999c6c6fad664f7415` changes only comments in
`doc.go` and this report. All 2,669 Go/module files are verified identical except
that comment-only file, whose only noncomment content in both revisions is
`package udpmux`. The original manifests and the explicit source bridge are
preserved; netstack images are built from exact `24817004`. Formatting and both
lint targets also pass on that exact successor, with zero reported issues.

Both complete `TestNBLinkReachesAgentNetwork` suites pass on exact `24817004`:
source-built POC peers in 92.591 s and the official nblink v0.81.3 peer against
the POC embedded peer in 94.212 s. Native logs confirm direct ICE active on both
sides in both runs; HTTP success alone is not used to infer the path. Existing
policy, TLS, browser, streaming and restart assertions all remain enabled.
All 2,669 Go/module files still match the build manifest after completion, and
the validation containers are removed before repeated timing begins.
Full evidence: `/workspace/scratch/validation-reader-queues/` and
`/workspace/scratch/portability-reader-queues/`. VM validation of this newer
source remains pending; the linked lifecycle-source run cannot establish it.

### Repeated timing of the candidate-ownership revision

Exact baseline `1e63b68c4dc243a32fef823df1bc024c997a9c60` and exact POC
`24817004b0889477fee849999c6c6fad664f7415` are rebuilt with identical observers,
Go 1.26.7 and GOMAXPROCS=2. There are 24 repetitions per source/configuration,
192 samples total, alternating baseline/POC order. Timing starts at a shared
Dial/Accept barrier and ends when all pairs connect; gathering and signalling
are excluded. Each side shares one mux with one host and one STUN-derived srflx
candidate per agent. Source, helper and binary hashes are verified again after
sampling. The earlier lifecycle-source measurements remain separately below.

| Pairs | Pair IDs | Baseline median ms (range) | POC median ms (range) | Median difference ms | Paired-difference median ms |
| ---: | :---: | ---: | ---: | ---: | ---: |
| 1 | present | 602.624 (602.026–623.628) | 602.337 (601.573–603.377) | -0.287 | -0.416 |
| 1 | absent | 602.746 (601.479–603.638) | 602.469 (601.976–604.570) | -0.277 | -0.249 |
| 20 | present | 605.267 (603.888–614.187) | 606.114 (603.910–610.526) | +0.847 | +0.595 |
| 20 | absent | 620.850 (615.597–631.250) | 605.985 (604.463–608.638) | -14.866 | -15.030 |

All 96 POC samples pass exact request/response ownership assertions with zero
violations. The baseline observer records 11,675 misrouted-response transactions
and 8,302 misrouted-request transactions; those are evidence of baseline routing,
not assertions silently removed from the POC. With pair IDs, every baseline
agent selects srflx/srflx; every POC controlling agent selects host/srflx, and
every POC controlled agent selects srflx/srflx (24 agents per role in the
one-pair group, 480 in the twenty-pair group). Without IDs, every POC agent
selects host/srflx. Baseline one-pair controlling selections are 20 srflx/srflx
and four host/srflx, with controlled selections five and 19 respectively;
twenty-pair controlling selections are 329 and 151, and controlled selections
90 and 390. These candidate-reporting differences remain explicit.

The twenty-pair, pair-ID median is 0.847 ms higher (about 0.14%) with overlapping
ranges. This does not establish a strict no-slowdown guarantee. The no-ID
twenty-pair median improves by 14.866 ms. These are virtual-NAT measurements,
not Windows, WAN, Proxbird or multi-host timing. Raw samples, ranges, observers,
reproduction scripts and verified provenance are retained in
`/workspace/scratch/mux-timing-reader-queues/`.

Analysis of those same samples, without rerunning the benchmark, finds 16 of
24 paired differences positive for twenty pairs with IDs. The paired median is
+0.273 ms when baseline runs first and +0.773 ms when POC runs first; a simple
second-process penalty does not explain away the shift. Order-stratified
bootstrap 95% percentile intervals are -0.306 to +1.663 ms for the difference
of medians and -0.145 to +1.586 ms for the paired median. Adjacent balanced-block
resampling instead gives +0.250 to +1.285 ms for the paired median. This
sensitivity is reported rather than selecting a convenient interval. Neither
"just noise" nor a causal slowdown is established: deterministic alternation,
24 repetitions, one virtual-NAT session and different selected candidate types
limit inference. The script and all assumptions are in `order-analysis.md`,
`order_analysis.py` and its JSON output in the same evidence directory.

The validated source and this report were pushed normally as
`145a4ab86c27b8658c18308b33aa4c41109a52a5`; only this report differs from exact
`24817004`. Remote SHA verification succeeded. GitHub reports no workflow runs
for that push: the existing platform test workflows trigger only on main,
release branches or pull requests. No workflow trigger or branch naming was
changed to circumvent that condition. The user has the existing-workflow
command pinned to `145a4ab8` for the full 85 cases and two client-suite repeats.

Before the next report-only push, the requested four-command sequence is run
again on `145a4ab8`: formatting and lint pass, full unit results remain exactly
253 passing / 137 without tests / six baseline-matched failures, and the required
race command passes using Go's cache for unchanged packages. No package result
changes. All 2,669 Go/module files match exact `24817004` before and after each
command. The earlier uncached race and both complete e2e results remain the
runtime evidence; they are not relabelled as new runs. This sequence and cleanup
are recorded in `/workspace/scratch/validation-reader-queues/report-followup/`.

## Multi-host regression found during final-source validation

The source pinned by run `39617144938` is not yet an acceptable final result.
Further real-agent tests found that wildcard-bound sockets gather physical and
loopback host candidates which share one mux connection. A legal reader order
can deliver nomination to loopback and its check responses to the physical
candidate. Baseline `1e63b68c` connects under the same order because its broadcast
also delivers nomination to srflx; intermediate `37dab7d` and `42b087a4` leave
the controlled agent Checking. A 12-second observation records the loopback
pair with nine requests and zero responses. All 41 scheduled host packets were
delivered once; this is not a packet-loss simulation.

The mux-only correction gives each candidate its own queue within the existing
ufrag/family group. USERNAME routing retains the first surviving host queue, so
later gathering does not switch the nomination recipient. Candidate IDs remain
local queue identities and request-routing compatibility hints; empty IDs use
the requested local address. Socket `LocalAddr`, fork interfaces, wire format
and overlay checks are unchanged. Closing one candidate removes only its queue;
explicit ufrag removal removes all children of that exact key. Existing URL-key
semantics remain: srflx children close with their candidates, not by prefix
matching a host ufrag.

The committed multi-host test fails on `42b087a4` with controlled connection
timeout and wrong-candidate responses in both roles. With separate queues it
passes under the race detector, as do the existing package tests. Evidence:
`/workspace/scratch/multihost/regression-before-fix.log`,
`regression-after-fix-race.log`, `prototype-race.log`, and
`scheduled-long/final-00.log`.

A second real-agent ordering still prevents connection after separating queues:
the exact baseline peer broadcasts a request and produces two responses. The
first consumes the transaction record; the second follows unknown-ID fallback.
Delaying the host reader by 30 ms lets the srflx reader consume that duplicate
first and take the agent's pending transaction. Native pair stats show the host
pair failing while srflx succeeds without nomination. Evidence:
`/workspace/scratch/multihost/duplicate-delay/final-00.log`. This is a local
reproduction, not proof of the cause of the Windows VM retries.

The mux-only correction removes the pending entry on response but
retains a bounded, expiring recently-answered owner for duplicate routing. This
explicitly adjusts the original immediate-forgetting design: ownership must
survive long enough that a duplicate cannot enter broad fallback. Truly unknown
transactions keep the existing fallback. No packet is suppressed based on an
unauthenticated first response. Pending and recently answered maps each cap at
4096 owners, with independent queues capped at 8192 records; answered traffic
cannot evict outstanding checks. The recent owner retains the original deadline
five seconds after the last request write. Duplicate reads do not refresh it.
Lookup checks that deadline directly, and the five-second worker releases idle
owners within ten seconds. Recent expiry uses a bounded map sweep because
response arrival order need not match request expiry order. Connection removal
and mux close release both kinds of owner under the existing mutex discipline.

Both real-agent regression tests pass under `-race`; package lint has zero
issues. The exact baseline peer with delayed host reads now connects in all
three runs at 602–603 ms. Across 18 answered transactions, all 36 response reads
(two copies each) reach their originating candidate. Focused tests also pass
for expiry in reversed response order, independent bounds, generations, idle
cleanup, and a failed resend after the original response. Two-pass review found
no production locking or lifecycle defect. Evidence and reproduction commands:
`/workspace/scratch/multihost/README.md`, `recent-owner-long/ownership.json`,
`regression-recent-owner-race.log`, and `recent-lifecycle-race.log`.
The full local checks above are complete; VM validation of this newer source
is still pending. The already-dispatched `42b087a4` run does not contain these
corrections.

The full package race run also exposed a preexisting reconnect-test assertion
error, reproduced twice in six runs on immutable `42b087a4`. While the old
agents close, one can still send a request after the other's ufrag is removed.
That now-unknown request must use the required address fallback; surviving
agents reject it without answering. The test now checks all routing before
closure and, afterward, checks exact ownership for surviving-agent checks plus
no surviving-agent replies to stale usernames. Its freshness condition still
requires at least three new responses, now counting distinct transactions
actually sent by that surviving connection. No production fallback or test
threshold changed. The final full `udpmux` race run passes in 11.957 s.

## VM validation of the lifecycle revision (2026-10-21)

The user dispatched [run 39617144938](https://github.com/netbirdio/proxbird-tests/actions/runs/39617144938)
at 14:28:50 UTC for requested source
`42b087a4b5fb0dfcb111c46864d3340194a5a748`, whose Go files match `532e38be`.
The run left the shared workflow queue at 15:06 UTC. Discovery job
`119299897860` confirms the literal source SHA, source-built client/lab, and
all 85 scenario names matching baseline (maximum parallelism 11). All nine
preparation/build jobs passed; the four OS client builds and source-built server
are pinned to that SHA and Go 1.26.7 in manifest artifact `12356575669`. All
85 scenario jobs exist, with the first cases running from 15:15 UTC. It followed
the existing baseline and intermediate client-test
repetitions; no run was cancelled or duplicated. The newer multi-host and
duplicate-response fixes above require a separate immutable-source run.

The first failed case, `client-freebsd-nat-allowed-ports`, is a pre-ICE
infrastructure failure ([artifact 12355883225](https://github.com/netbirdio/proxbird-tests/actions/runs/39617144938/artifacts/12355883225),
job `119304353650`). Proxmox rejects the guest-agent command stopping the lab
artifact server: HTTP 596/broken pipe, submission not accepted, no status
polls, and about 234 seconds left in its budget. Both client diagnostics report
`netbird: command not found` (exit 127); readiness, reconnect and traffic
assertions are all NOT RUN. Candidate, mode and timing evidence are unavailable
for this attempt. It is neither a mux pass nor a demonstrated mux failure.
One targeted job retry is permitted after the workflow finishes; the failed
attempt must remain visible alongside any retry. After the completed attempt-1
audit was frozen, GitHub accepted the one targeted retry; its result is recorded
separately below.

Another writer changed the remote branch after `42b087a4` was pushed. Merge
`27531b60` and report commit `58046129` retain the earlier `37dab7d` source and
remove the later fixes from the current remote tree. The final validation must
therefore pin the intended immutable source, not resolve the moving branch name. The
existing commits and reports remain preserved. A normal merge now reconciles
that history while retaining the reproduced lifecycle and candidate-ownership
fixes. The source must pass its own checks and VM run before acceptance; no
force push or history rewrite is used. The concurrent report is preserved at
[58046129](https://github.com/netbirdio/netbird/blob/580461295b3dd052648f8fb16e1b91599537af77/POC-udpmux-txid-routing.md).
Its setup-convergence table covers the controller's broader assertion phase,
not ICE negotiation medians: across 85 different cases its reported medians
are 8.0 s baseline and 8.4 s intermediate POC, with median paired difference
0.00 s. Native artifact timing and candidate evidence below supersede its
earlier artifact-access limitations.

A later remote update resolves the competing branch trees: commit
`6f5ef8ada8bbc507fe0241693c1a6ba5d4eb261c` explicitly restores the entire tree of
`145a4ab8`, after retaining the other work on a separate branch. The checkout
fast-forwards to that commit after verifying an empty tree diff against
`145a4ab8`. This changes history only; all validated source files and the pinned
new-source dispatch remain identical. The other report at `54d3393a` describes
the same shared-reader nomination mechanism but treats queue separation and
recent-owner retention as outside its selected design. This branch implements
and tests those mux-only alternatives as documented above. Its independent
scratch trial counts are not relabelled as evidence reproduced here.

### Repeated intermediate-source client tests

All four additional 20-case artifact sets pass their case and integrity audits.
They still test baseline `1e63b68c` and intermediate `37dab7d`, not the newer
candidate-ownership fixes.

| Sample | Source | Run |
| --- | --- | --- |
| P2 | `37dab7d` | [39608305272](https://github.com/netbirdio/proxbird-tests/actions/runs/39608305272) |
| B2 | `1e63b68c` | [39608330203](https://github.com/netbirdio/proxbird-tests/actions/runs/39608330203) |
| B3 | `1e63b68c` | [39608353253](https://github.com/netbirdio/proxbird-tests/actions/runs/39608353253) |
| P3 | `37dab7d` | [39608375543](https://github.com/netbirdio/proxbird-tests/actions/runs/39608375543) |

The Linux connect-relay delay does not recur in P2/P3 (0.606/0.605 s). Windows
DNS repeats its asymmetric second negotiation in P2, but B3 connects in 0.610 s
in the same intended controlled role and P3 connects in 0.607 s as controlling.
Both latter runs select a loopback host locally. P3 instead shows an asymmetric
second negotiation in Windows connect-legacy against v0.28.9: 32.401 s and
three attempts versus B3's 13.184 s and two. These native observations do not
establish which mux mechanism caused any VM retry. Evidence, intended-role
provenance, and complete case tables are retained under
`/workspace/scratch/proxbird-repeat-client-tests/`.

## Resumed work (2026-10-21)

The mux-only POC continues. The candidate-type difference is reported below;
it does not justify changing pion/ice in this task. The experimental mapped-
candidate/remote-affinity implementation was not adopted: a deterministic test
that holds Binding responses until nomination arrives can prevent it from
connecting. The request-sender transaction routing passes that ordering test.

The checkout was fast-forwarded from `405edfec` to `f1048acf`, preserving the
parallel implementation and its merge `37dab7d`. That merge deliberately retained
the implementation described below. The completed Proxbird run tests `37dab7d`
and passes all 85 scenarios; later lifecycle fixes need validation at their own
source SHA.

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

Full repository checks were repeated in a disposable Ubuntu container with
the actual GTK/WebKit development libraries, Docker access, and normal `/tmp`
ownership. Lint and the required race checks pass. The complete unit commands
remain red on both revisions: ten failing packages on baseline, nine on the
POC, with the baseline-only bind failure fixed. The completed comparison below
supersedes the earlier restricted-environment results.

All 85 baseline Proxbird case artifacts were downloaded and audited: 2,575
evidence file hashes, 287 complete node diagnostics, 202 native debug bundles
and TRACE archives, and 85 server runtime identities. All cases passed at
`1e63b68c4dc243a32fef823df1bc024c997a9c60`; the status candidate fields match
the native bundle captures. All 85 intermediate POC case artifacts were also
audited with the same evidence counts and zero audit errors. Initial path/status
assertions match across all cases, while final local candidate types differ in
73 directed peer observations. Published case phase durations include work
beyond ICE and must not be described as time-to-P2P medians. The full comparison
below distinguishes the intermediate `37dab7d` run from later lifecycle fixes.

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
| POC e2e run | [39597620276](https://github.com/netbirdio/proxbird-tests/actions/runs/39597620276), dispatched 2026-10-21 12:11 UTC, same inputs; completed successfully, last updated 13:24:17 UTC: **85/85 passed** |
| Revised implementation | `532e38be0da5855fe3b7f95f5612adf0783312c7` (lifecycle fixes and expanded regressions); requested run [39617144938](https://github.com/netbirdio/proxbird-tests/actions/runs/39617144938) pins report descendant `42b087a4`; discovery confirms the source and exact 85-case selection, builds running |

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

### Revised source checks

These checks use Go 1.26.7 and source `532e38be`; later report-only commits and
the merge of the parallel collection notes leave the tested Go file hashes
unchanged. The disposable Ubuntu container has the repository's GTK/WebKit
development libraries and a mounted Docker socket, runs the unit command as a
normal user, and leaves the host's networking unchanged.

| Check | Result |
| --- | --- |
| `go fmt ./...` | exit 0; the 26 unrelated baseline formatting changes were restored |
| `make lint` | exit 0, zero issues with its normal two-minute timeout |
| `make lint-all` | exit 0, zero issues; the empty `nolint` warning also appears on baseline |
| `go test -race ./client/iface/udpmux/... ./client/iface/bind/... ./client/internal/peer/...` | exit 0 across all target packages; udpmux 10.025 s, bind 1.750 s |
| Baseline `make test-unit` | exit 2; 249 passing packages, 10 failing, 137 without tests |
| Revised POC `make test-unit` | exit 2; 250 passing packages, 9 failing, 137 without tests; no new failing package |
| `TestNBLinkReachesAgentNetwork` against source-built baseline | pass, 104.031 s package time |
| Same local netstack e2e against source-built `532e38be` | pass, 104.738 s package time; all 17 nested/leaf assertions pass |
| Official `nblink` v0.81.3 against POC embedded peer | pass, 98.372 s package time; both native peer logs confirm direct ICE active; unchanged full netstack suite |
| Final-source `udpmux` cross-builds | pass with Go 1.26.7 and `CGO_ENABLED=0`: Windows/amd64, Darwin/arm64, Android/arm64 and js/wasm |
| Forbidden production scope changes | none: `go.mod`, `go.sum`, `universal.go`, and `worker_ice.go` are unchanged from baseline |

The e2e package durations above include setup and cleanup and are single-run
functional evidence, not repeated ICE timing medians. The source-built combined
server, proxy and nblink binaries, their hashes, and their runtime images are
recorded in the local validation evidence. This exercises embedded netstack
traffic as well as reconnect, TLS verification and browser boundary checks.
The cross-builds run `go build -p=2 ./client/iface/udpmux` for each target with
`GOMAXPROCS=2`; they prove package compilation, not runtime behavior or native
application linking. Logs and source identity are retained under
`/workspace/scratch/portability-final/`. The earlier FreeBSD cross-build's cgo
dependency limitation was not rerun; native FreeBSD coverage is in Proxbird.

Infrastructure corrections were made only to disposable validation artifacts:
normal `/tmp` ownership, the actual UI development libraries, Docker socket
access, public test CA and executable binary file modes, and proxy exclusions
limited to local fixture destinations. No source assertions were skipped,
thresholds lowered, TLS checks disabled, or host routing/firewall changed.
Superseded full-suite attempts without Docker socket access were cancelled and
are not counted as complete runs. All owned validation containers and fixtures
were removed afterward; the final Docker container inventory is empty.

### Complete unit-suite comparison

Both full commands ran to completion with the repository's `-tags devcert` and
ten-minute package deadline. The source under test is exactly `1e63b68` versus
`532e38be`. No exclusions or thresholds were changed. Focused reruns after an
environment correction are shown separately; they do not make the full commands
green.

| Package / test | Baseline and POC evidence |
| --- | --- |
| `client/iface/bind`, `TestICEBind_HandlesConcurrentMixedTraffic` | Baseline receives 256 packets against the 400 threshold; POC passes after the test receiver-buffer fix described above. This is the only baseline-only failing package. |
| `client/iface/device`, `TestModuleStatus` | Both cannot open `/proc/modules` in the validation container. |
| `client/internal`, `TestEngine_UpdateNetworkMapWithRoutes` | Both lack `/dev/net/tun`; the unchanged nonfatal setup assertion then permits a nil-interface panic. |
| `client/internal/dns`, `TestUpstreamResolver_ServeDNS` | Both cannot reach the public UDP resolvers at `8.8.8.8` / `8.8.4.4` for `one.one.one.one`. |
| `client/internal/dns/mgmt`, empty/partial update tests | Both OS DNS queries fail, leaving empty caches; the unchanged test indexes an absent result and panics. |
| `management/cmd`, `Test_LoadMgmtConfig` | Both Auth0 discovery requests receive explicit proxy `Forbidden`, followed by the unchanged nil-config panic. |
| `management/server`, local gRPC tests | Both proxy their local `[::]:port` fixtures. The POC also encounters a transient disk-full condition while superseded runners coexist. After disk recovery and exact local proxy exclusions, the full package passes on both: 138.433 s baseline / 135.387 s POC. |
| `shared/relay/client`, `TestServerPicker_UnavailableServers` | Both hit the unchanged five-second timeout with only one nanosecond of outer deadline margin while resolving dummy server names. |
| `shared/signal/client`, `TestSignal` | Both reach the 600 s package deadline while proxying a local `[::]:port` fixture. Full package reruns with local proxy exclusions pass: 1.122 s / 1.308 s. |
| `upload-server/server`, `Test_S3HandlerGetUploadURL` | Both time out polling the local Docker S3 fixture through the proxy. The owned fixture returns 403 via the proxy and 200 with an exact `172.17.0.1` exclusion. Full package reruns pass: 1.196 s / 1.353 s. |

The corrected focused runs leave six baseline/environment package failures
unresolved. The complete POC command still has nine failing packages and the
all-unit-tests-pass acceptance condition remains unmet. No additional POC
failing package remains unexplained by the baseline or observed environment
faults. Host routing, external proxy policy and TLS verification were preserved.

Durable workspace evidence is in `/workspace/scratch/validation-resumed/`:
`SUMMARY.md`, `baseline-unit-socket.log`, `poc-final-unit.log`,
`full-unit-results.json`, `unit-failures.json`, `unit-analysis.txt`, and the
focused `*-localproxy.log` files. The full commands and environment are in
`VALIDATION-ENVIRONMENT.txt`; `poc-final-checked-files.sha256` and
`final-source-manifest-check.log` tie the checked Go files to `532e38be`.
These local files are not GitHub workflow artifacts; the results needed to
resume the branch are recorded in this document.

### Current-release embedded-netstack interoperability

The official [nblink v0.81.3 release](https://github.com/netbirdio/netbird/releases/tag/v0.81.3),
published 2026-10-19, passes the unchanged `TestNBLinkReachesAgentNetwork`
suite against the exact `532e38be` POC proxy peer (the same code as `42b087a4`).
The release binary was downloaded, not rebuilt. Its archive SHA256 matches the
published asset digest:
`2162eeeb51b1c3a5f5936eeb8bb95059ab827e76990a223fd223e601beff4d95`.
The extracted binary reports `nblink version 0.81.3` and has SHA256
`39402a7d32ce8e8d4f6aec44a3f24b17f22dfbc880db7c2e15eb0093a1bd4e2c`.

The two native peer logs cross-match their endpoints and identities. The release
peer selected host/prflx and the POC peer host/host; both logged `set ICE to
active connection` at 14:34:42 UTC. The fixture also offers relay, so direct ICE
is established by the native connection evidence rather than inferred from
HTTP success. The full existing traffic, policy denial, TLS rejection and
identity/restart suite passes in 98.372 s (95.17 s top-level test).

This proves actual current-release nblink versus POC embedded-netstack
interoperability in the local Docker network. It does not establish external
NAT behavior, full OS-client interoperability, both initiation roles, or timing
equivalence. The release image retains the fixture's non-root runtime and TLS
verification; all containers were cleaned up. No repository source or assertions
changed. Release metadata, runtime provenance, native connectivity logs and
reproduction are in `/workspace/scratch/release-interop/README.md` and its sibling
files.

## What the routing does now (branch head)

| Inbound STUN | Baseline (`1e63b68`) | POC |
| --- | --- | --- |
| Success / error response | conn of the `0x8100` target candidate, else broadcast to every conn that wrote to the source address | the conn that wrote the request (transaction ID recorded on `udpMuxedConn.WriteTo`); unknown ID: as baseline |
| Request / indication with resolvable `0x8100` | conn of the target candidate | unchanged |
| Request / indication without it | broadcast: address-map conns plus the USERNAME ufrag conn | host conn of the USERNAME ufrag only; no such conn: as baseline |
| Anything else | address-map broadcast | unchanged |

Tracker (`client/iface/udpmux/transactions.go`): header-only parse of outgoing
requests (RFC 8489 section 5: class bits of the type, ID in bytes 8 to 20),
recorded before the socket write. A response removes its pending entry and
retains a recently-answered owner until the original `transactionTTL` deadline
(5 s after the last write). That owner routes duplicate copies without
extending their lifetime. Initial write failure, connection removal and mux
close remove the applicable state; a retired or closed conn is never recorded. At most
`maxTransactions` (4096) outstanding requests are kept, the oldest outstanding
one evicted first. A FIFO queue in insertion order (equal to expiry order, the
TTL being constant) drives expiry and eviction; answered or resent records
left in it are skipped and compacted away at twice the cap, so memory is
bounded by the cap, not by the send rate. Recently answered owners have a
separate 4096-entry cap and a completion-order eviction queue capped at 8192.
Their original expiry is checked on lookup and by the idle worker's bounded map
sweep. Both maps share one mutex, never held across I/O.

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
   Separately, the old mux's asynchronous close watcher could outlive even a
   normally completed agent close and remove its replacement. Synchronous,
   pointer-checked cleanup fixes that tested lifecycle defect in `532e38be`.
8. `go fmt ./...` on `origin/main` reformats 26 files outside `udpmux`
   (pre-existing). They were reverted, not committed, to stay in scope.
9. Earlier lint runs lacked GTK/WebKit headers and one hit the two-minute
   timeout. In the resumed disposable container with those headers installed,
   the unmodified `make lint` and `make lint-all` commands both pass with zero
   issues on the revised source.
10. Direct RFC access was initially blocked. The resumed review verified the
    published [RFC 8489 section 5](https://www.rfc-editor.org/rfc/rfc8489.html#section-5)
    header/transaction rules, [section 14](https://www.rfc-editor.org/rfc/rfc8489.html#section-14)
    comprehension-optional range and [section 14.7](https://www.rfc-editor.org/rfc/rfc8489.html#section-14.7)
    FINGERPRINT ordering, plus [RFC 8445 section 7.2.5](https://www.rfc-editor.org/rfc/rfc8445.html#section-7.2.5)
    response processing and mapped-address valid-pair construction. Other RFC
    section references from the earlier notes were not independently verified.
11. Direct artifact downloads were blocked by the network policy. The supported
    GitHub artifact download interface does work: all baseline per-case reports,
    native bundles and raw logs have now been downloaded and audited, followed
    by the intermediate POC artifacts as they become available. The earlier
    inability to inspect artifacts is superseded. Workflow dispatch still
    requires access to `api.github.com`, which this environment denies.

12. **Parallel run on the same branch.** While this run was validating, the
    branch received three commits from a parallel run of the same task
    (`553908d`, `b204c66`, `405edfe`, 10:54 to 11:02 UTC). That run measured the
    same srflx-to-host change on the controlling side, treated it as the
    hard stop, and could not reach the GitHub API for e2e. `37dab7d` is an `-s ours`
    merge: those commits stay in history, none of their files are in the tree.
13. **The srflx-to-host change is reported, not treated as a hard stop.** The
    task lists the reported local candidate type under behavior to record and
    says to call a change such as "srflx shown as host" out explicitly with
    evidence. It is a direct consequence of the mandated response routing
    (see "What the change does to candidate selection" below). The wire format
    and fork stay unchanged, but selecting a different candidate can change
    existing nomination attributes and timing. The e2e comparison must assess
    those effects separately.
14. In the earlier parallel environment, letting the pre-push hook's `make
    lint` typecheck `client/ui` required the packages CI installs
    (`libgtk-4-dev libwebkitgtk-6.0-dev libsoup-3.0-dev libgl1-mesa-dev
    xorg-dev libpcap-dev`) and created the ignored placeholder
    `client/ui/frontend/dist/.embed-placeholder`, as the lint workflow does.
    `make lint` then passed in that environment's hook. The resumed checkout
    has no configured pre-push hook; the required lint commands were run
    directly in the disposable validation container. No hook was bypassed.

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

There is no wire-format or fork change. The tested NAT fixtures retain the
same socket, external 5-tuple and remote WireGuard endpoint. Selecting a
different candidate can change existing STUN PRIORITY and pair-ID values in
nomination traffic; packet contents and timing are not claimed identical.
NetBird uses the reported local candidate type for display (`netbird status
-d`, UI, mobile) and debug logs; relay detection, route selection and connection
priority use the relay flag and the remote endpoint. The local endpoint shown
becomes the interface address instead of the public mapping. Proxbird's NAT
check accepts srflx or prflx on either side, so it still passes when the remote
side is reflexive.

The earlier implementations (`37dab7d` and `42b087a4`) shared a read queue
between host candidates of one family and between srflx candidates using the
same URL/socket family. That made exact connection ownership weaker than exact
candidate ownership. The multi-host reproduction above demonstrates a complete
nomination failure, beyond an RTT/reporting difference. The revised mux gives
each candidate ID a separate queue, including URL-keyed candidates. Real-agent
physical/loopback host coverage now passes; a full dual-stack NAT runtime
comparison remains outside the collected evidence.

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
| `go test -race ./client/iface/udpmux/... ./client/iface/bind/... ./client/internal/peer/...` | `udpmux` ok. `bind`: the same `TestICEBind_OpenDoesNotDiscoverInterfaces` environmental failure as baseline. `peer`: a data race between `TestWGWatcher_CheckSuccessCallback`'s leftover goroutine and `TestWGWatcher_EnableWgWatcher` writing package-level `checkPeriod`; reproduces on baseline in 5 of 6 `-race` runs (POC tree 2 of 6), unrelated to the mux; resolved by the test-only watcher cleanup in `f6095c0e` during resumed work. `peer/guard`, `peer/ice` ok |
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
| Record could be added for a conn after `removeConn`/`Close` passed | initially incomplete fix | The initial `isClosed` check did not cover nonclosing removal; `532e38be` adds the registered-pointer check under `m.mu` and regression tests. |
| Failed write (overlay refusal) held a slot for the TTL | nit | `forget` on write error; `TestUniversalUDPMux_RefusedWriteIsNotTracked` |
| `Close` clearing records untested; counts and listings snapshotted separately; `require` used for the condition under test; alias map key; duplicated mux start helper; `pending()` only used by tests | nits | fixed |
| Dual-stack: udp4 and udp6 srflx candidates share one muxed conn (keyed `ufrag+url` on the v4 map), so a response routed to it can be read by the wrong-family candidate | pre-existing; the earlier experiment observed no lower srflx-pair success, not a general guarantee | recorded under "Not covered / caveats" |
| "At most one response per request" not "exactly one" | coverage limit | The trace proves exclusive ownership for observed response reads and at-most-one answer per observed request. ICE connection success does not prove that every request received an answer; some packet loss can coexist with successful ICE. |

The seven mutants the reviewers and I built (order swap, no pair ID
fallback, queue-based eviction, no `forget`, no `clear`, no closed check,
wrong-agent delivery) all fail the suite now.

### Cross-version check (scratch only, not committed)

proxbird has no case that pairs the candidate build with a current release
peer (its references are 0.28.9 and 0.30.1, both older than pair-ID routing,
which shipped in v0.57.0 with #4430). To exercise POC versus baseline mux
behavior at unit level, a throwaway worktree (`git worktree add --detach cb20fec`) got a
renamed copy of the baseline mux (`git show 1e63b68:client/iface/udpmux/{mux,conn,universal,mux_generic}.go`
as package `baselinemux`) and a test connecting a POC-mux host to a
baseline-mux host over the same vnet NAT, two agent pairs at once, POC
controlling and controlled. The peer variant "baseline mux, stamps pair ID" is
representative of the v0.57+ routing path; "baseline mux, pair ID stripped"
exercises the broadcast routing that pre-0.57 clients use. Neither variant is
an actual release binary or a substitute for that interoperability check.

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
- 12:44 UTC: test-only bind buffer and watcher-lifetime corrections committed
  as `f6095c0e`, after reproducing the required suite failures.
- 12:45 UTC: lifecycle, address ownership and retransmission fixes committed
  as `532e38be`, with the real-socket and real-agent regressions described above.
- 12:53 UTC: repeated local timing/candidate comparison recorded in `92dfa510`.
- 13:00 UTC: parallel collection notes preserved in merge `e42654b0`; tested
  production and test sources remain identical to `532e38be`.
- 13:13 UTC: completed full-unit, lint, race and local netstack evidence
  recorded in `2f02d871`, with baseline failures and environment corrections.
- 13:19 UTC: portable timing evidence and final-source cross-build results
  recorded in `4c5a0f96`.
- 13:24 UTC: intermediate POC workflow reports success for all 85 cases.
  All 85 artifacts are subsequently audited and compared below. No rerun or
  cancellation was used to obtain these results.

## Initial e2e collection method (superseded by artifact inspection)

Before artifact access was established, the comparison used:

1. `gh api repos/netbirdio/proxbird-tests/actions/runs/RUN/attempts/1/jobs?per_page=100`
   for per-case status and conclusion.
2. Each scenario job's log, fetched through the supported GitHub interface,
   keeping the controller lines
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

The artifacts are now reachable. Candidate types per peer come from each case
artifact's `results/*/result.json` (`.peers[i].peers.details[]` with
`connectionType` and `iceCandidateType.{local,remote}`) or
`results/*/nodes/peer-N/status-detail.txt` (`ICE candidate (Local/Remote)`).
Artifacts expire 14 days after the runs (2026-11-04).

## Not covered / caveats

- **Final source in Proxbird**: the intermediate run uses `37dab7d`; run
  `39617144938` now builds the later lifecycle source `42b087a4` (`532e38be` Go
  files). It does not include the newer candidate-queue/recent-owner fixes. Artifact
  inspection now includes the candidate types, initial assertion results,
  final snapshots, and native negotiation traces for the available runs.
- **Current release peers**: no proxbird case pairs the candidate build with a
  current release binary; the scratch cross-version test uses baseline mux
  behavior. Separately, official nblink v0.81.3 passes the local full netstack
  suite against the POC peer, with direct ICE confirmed on both sides. Full
  OS-client and external-NAT mixed-release coverage remains unproven.
- **Netstack (`client/embed`)**: the local `TestNBLinkReachesAgentNetwork` suite
  passes with source-built binaries for both `1e63b68` and `532e38be`, including
  overlay HTTP traffic, reconnect identity, browser boundary checks and TLS
  rejection. Runtime users and verification remain unchanged. Correct fixture
  file modes and scoped local Docker proxy exclusions were required; no
  production source or test assertions were altered. This is separate from
  Proxbird's kernel/userspace VM coverage.
- **Mobile (iOS, Android)**: not exercised; Android builds.
- **Reused credentials**: distinct simultaneous agents using the identical
  ufrag remain ambiguous for USERNAME routing and explicit ufrag removal.
  Ordinary reconnect coverage uses distinct credentials. Candidate queues,
  shared-address removal, and pointer-specific close are fixed and tested;
  full dual-stack and mobile runtime coverage remains incomplete.
- **Full pair-ID removal** (variant R) was measured only at unit level; no
  e2e run of it exists.

## Proxbird evidence for the intermediate source

Both runs report `completed` / `success`, with 94/94 successful jobs including
85/85 scenarios. Baseline's final run update is 12:06:31 UTC; intermediate POC's
is 13:24:17 UTC on 2026-10-21 (last job completion 13:24:14 UTC). The source SHAs
are `1e63b68` and `37dab7d`; the later lifecycle implementation at `532e38be` is
not covered by these VM runs.

For each run, all 85 case ZIPs were downloaded and inspected: 2,575 evidence
files match their size/hash inventories, 287 node diagnostics are complete,
202 native debug bundles and raw TRACE archives are readable, and 85 server
runtime identities match. All 65 Robot reports and 13 recovery/path/underlay
traffic audits pass; all 32 canonical start warnings are followed by readiness.
There are zero audit errors. This checks published cleanup evidence, not a
separate live inventory of VM/ISO absence. Build manifests identify Go 1.26.7
and the exact source for all four clients and the server; recorded installer
hashes were not independently recomputed from the large binary archives.

| Directed observation differences | Initial snapshots | Final snapshots |
| --- | ---: | ---: |
| Path/status | 0 | 2 |
| Local/remote candidate types | 105 | 90 |
| Local candidate type | 77 | 73 |

The two final path differences belong to the Windows DNS post-restart snapshot,
described below. They do not contradict its passing initial P2P assertions.
Both runs report Linux kernel mode on 82 nodes and userspace mode on 56 FreeBSD,
32 macOS and 32 Windows nodes, with no missing or unexpected mode flags. Each
run has 182 source-built nodes, sixteen 0.30.1 peers and four 0.28.9 peers;
CLI and daemon versions match. No current-release binary is represented.

There are 212 paired successful ICE observations across the matching case
artifacts. This count is not 212 repeated trials of one topology. The three
slower episodes and their native-log evidence are recorded after the complete
per-case table. All downloaded evidence is retained under
`/workspace/scratch/proxbird/`; artifact links below identify the published
sources, which have the workflow's 14-day retention.

### Portable Proxbird comparison: intermediate source only

Baseline [run 39588288742](https://github.com/netbirdio/proxbird-tests/actions/runs/39588288742), source `1e63b68c4dc243a32fef823df1bc024c997a9c60`; intermediate POC [run 39597620276](https://github.com/netbirdio/proxbird-tests/actions/runs/39597620276), source `37dab7d7124ea1de7a7e9bdfa5a3cd445f8413dc`. Harness `a1abca530f93969ad81f11a9683dc6e89171a23c`, attempt 1, exact 85-case selection: `peer-pairs,client-tests,recovery,connectivity-repair,connectivity-underlay,routing-ha,routing-overlap`. This table does not validate final source `532e38be`.

Each arrow is baseline → intermediate POC; `(both)` means the displayed fields match. `I` is the initial `start-clients` peer snapshot when present, otherwise `result.peers`; `F` is the final per-node diagnostic snapshot, captured after test actions. `1>2` means peer-1 reporting peer-2; `2R` means peer-2-replacement. Final snapshots are not atomic. Candidate pairs are local/remote types. The Windows DNS final Connecting/Relayed baseline follows a daemon restart even though initial P2P assertions passed.

The timing column is seconds from first observed ICE agent dial to first success for the same local role/remote identity, including failed attempts and gaps. It is not application-observed time to P2P or a repeated-run median. It excludes earlier signalling/setup and later traffic readiness; local role archives can span restarts. Original and replacement identities are mapped from status and exact interface key/address logs. Unmeasured legacy/no-success observations are never zero. Three slowdown episodes are investigated separately; no mux causality is inferred solely from timing. There is one workflow per source/topology.

Each B/P link is the immutable GitHub artifact ID for that case. Inside its ZIP, evidence is under `results/<controller-id>/`: `result.json`, `nodes/peer-*/status.json`, `status-detail.txt`, `debug-bundle.zip` (`status.txt`), and raw `client-logs.*`. Source identities and artifact/file SHA-256 checks were audited. These links survive copying this table into the branch progress log.

| Case | Result B/P | P2P/relay snapshots | Candidate snapshots (local/remote) | First ICE dial→success seconds B→P | Artifact IDs |
| --- | --- | --- | --- | --- | --- |
| `client-freebsd-nat-allowed-ports` | pass/pass | I: 1>2:P2P; 2>1:P2P (both)<br>F: 1>2:P2P; 2>1:P2P (both) | I: 1>2:host/srflx; 2>1:host/srflx → 1>2:srflx/srflx; 2>1:host/srflx<br>F: 1>2:host/prflx; 2>1:host/srflx (both) | 1>2:0.604→0.625; 2:legacy/unmeasured | B [12340654721](https://github.com/netbirdio/proxbird-tests/actions/runs/39588288742/artifacts/12340654721)<br>P [12344594476](https://github.com/netbirdio/proxbird-tests/actions/runs/39597620276/artifacts/12344594476) |
| `client-freebsd-nat-connect-legacy` | pass/pass | I: 1>2:P2P; 2>1:P2P (both)<br>F: 1>2:P2P; 2>1:P2P (both) | I: 1>2:host/srflx; 2>1:host/srflx (both)<br>F: 1>2:host/srflx; 2>1:host/srflx (both) | 1>2:0.604→0.604; 2:legacy/unmeasured | B [12342305010](https://github.com/netbirdio/proxbird-tests/actions/runs/39588288742/artifacts/12342305010)<br>P [12345956309](https://github.com/netbirdio/proxbird-tests/actions/runs/39597620276/artifacts/12345956309) |
| `client-freebsd-nat-connect-relay` | pass/pass | I: 1>2:P2P; 2>1:P2P (both)<br>F: 1>2:P2P; 2>1:P2P (both) | I: 1>2:srflx/srflx; 2>1:host/srflx → 1>2:host/srflx; 2>1:host/srflx<br>F: 1>2:srflx/srflx; 2>1:host/srflx → 1>2:host/srflx; 2>1:host/srflx | 1>2:0.613→0.603; 2:legacy/unmeasured | B [12341165873](https://github.com/netbirdio/proxbird-tests/actions/runs/39588288742/artifacts/12341165873)<br>P [12345452007](https://github.com/netbirdio/proxbird-tests/actions/runs/39597620276/artifacts/12345452007) |
| `client-freebsd-nat-dns` | pass/pass | I: 1>2:P2P; 2>1:P2P (both)<br>F: 1>2:P2P; 2>1:P2P (both) | I: 1>2:host/srflx; 2>1:host/srflx (both)<br>F: 1>2:host/srflx; 2>1:host/srflx (both) | 1>2:0.605→0.605; 2:legacy/unmeasured | B [12341410760](https://github.com/netbirdio/proxbird-tests/actions/runs/39588288742/artifacts/12341410760)<br>P [12345532811](https://github.com/netbirdio/proxbird-tests/actions/runs/39597620276/artifacts/12345532811) |
| `client-freebsd-nat-exit-node` | pass/pass | I: 1>2:P2P; 2>1:P2P (both)<br>F: 1>2:P2P; 2>1:P2P (both) | I: 1>2:host/srflx; 2>1:host/srflx → 1>2:srflx/srflx; 2>1:srflx/srflx<br>F: 1>2:host/srflx; 2>1:host/srflx → 1>2:srflx/srflx; 2>1:srflx/srflx | 1>2:0.615→0.605; 2:legacy/unmeasured | B [12341420754](https://github.com/netbirdio/proxbird-tests/actions/runs/39588288742/artifacts/12341420754)<br>P [12345242992](https://github.com/netbirdio/proxbird-tests/actions/runs/39597620276/artifacts/12345242992) |
| `client-linux-nat-allowed-ports` | pass/pass | I: 1>2:P2P; 2>1:P2P (both)<br>F: 1>2:P2P; 2>1:P2P (both) | I: 1>2:host/srflx; 2>1:host/srflx (both)<br>F: 1>2:host/prflx; 2>1:host/srflx (both) | 1>2:0.606→0.606; 2:legacy/unmeasured | B [12341094768](https://github.com/netbirdio/proxbird-tests/actions/runs/39588288742/artifacts/12341094768)<br>P [12345252179](https://github.com/netbirdio/proxbird-tests/actions/runs/39597620276/artifacts/12345252179) |
| `client-linux-nat-connect-legacy` | pass/pass | I: 1>2:P2P; 2>1:P2P (both)<br>F: 1>2:P2P; 2>1:P2P (both) | I: 1>2:srflx/srflx; 2>1:host/srflx → 1>2:host/srflx; 2>1:host/srflx<br>F: 1>2:srflx/srflx; 2>1:host/srflx → 1>2:host/srflx; 2>1:host/srflx | 1>2:0.603→0.605; 2:legacy/unmeasured | B [12341034872](https://github.com/netbirdio/proxbird-tests/actions/runs/39588288742/artifacts/12341034872)<br>P [12344703617](https://github.com/netbirdio/proxbird-tests/actions/runs/39597620276/artifacts/12344703617) |
| `client-linux-nat-connect-relay` | pass/pass | I: 1>2:P2P; 2>1:P2P (both)<br>F: 1>2:P2P; 2>1:P2P (both) | I: 1>2:host/srflx; 2>1:host/srflx → 1>2:host/prflx; 2>1:srflx/srflx<br>F: 1>2:host/srflx; 2>1:host/srflx → 1>2:host/prflx; 2>1:srflx/srflx | 1>2:0.605→29.127; 2:legacy/unmeasured | B [12341850071](https://github.com/netbirdio/proxbird-tests/actions/runs/39588288742/artifacts/12341850071)<br>P [12345292351](https://github.com/netbirdio/proxbird-tests/actions/runs/39597620276/artifacts/12345292351) |
| `client-linux-nat-dns` | pass/pass | I: 1>2:P2P; 2>1:P2P (both)<br>F: 1>2:P2P; 2>1:P2P (both) | I: 1>2:host/srflx; 2>1:host/srflx (both)<br>F: 1>2:host/srflx; 2>1:host/srflx (both) | 1>2:0.605→0.605; 2:legacy/unmeasured | B [12341540836](https://github.com/netbirdio/proxbird-tests/actions/runs/39588288742/artifacts/12341540836)<br>P [12345198908](https://github.com/netbirdio/proxbird-tests/actions/runs/39597620276/artifacts/12345198908) |
| `client-linux-nat-exit-node` | pass/pass | I: 1>2:P2P; 2>1:P2P (both)<br>F: 1>2:P2P; 2>1:P2P (both) | I: 1>2:host/srflx; 2>1:host/srflx → 1>2:srflx/srflx; 2>1:srflx/srflx<br>F: 1>2:host/srflx; 2>1:host/srflx → 1>2:srflx/srflx; 2>1:srflx/srflx | 1>2:0.606→0.605; 2:legacy/unmeasured | B [12341545883](https://github.com/netbirdio/proxbird-tests/actions/runs/39588288742/artifacts/12341545883)<br>P [12346200603](https://github.com/netbirdio/proxbird-tests/actions/runs/39597620276/artifacts/12346200603) |
| `client-macos-nat-allowed-ports` | pass/pass | I: 1>2:P2P; 2>1:P2P (both)<br>F: 1>2:P2P; 2>1:P2P (both) | I: 1>2:host/srflx; 2>1:host/srflx (both)<br>F: 1>2:srflx/prflx; 2>1:host/srflx → 1>2:host/prflx; 2>1:host/srflx | 1>2:0.606→0.606; 2:legacy/unmeasured | B [12342480775](https://github.com/netbirdio/proxbird-tests/actions/runs/39588288742/artifacts/12342480775)<br>P [12345992075](https://github.com/netbirdio/proxbird-tests/actions/runs/39597620276/artifacts/12345992075) |
| `client-macos-nat-connect-legacy` | pass/pass | I: 1>2:P2P; 2>1:P2P (both)<br>F: 1>2:P2P; 2>1:P2P (both) | I: 1>2:host/srflx; 2>1:host/srflx → 1>2:host/srflx; 2>1:srflx/srflx<br>F: 1>2:host/srflx; 2>1:host/srflx → 1>2:host/srflx; 2>1:srflx/srflx | 1>2:0.605→0.604; 2:legacy/unmeasured | B [12342625657](https://github.com/netbirdio/proxbird-tests/actions/runs/39588288742/artifacts/12342625657)<br>P [12346062221](https://github.com/netbirdio/proxbird-tests/actions/runs/39597620276/artifacts/12346062221) |
| `client-macos-nat-connect-relay` | pass/pass | I: 1>2:P2P; 2>1:P2P (both)<br>F: 1>2:P2P; 2>1:P2P (both) | I: 1>2:host/srflx; 2>1:host/srflx → 1>2:srflx/srflx; 2>1:host/srflx<br>F: 1>2:host/srflx; 2>1:host/srflx → 1>2:srflx/srflx; 2>1:host/srflx | 1>2:0.604→0.605; 2:legacy/unmeasured | B [12342735708](https://github.com/netbirdio/proxbird-tests/actions/runs/39588288742/artifacts/12342735708)<br>P [12344833609](https://github.com/netbirdio/proxbird-tests/actions/runs/39597620276/artifacts/12344833609) |
| `client-macos-nat-dns` | pass/pass | I: 1>2:P2P; 2>1:P2P (both)<br>F: 1>2:P2P; 2>1:P2P (both) | I: 1>2:srflx/srflx; 2>1:host/srflx → 1>2:host/srflx; 2>1:host/srflx<br>F: 1>2:srflx/srflx; 2>1:host/srflx → 1>2:host/srflx; 2>1:host/srflx | 1>2:0.606→0.603; 2:legacy/unmeasured | B [12341906028](https://github.com/netbirdio/proxbird-tests/actions/runs/39588288742/artifacts/12341906028)<br>P [12345443406](https://github.com/netbirdio/proxbird-tests/actions/runs/39597620276/artifacts/12345443406) |
| `client-macos-nat-exit-node` | pass/pass | I: 1>2:P2P; 2>1:P2P (both)<br>F: 1>2:P2P; 2>1:P2P (both) | I: 1>2:srflx/srflx; 2>1:host/srflx → 1>2:host/srflx; 2>1:host/srflx<br>F: 1>2:srflx/srflx; 2>1:host/srflx → 1>2:host/srflx; 2>1:host/srflx | 1>2:0.605→0.605; 2:legacy/unmeasured | B [12341841039](https://github.com/netbirdio/proxbird-tests/actions/runs/39588288742/artifacts/12341841039)<br>P [12345398159](https://github.com/netbirdio/proxbird-tests/actions/runs/39597620276/artifacts/12345398159) |
| `client-windows-nat-allowed-ports` | pass/pass | I: 1>2:P2P; 2>1:P2P (both)<br>F: 1>2:P2P; 2>1:P2P (both) | I: 1>2:host/srflx; 2>1:host/prflx → 1>2:host/srflx; 2>1:host/srflx<br>F: 1>2:host/srflx; 2>1:host/srflx → 1>2:srflx/srflx; 2>1:host/srflx | 1>2:21.180→0.605; 2:legacy/unmeasured | B [12341137187](https://github.com/netbirdio/proxbird-tests/actions/runs/39588288742/artifacts/12341137187)<br>P [12344709817](https://github.com/netbirdio/proxbird-tests/actions/runs/39597620276/artifacts/12344709817) |
| `client-windows-nat-connect-legacy` | pass/pass | I: 1>2:P2P; 2>1:P2P (both)<br>F: 1>2:P2P; 2>1:P2P (both) | I: 1>2:host/srflx; 2>1:host/srflx → 1>2:srflx/srflx; 2>1:srflx/srflx<br>F: 1>2:host/srflx; 2>1:host/srflx → 1>2:srflx/srflx; 2>1:srflx/srflx | 1>2:13.882→13.142; 2:legacy/unmeasured | B [12342086503](https://github.com/netbirdio/proxbird-tests/actions/runs/39588288742/artifacts/12342086503)<br>P [12346321422](https://github.com/netbirdio/proxbird-tests/actions/runs/39597620276/artifacts/12346321422) |
| `client-windows-nat-connect-relay` | pass/pass | I: 1>2:P2P; 2>1:P2P (both)<br>F: 1>2:P2P; 2>1:P2P (both) | I: 1>2:host/srflx; 2>1:host/srflx → 1>2:srflx/srflx; 2>1:srflx/srflx<br>F: 1>2:host/srflx; 2>1:host/srflx → 1>2:srflx/srflx; 2>1:srflx/srflx | 1>2:0.605→0.604; 2:legacy/unmeasured | B [12342531334](https://github.com/netbirdio/proxbird-tests/actions/runs/39588288742/artifacts/12342531334)<br>P [12345963160](https://github.com/netbirdio/proxbird-tests/actions/runs/39597620276/artifacts/12345963160) |
| `client-windows-nat-dns` | pass/pass | I: 1>2:P2P; 2>1:P2P (both)<br>F: 1>2:-(Connecting); 2>1:Relayed → 1>2:P2P; 2>1:P2P | I: 1>2:host/srflx; 2>1:host/prflx → 1>2:host/prflx; 2>1:srflx/srflx<br>F: 1>2:-/-; 2>1:-/- → 1>2:host/srflx; 2>1:srflx/prflx | 1>2:21.182→29.053; 2:legacy/unmeasured | B [12341942075](https://github.com/netbirdio/proxbird-tests/actions/runs/39588288742/artifacts/12341942075)<br>P [12346227132](https://github.com/netbirdio/proxbird-tests/actions/runs/39597620276/artifacts/12346227132) |
| `client-windows-nat-exit-node` | pass/pass | I: 1>2:P2P; 2>1:P2P (both)<br>F: 1>2:P2P; 2>1:P2P (both) | I: 1>2:host/srflx; 2>1:host/srflx → 1>2:host/srflx; 2>1:srflx/srflx<br>F: 1>2:host/srflx; 2>1:host/srflx → 1>2:host/srflx; 2>1:srflx/srflx | 1>2:0.609→0.607; 2:legacy/unmeasured | B [12341566794](https://github.com/netbirdio/proxbird-tests/actions/runs/39588288742/artifacts/12341566794)<br>P [12345968342](https://github.com/netbirdio/proxbird-tests/actions/runs/39597620276/artifacts/12345968342) |
| `connectivity-repair-freebsd-nat-path-repair` | pass/pass | I: 1>2:P2P; 2>1:P2P (both)<br>F: 1>2:Relayed; 2>1:Relayed (both) | I: 1>2:srflx/srflx; 2>1:srflx/srflx → 1>2:srflx/srflx; 2>1:host/srflx<br>F: 1>2:-/-; 2>1:-/- (both) | 1>2:0.605→0.604; 2>1:0.606→0.605 | B [12341916838](https://github.com/netbirdio/proxbird-tests/actions/runs/39588288742/artifacts/12341916838)<br>P [12346216851](https://github.com/netbirdio/proxbird-tests/actions/runs/39597620276/artifacts/12346216851) |
| `connectivity-repair-linux-nat-path-repair` | pass/pass | I: 1>2:P2P; 2>1:P2P (both)<br>F: 1>2:Relayed; 2>1:Relayed (both) | I: 1>2:srflx/srflx; 2>1:srflx/srflx → 1>2:srflx/srflx; 2>1:host/srflx<br>F: 1>2:-/-; 2>1:-/- (both) | 1>2:0.604→0.603; 2>1:0.605→0.605 | B [12342606512](https://github.com/netbirdio/proxbird-tests/actions/runs/39588288742/artifacts/12342606512)<br>P [12344814457](https://github.com/netbirdio/proxbird-tests/actions/runs/39597620276/artifacts/12344814457) |
| `connectivity-repair-macos-nat-path-repair` | pass/pass | I: 1>2:P2P; 2>1:P2P (both)<br>F: 1>2:Relayed; 2>1:Relayed (both) | I: 1>2:srflx/srflx; 2>1:srflx/srflx → 1>2:host/srflx; 2>1:srflx/srflx<br>F: 1>2:-/-; 2>1:-/- (both) | 1>2:0.604→0.605; 2>1:0.605→0.605 | B [12342611591](https://github.com/netbirdio/proxbird-tests/actions/runs/39588288742/artifacts/12342611591)<br>P [12345154255](https://github.com/netbirdio/proxbird-tests/actions/runs/39597620276/artifacts/12345154255) |
| `connectivity-repair-windows-nat-path-repair` | pass/pass | I: 1>2:P2P; 2>1:P2P (both)<br>F: 1>2:Relayed; 2>1:Relayed (both) | I: 1>2:srflx/srflx; 2>1:srflx/srflx → 1>2:srflx/srflx; 2>1:host/srflx<br>F: 1>2:-/-; 2>1:-/- (both) | 1>2:0.605→0.603; 2>1:0.612→0.610 | B [12342246693](https://github.com/netbirdio/proxbird-tests/actions/runs/39588288742/artifacts/12342246693)<br>P [12345658989](https://github.com/netbirdio/proxbird-tests/actions/runs/39597620276/artifacts/12345658989) |
| `connectivity-underlay-linux-nat-underlay-change` | pass/pass | I: 1>2:P2P; 2>1:P2P (both)<br>F: 1>2:P2P; 2>1:P2P (both) | I: 1>2:srflx/srflx; 2>1:srflx/srflx → 1>2:host/srflx; 2>1:srflx/srflx<br>F: 1>2:srflx/prflx; 2>1:host/srflx → 1>2:host/prflx; 2>1:host/srflx | 1>2:0.604→0.603; 2>1:0.604→0.604 | B [12341802157](https://github.com/netbirdio/proxbird-tests/actions/runs/39588288742/artifacts/12341802157)<br>P [12346103703](https://github.com/netbirdio/proxbird-tests/actions/runs/39597620276/artifacts/12346103703) |
| `freebsd-freebsd-direct` | pass/pass | I: 1>2:P2P; 2>1:P2P (both)<br>F: 1>2:P2P; 2>1:P2P (both) | I: 1>2:srflx/srflx; 2>1:srflx/srflx → 1>2:host/host; 2>1:host/prflx<br>F: 1>2:srflx/srflx; 2>1:srflx/srflx → 1>2:host/host; 2>1:host/prflx | 1>2:0.614→1.044; 2>1:0.614→1.044 | B [12342671706](https://github.com/netbirdio/proxbird-tests/actions/runs/39588288742/artifacts/12342671706)<br>P [12346337131](https://github.com/netbirdio/proxbird-tests/actions/runs/39597620276/artifacts/12346337131) |
| `freebsd-freebsd-nat` | pass/pass | I: 1>2:P2P; 2>1:P2P (both)<br>F: 1>2:P2P; 2>1:P2P (both) | I: 1>2:srflx/srflx; 2>1:srflx/srflx → 1>2:srflx/srflx; 2>1:host/srflx<br>F: 1>2:srflx/srflx; 2>1:srflx/srflx → 1>2:srflx/srflx; 2>1:host/srflx | 1>2:0.620→0.623; 2>1:0.621→0.624 | B [12341192628](https://github.com/netbirdio/proxbird-tests/actions/runs/39588288742/artifacts/12341192628)<br>P [12345644301](https://github.com/netbirdio/proxbird-tests/actions/runs/39597620276/artifacts/12345644301) |
| `freebsd-freebsd-relay` | pass/pass | I: 1>2:Relayed; 2>1:Relayed (both)<br>F: 1>2:Relayed; 2>1:Relayed (both) | I: 1>2:-/-; 2>1:-/- (both)<br>F: 1>2:-/-; 2>1:-/- (both) | 1>2:unmeasured→unmeasured; 2>1:unmeasured→unmeasured | B [12341387476](https://github.com/netbirdio/proxbird-tests/actions/runs/39588288742/artifacts/12341387476)<br>P [12346371707](https://github.com/netbirdio/proxbird-tests/actions/runs/39597620276/artifacts/12346371707) |
| `freebsd-freebsd-slow` | pass/pass | I: 1>2:P2P; 2>1:P2P (both)<br>F: 1>2:P2P; 2>1:P2P (both) | I: 1>2:srflx/srflx; 2>1:srflx/srflx → 1>2:srflx/srflx; 2>1:host/srflx<br>F: 1>2:srflx/srflx; 2>1:srflx/srflx → 1>2:srflx/srflx; 2>1:host/srflx | 1>2:0.903→0.704; 2>1:0.903→0.905 | B [12341258342](https://github.com/netbirdio/proxbird-tests/actions/runs/39588288742/artifacts/12341258342)<br>P [12345059832](https://github.com/netbirdio/proxbird-tests/actions/runs/39597620276/artifacts/12345059832) |
| `macos-macos-direct` | pass/pass | I: 1>2:P2P; 2>1:P2P (both)<br>F: 1>2:P2P; 2>1:P2P (both) | I: 1>2:host/srflx; 2>1:srflx/prflx → 1>2:host/srflx; 2>1:srflx/host<br>F: 1>2:host/srflx; 2>1:srflx/prflx → 1>2:host/srflx; 2>1:srflx/host | 1>2:1.008→0.603; 2>1:1.011→0.604 | B [12341522480](https://github.com/netbirdio/proxbird-tests/actions/runs/39588288742/artifacts/12341522480)<br>P [12345889105](https://github.com/netbirdio/proxbird-tests/actions/runs/39597620276/artifacts/12345889105) |
| `macos-macos-nat` | pass/pass | I: 1>2:P2P; 2>1:P2P (both)<br>F: 1>2:P2P; 2>1:P2P (both) | I: 1>2:srflx/srflx; 2>1:srflx/srflx → 1>2:host/srflx; 2>1:srflx/srflx<br>F: 1>2:srflx/srflx; 2>1:srflx/srflx → 1>2:host/srflx; 2>1:srflx/srflx | 1>2:0.607→0.629; 2>1:0.607→0.628 | B [12342402445](https://github.com/netbirdio/proxbird-tests/actions/runs/39588288742/artifacts/12342402445)<br>P [12345808790](https://github.com/netbirdio/proxbird-tests/actions/runs/39597620276/artifacts/12345808790) |
| `macos-macos-relay` | pass/pass | I: 1>2:Relayed; 2>1:Relayed (both)<br>F: 1>2:Relayed; 2>1:Relayed (both) | I: 1>2:-/-; 2>1:-/- (both)<br>F: 1>2:-/-; 2>1:-/- (both) | 1>2:unmeasured→unmeasured; 2>1:unmeasured→unmeasured | B [12342342613](https://github.com/netbirdio/proxbird-tests/actions/runs/39588288742/artifacts/12342342613)<br>P [12345834542](https://github.com/netbirdio/proxbird-tests/actions/runs/39597620276/artifacts/12345834542) |
| `macos-macos-slow` | pass/pass | I: 1>2:P2P; 2>1:P2P (both)<br>F: 1>2:P2P; 2>1:P2P (both) | I: 1>2:srflx/srflx; 2>1:srflx/srflx → 1>2:srflx/srflx; 2>1:host/srflx<br>F: 1>2:srflx/srflx; 2>1:srflx/srflx → 1>2:srflx/srflx; 2>1:host/srflx | 1>2:0.703→0.704; 2>1:0.905→0.905 | B [12341573505](https://github.com/netbirdio/proxbird-tests/actions/runs/39588288742/artifacts/12341573505)<br>P [12345329898](https://github.com/netbirdio/proxbird-tests/actions/runs/39597620276/artifacts/12345329898) |
| `macos-windows-direct` | pass/pass | I: 1>2:P2P; 2>1:P2P (both)<br>F: 1>2:P2P; 2>1:P2P (both) | I: 1>2:host/prflx; 2>1:host/host (both)<br>F: 1>2:host/prflx; 2>1:host/host (both) | 1>2:1.011→0.015; 2>1:1.004→0.002 | B [12341193306](https://github.com/netbirdio/proxbird-tests/actions/runs/39588288742/artifacts/12341193306)<br>P [12345564980](https://github.com/netbirdio/proxbird-tests/actions/runs/39597620276/artifacts/12345564980) |
| `macos-windows-nat` | pass/pass | I: 1>2:P2P; 2>1:P2P (both)<br>F: 1>2:P2P; 2>1:P2P (both) | I: 1>2:srflx/srflx; 2>1:srflx/srflx → 1>2:host/srflx; 2>1:srflx/srflx<br>F: 1>2:srflx/srflx; 2>1:srflx/srflx → 1>2:host/srflx; 2>1:srflx/srflx | 1>2:0.612→0.611; 2>1:0.605→0.604 | B [12342137990](https://github.com/netbirdio/proxbird-tests/actions/runs/39588288742/artifacts/12342137990)<br>P [12346880490](https://github.com/netbirdio/proxbird-tests/actions/runs/39597620276/artifacts/12346880490) |
| `macos-windows-relay` | pass/pass | I: 1>2:Relayed; 2>1:Relayed (both)<br>F: 1>2:Relayed; 2>1:Relayed (both) | I: 1>2:-/-; 2>1:-/- (both)<br>F: 1>2:-/-; 2>1:-/- (both) | 1>2:unmeasured→unmeasured; 2>1:unmeasured→unmeasured | B [12341732793](https://github.com/netbirdio/proxbird-tests/actions/runs/39588288742/artifacts/12341732793)<br>P [12345934164](https://github.com/netbirdio/proxbird-tests/actions/runs/39597620276/artifacts/12345934164) |
| `macos-windows-slow` | pass/pass | I: 1>2:P2P; 2>1:P2P (both)<br>F: 1>2:P2P; 2>1:P2P (both) | I: 1>2:srflx/srflx; 2>1:srflx/srflx → 1>2:srflx/srflx; 2>1:host/srflx<br>F: 1>2:srflx/srflx; 2>1:srflx/srflx → 1>2:srflx/srflx; 2>1:host/srflx | 1>2:0.707→0.702; 2>1:0.704→0.899 | B [12342112840](https://github.com/netbirdio/proxbird-tests/actions/runs/39588288742/artifacts/12342112840)<br>P [12346422368](https://github.com/netbirdio/proxbird-tests/actions/runs/39597620276/artifacts/12346422368) |
| `recovery-freebsd-nat-daemon-restart` | pass/pass | I: 1>2:P2P; 2>1:P2P (both)<br>F: 1>2:P2P; 2>1:P2P (both) | I: 1>2:srflx/srflx; 2>1:srflx/srflx → 1>2:host/srflx; 2>1:srflx/srflx<br>F: 1>2:srflx/srflx; 2>1:srflx/srflx → 1>2:host/prflx; 2>1:host/srflx | 1>2:0.604→0.615; 2>1:0.604→0.616 | B [12341379155](https://github.com/netbirdio/proxbird-tests/actions/runs/39588288742/artifacts/12341379155)<br>P [12346258720](https://github.com/netbirdio/proxbird-tests/actions/runs/39597620276/artifacts/12346258720) |
| `recovery-freebsd-nat-path-failure` | pass/pass | I: 1>2:P2P; 2>1:P2P (both)<br>F: 1>2:Relayed; 2>1:Relayed (both) | I: 1>2:srflx/srflx; 2>1:srflx/srflx → 1>2:srflx/srflx; 2>1:host/srflx<br>F: 1>2:-/-; 2>1:-/- (both) | 1>2:0.603→0.603; 2>1:0.605→0.605 | B [12341608003](https://github.com/netbirdio/proxbird-tests/actions/runs/39588288742/artifacts/12341608003)<br>P [12347185358](https://github.com/netbirdio/proxbird-tests/actions/runs/39597620276/artifacts/12347185358) |
| `recovery-linux-nat-daemon-restart` | pass/pass | I: 1>2:P2P; 2>1:P2P (both)<br>F: 1>2:P2P; 2>1:P2P (both) | I: 1>2:srflx/srflx; 2>1:srflx/srflx → 1>2:srflx/srflx; 2>1:host/srflx<br>F: 1>2:host/srflx; 2>1:srflx/prflx → 1>2:host/srflx; 2>1:host/prflx | 1>2:0.604→0.604; 2>1:0.605→0.605 | B [12341733274](https://github.com/netbirdio/proxbird-tests/actions/runs/39588288742/artifacts/12341733274)<br>P [12346114755](https://github.com/netbirdio/proxbird-tests/actions/runs/39597620276/artifacts/12346114755) |
| `recovery-linux-nat-path-failure` | pass/pass | I: 1>2:P2P; 2>1:P2P (both)<br>F: 1>2:Relayed; 2>1:Relayed (both) | I: 1>2:srflx/srflx; 2>1:srflx/srflx → 1>2:host/srflx; 2>1:srflx/srflx<br>F: 1>2:-/-; 2>1:-/- (both) | 1>2:0.604→0.604; 2>1:0.605→0.605 | B [12341354543](https://github.com/netbirdio/proxbird-tests/actions/runs/39588288742/artifacts/12341354543)<br>P [12346841147](https://github.com/netbirdio/proxbird-tests/actions/runs/39597620276/artifacts/12346841147) |
| `recovery-macos-nat-daemon-restart` | pass/pass | I: 1>2:P2P; 2>1:P2P (both)<br>F: 1>2:P2P; 2>1:P2P (both) | I: 1>2:srflx/srflx; 2>1:srflx/srflx → 1>2:srflx/srflx; 2>1:host/srflx<br>F: 1>2:host/srflx; 2>1:srflx/prflx → 1>2:srflx/prflx; 2>1:host/srflx | 1>2:0.604→0.604; 2>1:0.605→0.606 | B [12341808921](https://github.com/netbirdio/proxbird-tests/actions/runs/39588288742/artifacts/12341808921)<br>P [12347455296](https://github.com/netbirdio/proxbird-tests/actions/runs/39597620276/artifacts/12347455296) |
| `recovery-macos-nat-path-failure` | pass/pass | I: 1>2:P2P; 2>1:P2P (both)<br>F: 1>2:Relayed; 2>1:Relayed (both) | I: 1>2:host/srflx; 2>1:srflx/prflx → 1>2:host/srflx; 2>1:srflx/srflx<br>F: 1>2:-/-; 2>1:-/- (both) | 1>2:22.425→0.606; 2>1:22.427→0.606 | B [12341264106](https://github.com/netbirdio/proxbird-tests/actions/runs/39588288742/artifacts/12341264106)<br>P [12346229646](https://github.com/netbirdio/proxbird-tests/actions/runs/39597620276/artifacts/12346229646) |
| `recovery-windows-nat-daemon-restart` | pass/pass | I: 1>2:P2P; 2>1:P2P (both)<br>F: 1>2:P2P; 2>1:P2P (both) | I: 1>2:srflx/srflx; 2>1:srflx/srflx → 1>2:srflx/srflx; 2>1:host/srflx<br>F: 1>2:host/srflx; 2>1:srflx/prflx → 1>2:srflx/srflx; 2>1:host/srflx | 1>2:0.604→0.604; 2>1:0.611→0.612 | B [12341299068](https://github.com/netbirdio/proxbird-tests/actions/runs/39588288742/artifacts/12341299068)<br>P [12347655132](https://github.com/netbirdio/proxbird-tests/actions/runs/39597620276/artifacts/12347655132) |
| `recovery-windows-nat-path-failure` | pass/pass | I: 1>2:P2P; 2>1:P2P (both)<br>F: 1>2:Relayed; 2>1:Relayed (both) | I: 1>2:srflx/srflx; 2>1:srflx/srflx → 1>2:srflx/srflx; 2>1:host/srflx<br>F: 1>2:-/-; 2>1:-/- (both) | 1>2:0.606→0.604; 2>1:0.610→0.611 | B [12342713738](https://github.com/netbirdio/proxbird-tests/actions/runs/39588288742/artifacts/12342713738)<br>P [12345899930](https://github.com/netbirdio/proxbird-tests/actions/runs/39597620276/artifacts/12345899930) |
| `routing-ha-freebsd-freebsd-nat-router-ha` | pass/pass | I: 1>2:P2P; 1>3:P2P; 2>1:P2P; 2>3:P2P; 3>1:P2P; 3>2:P2P (both)<br>F: 1>2R:P2P; 1>3:P2P; 2>1:P2P; 2>3:-(Idle); 3>1:P2P; 3>2R:-(Idle) (both) | I: 1>2:srflx/srflx; 1>3:srflx/srflx; 2>1:srflx/srflx; 2>3:host/host; 3>1:srflx/srflx; 3>2:host/prflx → 1>2:host/srflx; 1>3:srflx/srflx; 2>1:srflx/srflx; 2>3:srflx/host; 3>1:host/srflx; 3>2:host/prflx<br>F: 1>2R:host/srflx; 1>3:srflx/srflx; 2>1:srflx/prflx; 2>3:-/-; 3>1:srflx/srflx; 3>2R:-/- → 1>2R:host/srflx; 1>3:srflx/srflx; 2>1:host/prflx; 2>3:-/-; 3>1:host/srflx; 3>2R:-/- | 1>2:0.622→0.624; 1>2R:1.004→1.045; 1>3:0.612→0.623; 2>1:0.623→0.625; 2>3:0.002→1.032; 3>1:0.613→0.624; 3>2:0.002→1.032 | B [12342123979](https://github.com/netbirdio/proxbird-tests/actions/runs/39588288742/artifacts/12342123979)<br>P [12347226479](https://github.com/netbirdio/proxbird-tests/actions/runs/39597620276/artifacts/12347226479) |
| `routing-ha-freebsd-freebsd-relay-router-ha` | pass/pass | I: 1>2:Relayed; 1>3:Relayed; 2>1:Relayed; 2>3:P2P; 3>1:Relayed; 3>2:P2P (both)<br>F: 1>2R:Relayed; 1>3:Relayed; 2>1:Relayed; 2>3:-(Idle); 3>1:Relayed; 3>2R:-(Idle) (both) | I: 1>2:-/-; 1>3:-/-; 2>1:-/-; 2>3:host/host; 3>1:-/-; 3>2:host/prflx → 1>2:-/-; 1>3:-/-; 2>1:-/-; 2>3:host/host; 3>1:-/-; 3>2:host/host<br>F: 1>2R:-/-; 1>3:-/-; 2>1:-/-; 2>3:-/-; 3>1:-/-; 3>2R:-/- (both) | 1>2:unmeasured→unmeasured; 1>2R:unmeasured→unmeasured; 1>3:unmeasured→unmeasured; 2>1:unmeasured→unmeasured; 2>3:0.002→0.002; 3>1:unmeasured→unmeasured; 3>2:0.003→0.002 | B [12342244410](https://github.com/netbirdio/proxbird-tests/actions/runs/39588288742/artifacts/12342244410)<br>P [12347286224](https://github.com/netbirdio/proxbird-tests/actions/runs/39597620276/artifacts/12347286224) |
| `routing-ha-freebsd-linux-nat-router-ha` | pass/pass | I: 1>2:P2P; 1>3:P2P; 2>1:P2P; 2>3:P2P; 3>1:P2P; 3>2:P2P (both)<br>F: 1>2R:P2P; 1>3:P2P; 2>1:P2P; 2>3:-(Idle); 3>1:P2P; 3>2R:-(Idle) (both) | I: 1>2:srflx/srflx; 1>3:srflx/srflx; 2>1:srflx/srflx; 2>3:host/host; 3>1:srflx/srflx; 3>2:host/host → 1>2:srflx/prflx; 1>3:host/srflx; 2>1:host/srflx; 2>3:host/host; 3>1:srflx/srflx; 3>2:host/host<br>F: 1>2R:host/srflx; 1>3:srflx/srflx; 2>1:srflx/prflx; 2>3:-/-; 3>1:srflx/srflx; 3>2R:-/- → 1>2R:host/srflx; 1>3:host/srflx; 2>1:srflx/prflx; 2>3:-/-; 3>1:srflx/srflx; 3>2R:-/- | 1>2:0.603→21.147; 1>2R:0.603→0.603; 1>3:20.555→0.605; 2>1:0.605→21.149; 2>3:0.002→0.002; 3>1:20.557→0.604; 3>2:0.002→0.001 | B [12342674276](https://github.com/netbirdio/proxbird-tests/actions/runs/39588288742/artifacts/12342674276)<br>P [12347820615](https://github.com/netbirdio/proxbird-tests/actions/runs/39597620276/artifacts/12347820615) |
| `routing-ha-freebsd-linux-relay-router-ha` | pass/pass | I: 1>2:Relayed; 1>3:Relayed; 2>1:Relayed; 2>3:P2P; 3>1:Relayed; 3>2:P2P (both)<br>F: 1>2R:Relayed; 1>3:Relayed; 2>1:Relayed; 2>3:-(Idle); 3>1:Relayed; 3>2R:-(Idle) (both) | I: 1>2:-/-; 1>3:-/-; 2>1:-/-; 2>3:host/host; 3>1:-/-; 3>2:host/prflx (both)<br>F: 1>2R:-/-; 1>3:-/-; 2>1:-/-; 2>3:-/-; 3>1:-/-; 3>2R:-/- (both) | 1>2:unmeasured→unmeasured; 1>2R:unmeasured→unmeasured; 1>3:unmeasured→unmeasured; 2>1:unmeasured→unmeasured; 2>3:0.001→0.001; 3>1:unmeasured→unmeasured; 3>2:0.002→0.002 | B [12343020042](https://github.com/netbirdio/proxbird-tests/actions/runs/39588288742/artifacts/12343020042)<br>P [12347186988](https://github.com/netbirdio/proxbird-tests/actions/runs/39597620276/artifacts/12347186988) |
| `routing-ha-freebsd-macos-nat-router-ha` | pass/pass | I: 1>2:P2P; 1>3:P2P; 2>1:P2P; 2>3:P2P; 3>1:P2P; 3>2:P2P (both)<br>F: 1>2R:P2P; 1>3:P2P; 2>1:P2P; 2>3:-(Idle); 3>1:P2P; 3>2R:-(Idle) (both) | I: 1>2:srflx/srflx; 1>3:srflx/srflx; 2>1:srflx/srflx; 2>3:host/host; 3>1:srflx/srflx; 3>2:host/host → 1>2:srflx/srflx; 1>3:host/srflx; 2>1:host/srflx; 2>3:host/prflx; 3>1:srflx/srflx; 3>2:host/host<br>F: 1>2R:srflx/srflx; 1>3:srflx/srflx; 2>1:srflx/prflx; 2>3:-/-; 3>1:srflx/srflx; 3>2R:-/- → 1>2R:host/srflx; 1>3:host/srflx; 2>1:host/prflx; 2>3:-/-; 3>1:srflx/srflx; 3>2R:-/- | 1>2:0.604→0.620; 1>2R:0.604→1.016; 1>3:0.606→0.604; 2>1:0.606→0.621; 2>3:0.001→1.030; 3>1:0.607→0.605; 3>2:0.002→1.031 | B [12343280139](https://github.com/netbirdio/proxbird-tests/actions/runs/39588288742/artifacts/12343280139)<br>P [12346573922](https://github.com/netbirdio/proxbird-tests/actions/runs/39597620276/artifacts/12346573922) |
| `routing-ha-freebsd-macos-relay-router-ha` | pass/pass | I: 1>2:Relayed; 1>3:Relayed; 2>1:Relayed; 2>3:P2P; 3>1:Relayed; 3>2:P2P (both)<br>F: 1>2R:Relayed; 1>3:Relayed; 2>1:Relayed; 2>3:-(Idle); 3>1:Relayed; 3>2R:-(Idle) (both) | I: 1>2:-/-; 1>3:-/-; 2>1:-/-; 2>3:host/host; 3>1:-/-; 3>2:host/host (both)<br>F: 1>2R:-/-; 1>3:-/-; 2>1:-/-; 2>3:-/-; 3>1:-/-; 3>2R:-/- (both) | 1>2:unmeasured→unmeasured; 1>2R:unmeasured→unmeasured; 1>3:unmeasured→unmeasured; 2>1:unmeasured→unmeasured; 2>3:0.002→0.002; 3>1:unmeasured→unmeasured; 3>2:0.001→0.003 | B [12341719764](https://github.com/netbirdio/proxbird-tests/actions/runs/39588288742/artifacts/12341719764)<br>P [12347800971](https://github.com/netbirdio/proxbird-tests/actions/runs/39597620276/artifacts/12347800971) |
| `routing-ha-freebsd-windows-nat-router-ha` | pass/pass | I: 1>2:P2P; 1>3:P2P; 2>1:P2P; 2>3:P2P; 3>1:P2P; 3>2:P2P (both)<br>F: 1>2R:P2P; 1>3:P2P; 2>1:P2P; 2>3:-(Idle); 3>1:P2P; 3>2R:-(Idle) (both) | I: 1>2:srflx/srflx; 1>3:srflx/srflx; 2>1:srflx/srflx; 2>3:srflx/host; 3>1:srflx/srflx; 3>2:host/prflx → 1>2:srflx/srflx; 1>3:srflx/srflx; 2>1:host/srflx; 2>3:host/host; 3>1:host/srflx; 3>2:host/prflx<br>F: 1>2R:srflx/srflx; 1>3:srflx/srflx; 2>1:srflx/prflx; 2>3:-/-; 3>1:srflx/srflx; 3>2R:-/- → 1>2R:host/srflx; 1>3:srflx/srflx; 2>1:srflx/prflx; 2>3:-/-; 3>1:host/srflx; 3>2R:-/- | 1>2:0.605→0.604; 1>2R:1.094→0.656; 1>3:0.604→0.604; 2>1:0.610→0.611; 2>3:1.035→0.001; 3>1:0.610→0.610; 3>2:1.036→0.002 | B [12341979890](https://github.com/netbirdio/proxbird-tests/actions/runs/39588288742/artifacts/12341979890)<br>P [12347895788](https://github.com/netbirdio/proxbird-tests/actions/runs/39597620276/artifacts/12347895788) |
| `routing-ha-freebsd-windows-relay-router-ha` | pass/pass | I: 1>2:Relayed; 1>3:Relayed; 2>1:Relayed; 2>3:P2P; 3>1:Relayed; 3>2:P2P (both)<br>F: 1>2R:Relayed; 1>3:Relayed; 2>1:Relayed; 2>3:-(Idle); 3>1:Relayed; 3>2R:-(Idle) (both) | I: 1>2:-/-; 1>3:-/-; 2>1:-/-; 2>3:host/host; 3>1:-/-; 3>2:host/prflx (both)<br>F: 1>2R:-/-; 1>3:-/-; 2>1:-/-; 2>3:-/-; 3>1:-/-; 3>2R:-/- (both) | 1>2:unmeasured→unmeasured; 1>2R:unmeasured→unmeasured; 1>3:unmeasured→unmeasured; 2>1:unmeasured→unmeasured; 2>3:0.001→0.001; 3>1:unmeasured→unmeasured; 3>2:0.002→0.002 | B [12342459433](https://github.com/netbirdio/proxbird-tests/actions/runs/39588288742/artifacts/12342459433)<br>P [12347027288](https://github.com/netbirdio/proxbird-tests/actions/runs/39597620276/artifacts/12347027288) |
| `routing-ha-linux-freebsd-nat-router-ha` | pass/pass | I: 1>2:P2P; 1>3:P2P; 2>1:P2P; 2>3:P2P; 3>1:P2P; 3>2:P2P (both)<br>F: 1>2R:P2P; 1>3:P2P; 2>1:P2P; 2>3:-(Idle); 3>1:P2P; 3>2R:-(Idle) (both) | I: 1>2:srflx/srflx; 1>3:srflx/srflx; 2>1:srflx/srflx; 2>3:host/prflx; 3>1:srflx/srflx; 3>2:host/host → 1>2:host/srflx; 1>3:srflx/srflx; 2>1:srflx/srflx; 2>3:srflx/host; 3>1:host/srflx; 3>2:host/prflx<br>F: 1>2R:srflx/prflx; 1>3:srflx/srflx; 2>1:host/srflx; 2>3:-/-; 3>1:srflx/srflx; 3>2R:-/- → 1>2R:srflx/srflx; 1>3:srflx/srflx; 2>1:host/srflx; 2>3:-/-; 3>1:host/srflx; 3>2R:-/- | 1>2:0.604→0.624; 1>2R:0.603→0.603; 1>3:0.603→0.603; 2>1:0.605→0.625; 2>3:0.002→1.007; 3>1:0.604→0.604; 3>2:0.003→1.007 | B [12343895149](https://github.com/netbirdio/proxbird-tests/actions/runs/39588288742/artifacts/12343895149)<br>P [12347437155](https://github.com/netbirdio/proxbird-tests/actions/runs/39597620276/artifacts/12347437155) |
| `routing-ha-linux-freebsd-relay-router-ha` | pass/pass | I: 1>2:Relayed; 1>3:Relayed; 2>1:Relayed; 2>3:P2P; 3>1:Relayed; 3>2:P2P (both)<br>F: 1>2R:Relayed; 1>3:Relayed; 2>1:Relayed; 2>3:-(Idle); 3>1:Relayed; 3>2R:-(Idle) (both) | I: 1>2:-/-; 1>3:-/-; 2>1:-/-; 2>3:host/host; 3>1:-/-; 3>2:host/prflx → 1>2:-/-; 1>3:-/-; 2>1:-/-; 2>3:host/host; 3>1:-/-; 3>2:host/host<br>F: 1>2R:-/-; 1>3:-/-; 2>1:-/-; 2>3:-/-; 3>1:-/-; 3>2R:-/- (both) | 1>2:unmeasured→unmeasured; 1>2R:unmeasured→unmeasured; 1>3:unmeasured→unmeasured; 2>1:unmeasured→unmeasured; 2>3:1.006→0.002; 3>1:unmeasured→unmeasured; 3>2:1.006→0.004 | B [12342749776](https://github.com/netbirdio/proxbird-tests/actions/runs/39588288742/artifacts/12342749776)<br>P [12346902470](https://github.com/netbirdio/proxbird-tests/actions/runs/39597620276/artifacts/12346902470) |
| `routing-ha-linux-linux-nat-router-ha` | pass/pass | I: 1>2:P2P; 1>3:P2P; 2>1:P2P; 2>3:P2P; 3>1:P2P; 3>2:P2P (both)<br>F: 1>2R:P2P; 1>3:P2P; 2>1:P2P; 2>3:-(Idle); 3>1:P2P; 3>2R:-(Idle) (both) | I: 1>2:srflx/srflx; 1>3:srflx/srflx; 2>1:srflx/srflx; 2>3:host/host; 3>1:srflx/srflx; 3>2:host/prflx → 1>2:host/srflx; 1>3:host/srflx; 2>1:srflx/srflx; 2>3:host/host; 3>1:srflx/srflx; 3>2:host/prflx<br>F: 1>2R:srflx/srflx; 1>3:srflx/srflx; 2>1:srflx/srflx; 2>3:-/-; 3>1:srflx/srflx; 3>2R:-/- → 1>2R:host/srflx; 1>3:host/srflx; 2>1:srflx/prflx; 2>3:-/-; 3>1:srflx/srflx; 3>2R:-/- | 1>2:0.604→0.604; 1>2R:0.604→0.604; 1>3:0.604→0.603; 2>1:0.605→0.604; 2>3:0.001→1.007; 3>1:0.605→0.604; 3>2:0.003→1.008 | B [12343965299](https://github.com/netbirdio/proxbird-tests/actions/runs/39588288742/artifacts/12343965299)<br>P [12346778165](https://github.com/netbirdio/proxbird-tests/actions/runs/39597620276/artifacts/12346778165) |
| `routing-ha-linux-linux-relay-router-ha` | pass/pass | I: 1>2:Relayed; 1>3:Relayed; 2>1:Relayed; 2>3:P2P; 3>1:Relayed; 3>2:P2P (both)<br>F: 1>2R:Relayed; 1>3:Relayed; 2>1:Relayed; 2>3:-(Idle); 3>1:Relayed; 3>2R:-(Idle) (both) | I: 1>2:-/-; 1>3:-/-; 2>1:-/-; 2>3:host/host; 3>1:-/-; 3>2:host/prflx → 1>2:-/-; 1>3:-/-; 2>1:-/-; 2>3:host/host; 3>1:-/-; 3>2:host/host<br>F: 1>2R:-/-; 1>3:-/-; 2>1:-/-; 2>3:-/-; 3>1:-/-; 3>2R:-/- (both) | 1>2:unmeasured→unmeasured; 1>2R:unmeasured→unmeasured; 1>3:unmeasured→unmeasured; 2>1:unmeasured→unmeasured; 2>3:0.001→0.002; 3>1:unmeasured→unmeasured; 3>2:0.002→0.003 | B [12342996420](https://github.com/netbirdio/proxbird-tests/actions/runs/39588288742/artifacts/12342996420)<br>P [12346947945](https://github.com/netbirdio/proxbird-tests/actions/runs/39597620276/artifacts/12346947945) |
| `routing-ha-linux-macos-nat-router-ha` | pass/pass | I: 1>2:P2P; 1>3:P2P; 2>1:P2P; 2>3:P2P; 3>1:P2P; 3>2:P2P (both)<br>F: 1>2R:P2P; 1>3:P2P; 2>1:P2P; 2>3:-(Idle); 3>1:P2P; 3>2R:-(Idle) (both) | I: 1>2:srflx/srflx; 1>3:srflx/srflx; 2>1:srflx/srflx; 2>3:host/host; 3>1:srflx/srflx; 3>2:host/prflx → 1>2:srflx/srflx; 1>3:srflx/srflx; 2>1:host/srflx; 2>3:host/host; 3>1:host/srflx; 3>2:host/prflx<br>F: 1>2R:host/srflx; 1>3:srflx/srflx; 2>1:srflx/prflx; 2>3:-/-; 3>1:srflx/srflx; 3>2R:-/- → 1>2R:srflx/srflx; 1>3:srflx/srflx; 2>1:host/srflx; 2>3:-/-; 3>1:host/srflx; 3>2R:-/- | 1>2:0.610→0.604; 1>2R:0.605→0.604; 1>3:0.603→0.603; 2>1:0.611→0.606; 2>3:0.001→1.005; 3>1:0.605→0.603; 3>2:0.003→1.005 | B [12343681042](https://github.com/netbirdio/proxbird-tests/actions/runs/39588288742/artifacts/12343681042)<br>P [12346967941](https://github.com/netbirdio/proxbird-tests/actions/runs/39597620276/artifacts/12346967941) |
| `routing-ha-linux-macos-relay-router-ha` | pass/pass | I: 1>2:Relayed; 1>3:Relayed; 2>1:Relayed; 2>3:P2P; 3>1:Relayed; 3>2:P2P (both)<br>F: 1>2R:Relayed; 1>3:Relayed; 2>1:Relayed; 2>3:-(Idle); 3>1:Relayed; 3>2R:-(Idle) (both) | I: 1>2:-/-; 1>3:-/-; 2>1:-/-; 2>3:host/host; 3>1:-/-; 3>2:host/prflx → 1>2:-/-; 1>3:-/-; 2>1:-/-; 2>3:host/prflx; 3>1:-/-; 3>2:host/host<br>F: 1>2R:-/-; 1>3:-/-; 2>1:-/-; 2>3:-/-; 3>1:-/-; 3>2R:-/- (both) | 1>2:unmeasured→unmeasured; 1>2R:unmeasured→unmeasured; 1>3:unmeasured→unmeasured; 2>1:unmeasured→unmeasured; 2>3:0.001→0.001; 3>1:unmeasured→unmeasured; 3>2:0.003→0.003 | B [12342977038](https://github.com/netbirdio/proxbird-tests/actions/runs/39588288742/artifacts/12342977038)<br>P [12347058559](https://github.com/netbirdio/proxbird-tests/actions/runs/39597620276/artifacts/12347058559) |
| `routing-ha-linux-windows-nat-router-ha` | pass/pass | I: 1>2:P2P; 1>3:P2P; 2>1:P2P; 2>3:P2P; 3>1:P2P; 3>2:P2P (both)<br>F: 1>2R:P2P; 1>3:P2P; 2>1:P2P; 2>3:-(Idle); 3>1:P2P; 3>2R:-(Idle) (both) | I: 1>2:srflx/srflx; 1>3:srflx/srflx; 2>1:srflx/srflx; 2>3:host/host; 3>1:srflx/srflx; 3>2:host/prflx → 1>2:srflx/srflx; 1>3:host/srflx; 2>1:host/srflx; 2>3:host/prflx; 3>1:srflx/srflx; 3>2:host/host<br>F: 1>2R:srflx/srflx; 1>3:srflx/srflx; 2>1:srflx/prflx; 2>3:-/-; 3>1:srflx/srflx; 3>2R:-/- → 1>2R:host/srflx; 1>3:host/srflx; 2>1:host/prflx; 2>3:-/-; 3>1:srflx/srflx; 3>2R:-/- | 1>2:0.604→0.605; 1>2R:1.014→1.007; 1>3:0.604→0.603; 2>1:0.611→0.612; 2>3:0.002→1.006; 3>1:0.609→0.610; 3>2:0.002→1.006 | B [12343451472](https://github.com/netbirdio/proxbird-tests/actions/runs/39588288742/artifacts/12343451472)<br>P [12347657345](https://github.com/netbirdio/proxbird-tests/actions/runs/39597620276/artifacts/12347657345) |
| `routing-ha-linux-windows-relay-router-ha` | pass/pass | I: 1>2:Relayed; 1>3:Relayed; 2>1:Relayed; 2>3:P2P; 3>1:Relayed; 3>2:P2P (both)<br>F: 1>2R:Relayed; 1>3:Relayed; 2>1:Relayed; 2>3:-(Idle); 3>1:Relayed; 3>2R:-(Idle) (both) | I: 1>2:-/-; 1>3:-/-; 2>1:-/-; 2>3:host/host; 3>1:-/-; 3>2:host/prflx (both)<br>F: 1>2R:-/-; 1>3:-/-; 2>1:-/-; 2>3:-/-; 3>1:-/-; 3>2R:-/- (both) | 1>2:unmeasured→unmeasured; 1>2R:unmeasured→unmeasured; 1>3:unmeasured→unmeasured; 2>1:unmeasured→unmeasured; 2>3:1.005→1.005; 3>1:unmeasured→unmeasured; 3>2:1.007→1.007 | B [12344065894](https://github.com/netbirdio/proxbird-tests/actions/runs/39588288742/artifacts/12344065894)<br>P [12347697352](https://github.com/netbirdio/proxbird-tests/actions/runs/39597620276/artifacts/12347697352) |
| `routing-overlap-freebsd-freebsd-nat-overlap` | pass/pass | I: 1>2:P2P; 1>3:P2P; 2>1:P2P; 2>3:P2P; 3>1:P2P; 3>2:P2P (both)<br>F: 1>2:P2P; 1>3:P2P; 2>1:P2P; 2>3:P2P; 3>1:P2P; 3>2:P2P (both) | I: 1>2:srflx/srflx; 1>3:srflx/srflx; 2>1:srflx/srflx; 2>3:host/prflx; 3>1:srflx/srflx; 3>2:host/host → 1>2:srflx/srflx; 1>3:host/srflx; 2>1:host/srflx; 2>3:host/host; 3>1:srflx/srflx; 3>2:host/host<br>F: 1>2:srflx/srflx; 1>3:srflx/srflx; 2>1:srflx/srflx; 2>3:host/prflx; 3>1:srflx/srflx; 3>2:host/host → 1>2:srflx/srflx; 1>3:host/srflx; 2>1:host/srflx; 2>3:host/host; 3>1:srflx/srflx; 3>2:host/host | 1>2:0.616→0.625; 1>3:0.614→0.623; 2>1:0.616→0.625; 2>3:0.002→0.001; 3>1:0.615→0.623; 3>2:0.003→0.002 | B [12343191665](https://github.com/netbirdio/proxbird-tests/actions/runs/39588288742/artifacts/12343191665)<br>P [12347902988](https://github.com/netbirdio/proxbird-tests/actions/runs/39597620276/artifacts/12347902988) |
| `routing-overlap-freebsd-freebsd-relay-overlap` | pass/pass | I: 1>2:Relayed; 1>3:Relayed; 2>1:Relayed; 2>3:P2P; 3>1:Relayed; 3>2:P2P (both)<br>F: 1>2:Relayed; 1>3:Relayed; 2>1:Relayed; 2>3:P2P; 3>1:Relayed; 3>2:P2P (both) | I: 1>2:-/-; 1>3:-/-; 2>1:-/-; 2>3:host/host; 3>1:-/-; 3>2:host/prflx (both)<br>F: 1>2:-/-; 1>3:-/-; 2>1:-/-; 2>3:host/host; 3>1:-/-; 3>2:host/prflx (both) | 1>2:unmeasured→unmeasured; 1>3:unmeasured→unmeasured; 2>1:unmeasured→unmeasured; 2>3:1.013→0.002; 3>1:unmeasured→unmeasured; 3>2:1.014→0.002 | B [12343371900](https://github.com/netbirdio/proxbird-tests/actions/runs/39588288742/artifacts/12343371900)<br>P [12347632596](https://github.com/netbirdio/proxbird-tests/actions/runs/39597620276/artifacts/12347632596) |
| `routing-overlap-freebsd-linux-nat-overlap` | pass/pass | I: 1>2:P2P; 1>3:P2P; 2>1:P2P; 2>3:P2P; 3>1:P2P; 3>2:P2P (both)<br>F: 1>2:P2P; 1>3:P2P; 2>1:P2P; 2>3:P2P; 3>1:P2P; 3>2:P2P (both) | I: 1>2:srflx/srflx; 1>3:srflx/srflx; 2>1:srflx/srflx; 2>3:host/host; 3>1:srflx/srflx; 3>2:host/host → 1>2:srflx/srflx; 1>3:srflx/srflx; 2>1:host/srflx; 2>3:host/host; 3>1:host/srflx; 3>2:host/prflx<br>F: 1>2:srflx/srflx; 1>3:srflx/srflx; 2>1:srflx/srflx; 2>3:host/host; 3>1:srflx/srflx; 3>2:host/host → 1>2:srflx/srflx; 1>3:srflx/srflx; 2>1:host/srflx; 2>3:host/host; 3>1:host/srflx; 3>2:host/prflx | 1>2:0.603→0.626; 1>3:0.605→0.633; 2>1:0.604→0.627; 2>3:0.001→1.013; 3>1:0.606→0.633; 3>2:0.002→1.014 | B [12343267256](https://github.com/netbirdio/proxbird-tests/actions/runs/39588288742/artifacts/12343267256)<br>P [12347872506](https://github.com/netbirdio/proxbird-tests/actions/runs/39597620276/artifacts/12347872506) |
| `routing-overlap-freebsd-linux-relay-overlap` | pass/pass | I: 1>2:Relayed; 1>3:Relayed; 2>1:Relayed; 2>3:P2P; 3>1:Relayed; 3>2:P2P (both)<br>F: 1>2:Relayed; 1>3:Relayed; 2>1:Relayed; 2>3:P2P; 3>1:Relayed; 3>2:P2P (both) | I: 1>2:-/-; 1>3:-/-; 2>1:-/-; 2>3:host/host; 3>1:-/-; 3>2:host/host (both)<br>F: 1>2:-/-; 1>3:-/-; 2>1:-/-; 2>3:host/host; 3>1:-/-; 3>2:host/host (both) | 1>2:unmeasured→unmeasured; 1>3:unmeasured→unmeasured; 2>1:unmeasured→unmeasured; 2>3:0.002→0.001; 3>1:unmeasured→unmeasured; 3>2:0.002→0.002 | B [12344161343](https://github.com/netbirdio/proxbird-tests/actions/runs/39588288742/artifacts/12344161343)<br>P [12347498364](https://github.com/netbirdio/proxbird-tests/actions/runs/39597620276/artifacts/12347498364) |
| `routing-overlap-freebsd-macos-nat-overlap` | pass/pass | I: 1>2:P2P; 1>3:P2P; 2>1:P2P; 2>3:P2P; 3>1:P2P; 3>2:P2P (both)<br>F: 1>2:P2P; 1>3:P2P; 2>1:P2P; 2>3:P2P; 3>1:P2P; 3>2:P2P (both) | I: 1>2:srflx/srflx; 1>3:srflx/srflx; 2>1:srflx/srflx; 2>3:host/host; 3>1:srflx/srflx; 3>2:host/prflx → 1>2:host/srflx; 1>3:host/srflx; 2>1:srflx/srflx; 2>3:host/host; 3>1:srflx/srflx; 3>2:host/host<br>F: 1>2:srflx/srflx; 1>3:srflx/srflx; 2>1:srflx/srflx; 2>3:host/host; 3>1:srflx/srflx; 3>2:host/prflx → 1>2:host/srflx; 1>3:host/srflx; 2>1:srflx/srflx; 2>3:host/host; 3>1:srflx/srflx; 3>2:host/host | 1>2:0.605→0.604; 1>3:0.605→0.605; 2>1:0.607→0.605; 2>3:1.006→0.002; 3>1:0.606→0.606; 3>2:1.006→0.003 | B [12343816858](https://github.com/netbirdio/proxbird-tests/actions/runs/39588288742/artifacts/12343816858)<br>P [12347738034](https://github.com/netbirdio/proxbird-tests/actions/runs/39597620276/artifacts/12347738034) |
| `routing-overlap-freebsd-macos-relay-overlap` | pass/pass | I: 1>2:Relayed; 1>3:Relayed; 2>1:Relayed; 2>3:P2P; 3>1:Relayed; 3>2:P2P (both)<br>F: 1>2:Relayed; 1>3:Relayed; 2>1:Relayed; 2>3:P2P; 3>1:Relayed; 3>2:P2P (both) | I: 1>2:-/-; 1>3:-/-; 2>1:-/-; 2>3:host/host; 3>1:-/-; 3>2:host/host (both)<br>F: 1>2:-/-; 1>3:-/-; 2>1:-/-; 2>3:host/host; 3>1:-/-; 3>2:host/host (both) | 1>2:unmeasured→unmeasured; 1>3:unmeasured→unmeasured; 2>1:unmeasured→unmeasured; 2>3:0.002→0.002; 3>1:unmeasured→unmeasured; 3>2:0.002→0.001 | B [12343017710](https://github.com/netbirdio/proxbird-tests/actions/runs/39588288742/artifacts/12343017710)<br>P [12348402116](https://github.com/netbirdio/proxbird-tests/actions/runs/39597620276/artifacts/12348402116) |
| `routing-overlap-freebsd-windows-nat-overlap` | pass/pass | I: 1>2:P2P; 1>3:P2P; 2>1:P2P; 2>3:P2P; 3>1:P2P; 3>2:P2P (both)<br>F: 1>2:P2P; 1>3:P2P; 2>1:P2P; 2>3:P2P; 3>1:P2P; 3>2:P2P (both) | I: 1>2:srflx/srflx; 1>3:srflx/srflx; 2>1:srflx/srflx; 2>3:host/host; 3>1:srflx/srflx; 3>2:host/host → 1>2:srflx/srflx; 1>3:srflx/srflx; 2>1:host/srflx; 2>3:host/host; 3>1:host/srflx; 3>2:host/prflx<br>F: 1>2:srflx/srflx; 1>3:srflx/srflx; 2>1:srflx/srflx; 2>3:host/host; 3>1:srflx/srflx; 3>2:host/host → 1>2:srflx/srflx; 1>3:srflx/srflx; 2>1:host/srflx; 2>3:host/host; 3>1:host/srflx; 3>2:host/prflx | 1>2:0.604→0.604; 1>3:0.606→0.603; 2>1:0.608→0.610; 2>3:0.002→1.024; 3>1:0.612→0.609; 3>2:0.002→1.025 | B [12343032979](https://github.com/netbirdio/proxbird-tests/actions/runs/39588288742/artifacts/12343032979)<br>P [12347504078](https://github.com/netbirdio/proxbird-tests/actions/runs/39597620276/artifacts/12347504078) |
| `routing-overlap-freebsd-windows-relay-overlap` | pass/pass | I: 1>2:Relayed; 1>3:Relayed; 2>1:Relayed; 2>3:P2P; 3>1:Relayed; 3>2:P2P (both)<br>F: 1>2:Relayed; 1>3:Relayed; 2>1:Relayed; 2>3:P2P; 3>1:Relayed; 3>2:P2P (both) | I: 1>2:-/-; 1>3:-/-; 2>1:-/-; 2>3:host/host; 3>1:-/-; 3>2:host/host → 1>2:-/-; 1>3:-/-; 2>1:-/-; 2>3:host/host; 3>1:-/-; 3>2:host/prflx<br>F: 1>2:-/-; 1>3:-/-; 2>1:-/-; 2>3:host/host; 3>1:-/-; 3>2:host/host → 1>2:-/-; 1>3:-/-; 2>1:-/-; 2>3:host/host; 3>1:-/-; 3>2:host/prflx | 1>2:unmeasured→unmeasured; 1>3:unmeasured→unmeasured; 2>1:unmeasured→unmeasured; 2>3:0.001→0.001; 3>1:unmeasured→unmeasured; 3>2:0.002→0.002 | B [12343043067](https://github.com/netbirdio/proxbird-tests/actions/runs/39588288742/artifacts/12343043067)<br>P [12347783703](https://github.com/netbirdio/proxbird-tests/actions/runs/39597620276/artifacts/12347783703) |
| `routing-overlap-linux-freebsd-nat-overlap` | pass/pass | I: 1>2:P2P; 1>3:P2P; 2>1:P2P; 2>3:P2P; 3>1:P2P; 3>2:P2P (both)<br>F: 1>2:P2P; 1>3:P2P; 2>1:P2P; 2>3:P2P; 3>1:P2P; 3>2:P2P (both) | I: 1>2:srflx/srflx; 1>3:srflx/srflx; 2>1:srflx/srflx; 2>3:host/host; 3>1:srflx/srflx; 3>2:host/prflx → 1>2:srflx/srflx; 1>3:srflx/srflx; 2>1:host/srflx; 2>3:host/host; 3>1:host/srflx; 3>2:host/prflx<br>F: 1>2:srflx/srflx; 1>3:srflx/srflx; 2>1:srflx/srflx; 2>3:host/host; 3>1:srflx/srflx; 3>2:host/prflx → 1>2:srflx/srflx; 1>3:srflx/srflx; 2>1:host/srflx; 2>3:host/host; 3>1:host/srflx; 3>2:host/prflx | 1>2:0.604→0.602; 1>3:0.603→0.602; 2>1:0.606→0.604; 2>3:1.005→0.001; 3>1:0.604→0.604; 3>2:1.006→0.002 | B [12343827402](https://github.com/netbirdio/proxbird-tests/actions/runs/39588288742/artifacts/12343827402)<br>P [12348039055](https://github.com/netbirdio/proxbird-tests/actions/runs/39597620276/artifacts/12348039055) |
| `routing-overlap-linux-freebsd-relay-overlap` | pass/pass | I: 1>2:Relayed; 1>3:Relayed; 2>1:Relayed; 2>3:P2P; 3>1:Relayed; 3>2:P2P (both)<br>F: 1>2:Relayed; 1>3:Relayed; 2>1:Relayed; 2>3:P2P; 3>1:Relayed; 3>2:P2P (both) | I: 1>2:-/-; 1>3:-/-; 2>1:-/-; 2>3:host/host; 3>1:-/-; 3>2:host/prflx (both)<br>F: 1>2:-/-; 1>3:-/-; 2>1:-/-; 2>3:host/host; 3>1:-/-; 3>2:host/prflx (both) | 1>2:unmeasured→unmeasured; 1>3:unmeasured→unmeasured; 2>1:unmeasured→unmeasured; 2>3:1.005→1.007; 3>1:unmeasured→unmeasured; 3>2:1.006→1.008 | B [12342939237](https://github.com/netbirdio/proxbird-tests/actions/runs/39588288742/artifacts/12342939237)<br>P [12348327878](https://github.com/netbirdio/proxbird-tests/actions/runs/39597620276/artifacts/12348327878) |
| `routing-overlap-linux-linux-nat-overlap` | pass/pass | I: 1>2:P2P; 1>3:P2P; 2>1:P2P; 2>3:P2P; 3>1:P2P; 3>2:P2P (both)<br>F: 1>2:P2P; 1>3:P2P; 2>1:P2P; 2>3:P2P; 3>1:P2P; 3>2:P2P (both) | I: 1>2:srflx/srflx; 1>3:srflx/srflx; 2>1:srflx/srflx; 2>3:host/prflx; 3>1:srflx/srflx; 3>2:host/host → 1>2:srflx/srflx; 1>3:srflx/srflx; 2>1:host/srflx; 2>3:host/host; 3>1:host/srflx; 3>2:host/host<br>F: 1>2:srflx/srflx; 1>3:srflx/srflx; 2>1:srflx/srflx; 2>3:host/prflx; 3>1:srflx/srflx; 3>2:host/host → 1>2:srflx/srflx; 1>3:srflx/srflx; 2>1:host/srflx; 2>3:host/host; 3>1:host/srflx; 3>2:host/host | 1>2:0.605→0.603; 1>3:0.604→0.603; 2>1:0.605→0.605; 2>3:0.002→0.001; 3>1:0.605→0.605; 3>2:0.003→0.002 | B [12343907815](https://github.com/netbirdio/proxbird-tests/actions/runs/39588288742/artifacts/12343907815)<br>P [12348183660](https://github.com/netbirdio/proxbird-tests/actions/runs/39597620276/artifacts/12348183660) |
| `routing-overlap-linux-linux-relay-overlap` | pass/pass | I: 1>2:Relayed; 1>3:Relayed; 2>1:Relayed; 2>3:P2P; 3>1:Relayed; 3>2:P2P (both)<br>F: 1>2:Relayed; 1>3:Relayed; 2>1:Relayed; 2>3:P2P; 3>1:Relayed; 3>2:P2P (both) | I: 1>2:-/-; 1>3:-/-; 2>1:-/-; 2>3:host/host; 3>1:-/-; 3>2:host/prflx (both)<br>F: 1>2:-/-; 1>3:-/-; 2>1:-/-; 2>3:host/host; 3>1:-/-; 3>2:host/prflx (both) | 1>2:unmeasured→unmeasured; 1>3:unmeasured→unmeasured; 2>1:unmeasured→unmeasured; 2>3:1.005→0.001; 3>1:unmeasured→unmeasured; 3>2:1.006→0.002 | B [12343882660](https://github.com/netbirdio/proxbird-tests/actions/runs/39588288742/artifacts/12343882660)<br>P [12347969793](https://github.com/netbirdio/proxbird-tests/actions/runs/39597620276/artifacts/12347969793) |
| `routing-overlap-linux-macos-nat-overlap` | pass/pass | I: 1>2:P2P; 1>3:P2P; 2>1:P2P; 2>3:P2P; 3>1:P2P; 3>2:P2P (both)<br>F: 1>2:P2P; 1>3:P2P; 2>1:P2P; 2>3:P2P; 3>1:P2P; 3>2:P2P (both) | I: 1>2:srflx/srflx; 1>3:srflx/srflx; 2>1:srflx/srflx; 2>3:host/host; 3>1:srflx/srflx; 3>2:host/host → 1>2:srflx/srflx; 1>3:srflx/srflx; 2>1:host/srflx; 2>3:host/host; 3>1:host/srflx; 3>2:host/prflx<br>F: 1>2:srflx/srflx; 1>3:srflx/srflx; 2>1:srflx/srflx; 2>3:host/host; 3>1:srflx/srflx; 3>2:host/host → 1>2:srflx/srflx; 1>3:srflx/srflx; 2>1:host/srflx; 2>3:host/host; 3>1:host/srflx; 3>2:host/prflx | 1>2:0.605→0.605; 1>3:0.604→0.604; 2>1:0.606→0.605; 2>3:0.002→1.005; 3>1:0.605→0.605; 3>2:0.003→1.007 | B [12343863067](https://github.com/netbirdio/proxbird-tests/actions/runs/39588288742/artifacts/12343863067)<br>P [12348233740](https://github.com/netbirdio/proxbird-tests/actions/runs/39597620276/artifacts/12348233740) |
| `routing-overlap-linux-macos-relay-overlap` | pass/pass | I: 1>2:Relayed; 1>3:Relayed; 2>1:Relayed; 2>3:P2P; 3>1:Relayed; 3>2:P2P (both)<br>F: 1>2:Relayed; 1>3:Relayed; 2>1:Relayed; 2>3:P2P; 3>1:Relayed; 3>2:P2P (both) | I: 1>2:-/-; 1>3:-/-; 2>1:-/-; 2>3:host/prflx; 3>1:-/-; 3>2:host/host → 1>2:-/-; 1>3:-/-; 2>1:-/-; 2>3:host/host; 3>1:-/-; 3>2:host/prflx<br>F: 1>2:-/-; 1>3:-/-; 2>1:-/-; 2>3:host/prflx; 3>1:-/-; 3>2:host/host → 1>2:-/-; 1>3:-/-; 2>1:-/-; 2>3:host/host; 3>1:-/-; 3>2:host/prflx | 1>2:unmeasured→unmeasured; 1>3:unmeasured→unmeasured; 2>1:unmeasured→unmeasured; 2>3:0.002→1.005; 3>1:unmeasured→unmeasured; 3>2:0.004→1.007 | B [12344073381](https://github.com/netbirdio/proxbird-tests/actions/runs/39588288742/artifacts/12344073381)<br>P [12348194318](https://github.com/netbirdio/proxbird-tests/actions/runs/39597620276/artifacts/12348194318) |
| `routing-overlap-linux-windows-nat-overlap` | pass/pass | I: 1>2:P2P; 1>3:P2P; 2>1:P2P; 2>3:P2P; 3>1:P2P; 3>2:P2P (both)<br>F: 1>2:P2P; 1>3:P2P; 2>1:P2P; 2>3:P2P; 3>1:P2P; 3>2:P2P (both) | I: 1>2:srflx/srflx; 1>3:srflx/srflx; 2>1:srflx/srflx; 2>3:host/prflx; 3>1:srflx/srflx; 3>2:host/host → 1>2:srflx/srflx; 1>3:srflx/srflx; 2>1:host/srflx; 2>3:host/host; 3>1:host/srflx; 3>2:host/prflx<br>F: 1>2:srflx/srflx; 1>3:srflx/srflx; 2>1:srflx/srflx; 2>3:host/prflx; 3>1:srflx/srflx; 3>2:host/host → 1>2:srflx/srflx; 1>3:srflx/srflx; 2>1:host/srflx; 2>3:host/host; 3>1:host/srflx; 3>2:host/prflx | 1>2:0.605→0.604; 1>3:0.606→0.604; 2>1:0.612→0.620; 2>3:0.001→0.001; 3>1:0.612→0.610; 3>2:0.003→0.002 | B [12344238383](https://github.com/netbirdio/proxbird-tests/actions/runs/39588288742/artifacts/12344238383)<br>P [12349231137](https://github.com/netbirdio/proxbird-tests/actions/runs/39597620276/artifacts/12349231137) |
| `routing-overlap-linux-windows-relay-overlap` | pass/pass | I: 1>2:Relayed; 1>3:Relayed; 2>1:Relayed; 2>3:P2P; 3>1:Relayed; 3>2:P2P (both)<br>F: 1>2:Relayed; 1>3:Relayed; 2>1:Relayed; 2>3:P2P; 3>1:Relayed; 3>2:P2P (both) | I: 1>2:-/-; 1>3:-/-; 2>1:-/-; 2>3:host/host; 3>1:-/-; 3>2:host/prflx → 1>2:-/-; 1>3:-/-; 2>1:-/-; 2>3:host/host; 3>1:-/-; 3>2:host/host<br>F: 1>2:-/-; 1>3:-/-; 2>1:-/-; 2>3:host/host; 3>1:-/-; 3>2:host/prflx → 1>2:-/-; 1>3:-/-; 2>1:-/-; 2>3:host/host; 3>1:-/-; 3>2:host/host | 1>2:unmeasured→unmeasured; 1>3:unmeasured→unmeasured; 2>1:unmeasured→unmeasured; 2>3:1.004→0.002; 3>1:unmeasured→unmeasured; 3>2:1.004→0.003 | B [12344213368](https://github.com/netbirdio/proxbird-tests/actions/runs/39588288742/artifacts/12344213368)<br>P [12349781408](https://github.com/netbirdio/proxbird-tests/actions/runs/39597620276/artifacts/12349781408) |
| `windows-macos-direct` | pass/pass | I: 1>2:P2P; 2>1:P2P (both)<br>F: 1>2:P2P; 2>1:P2P (both) | I: 1>2:host/host; 2>1:host/prflx → 1>2:host/srflx; 2>1:host/prflx<br>F: 1>2:host/host; 2>1:host/prflx → 1>2:host/srflx; 2>1:host/prflx | 1>2:1.005→1.004; 2>1:1.012→1.010 | B [12344470088](https://github.com/netbirdio/proxbird-tests/actions/runs/39588288742/artifacts/12344470088)<br>P [12347579605](https://github.com/netbirdio/proxbird-tests/actions/runs/39597620276/artifacts/12347579605) |
| `windows-macos-nat` | pass/pass | I: 1>2:P2P; 2>1:P2P (both)<br>F: 1>2:P2P; 2>1:P2P (both) | I: 1>2:srflx/srflx; 2>1:srflx/srflx → 1>2:host/srflx; 2>1:srflx/srflx<br>F: 1>2:srflx/srflx; 2>1:srflx/srflx → 1>2:host/srflx; 2>1:srflx/srflx | 1>2:0.604→0.603; 2>1:0.611→0.608 | B [12344267668](https://github.com/netbirdio/proxbird-tests/actions/runs/39588288742/artifacts/12344267668)<br>P [12347804255](https://github.com/netbirdio/proxbird-tests/actions/runs/39597620276/artifacts/12347804255) |
| `windows-macos-relay` | pass/pass | I: 1>2:Relayed; 2>1:Relayed (both)<br>F: 1>2:Relayed; 2>1:Relayed (both) | I: 1>2:-/-; 2>1:-/- (both)<br>F: 1>2:-/-; 2>1:-/- (both) | 1>2:unmeasured→unmeasured; 2>1:unmeasured→unmeasured | B [12343304366](https://github.com/netbirdio/proxbird-tests/actions/runs/39588288742/artifacts/12343304366)<br>P [12348154491](https://github.com/netbirdio/proxbird-tests/actions/runs/39597620276/artifacts/12348154491) |
| `windows-macos-slow` | pass/pass | I: 1>2:P2P; 2>1:P2P (both)<br>F: 1>2:P2P; 2>1:P2P (both) | I: 1>2:srflx/srflx; 2>1:srflx/srflx → 1>2:srflx/srflx; 2>1:host/srflx<br>F: 1>2:srflx/srflx; 2>1:srflx/srflx → 1>2:srflx/srflx; 2>1:host/srflx | 1>2:0.703→0.703; 2>1:0.709→0.909 | B [12343384214](https://github.com/netbirdio/proxbird-tests/actions/runs/39588288742/artifacts/12343384214)<br>P [12348601755](https://github.com/netbirdio/proxbird-tests/actions/runs/39597620276/artifacts/12348601755) |
| `windows-windows-direct` | pass/pass | I: 1>2:P2P; 2>1:P2P (both)<br>F: 1>2:P2P; 2>1:P2P (both) | I: 1>2:host/host; 2>1:host/host (both)<br>F: 1>2:host/host; 2>1:host/host (both) | 1>2:0.003→0.404; 2>1:0.003→0.403 | B [12343094771](https://github.com/netbirdio/proxbird-tests/actions/runs/39588288742/artifacts/12343094771)<br>P [12348129502](https://github.com/netbirdio/proxbird-tests/actions/runs/39597620276/artifacts/12348129502) |
| `windows-windows-nat` | pass/pass | I: 1>2:P2P; 2>1:P2P (both)<br>F: 1>2:P2P; 2>1:P2P (both) | I: 1>2:srflx/srflx; 2>1:srflx/srflx → 1>2:host/srflx; 2>1:srflx/srflx<br>F: 1>2:srflx/srflx; 2>1:srflx/srflx → 1>2:host/srflx; 2>1:srflx/srflx | 1>2:0.607→0.605; 2>1:0.678→0.605 | B [12343848656](https://github.com/netbirdio/proxbird-tests/actions/runs/39588288742/artifacts/12343848656)<br>P [12349031398](https://github.com/netbirdio/proxbird-tests/actions/runs/39597620276/artifacts/12349031398) |
| `windows-windows-relay` | pass/pass | I: 1>2:Relayed; 2>1:Relayed (both)<br>F: 1>2:Relayed; 2>1:Relayed (both) | I: 1>2:-/-; 2>1:-/- (both)<br>F: 1>2:-/-; 2>1:-/- (both) | 1>2:unmeasured→unmeasured; 2>1:unmeasured→unmeasured | B [12344585735](https://github.com/netbirdio/proxbird-tests/actions/runs/39588288742/artifacts/12344585735)<br>P [12348661846](https://github.com/netbirdio/proxbird-tests/actions/runs/39597620276/artifacts/12348661846) |
| `windows-windows-slow` | pass/pass | I: 1>2:P2P; 2>1:P2P (both)<br>F: 1>2:P2P; 2>1:P2P (both) | I: 1>2:srflx/srflx; 2>1:srflx/srflx → 1>2:host/srflx; 2>1:srflx/srflx<br>F: 1>2:srflx/srflx; 2>1:srflx/srflx → 1>2:host/srflx; 2>1:srflx/srflx | 1>2:0.704→0.907; 2>1:0.906→0.908 | B [12344133648](https://github.com/netbirdio/proxbird-tests/actions/runs/39588288742/artifacts/12344133648)<br>P [12349041737](https://github.com/netbirdio/proxbird-tests/actions/runs/39597620276/artifacts/12349041737) |

### Investigated timing differences and stable evidence

These are single-run observations comparing baseline `1e63b68c4dc243a32fef823df1bc024c997a9c60` (run `39588288742`) with intermediate POC `37dab7d7124ea1de7a7e9bdfa5a3cd445f8413dc` (run `39597620276`). They do not validate subsequent lifecycle fixes. Each duration uses one node's clock and includes failed attempts and retry gaps from its first observed ICE dial to first success. This is not application-observed time to P2P or a repeated-run median. All line references below are one-based within the named native log member.

| Episode | Baseline | Intermediate POC | Evidence-supported interpretation |
| --- | ---: | ---: | --- |
| Linux modern → legacy 0.30.1, `client-linux-nat-connect-relay` | 0.605 s, one attempt | 29.127 s, three attempts | The legacy peer logs candidates arriving before agent initialization in both failed attempts. Third-attempt candidates follow initialization. |
| Windows modern → legacy 0.30.1, `client-windows-nat-dns` | 21.182 s, two attempts | 29.053 s, three attempts | Both first attempts reject an early srflx candidate. The POC second attempt is asymmetric despite both peers accepting candidates: legacy connects; Windows times out. Cause remains unresolved. |
| Original FreeBSD → Linux, `routing-ha-freebsd-linux-nat-router-ha` | 0.605 s, one attempt | 21.149 s, two attempts | Modern Linux discards both candidates before agent initialization. The same ordering problem appears on another baseline edge; the POC's effect on its frequency is unproven. |
| Reciprocal original Linux → FreeBSD in the same HA episode | 0.603 s, one attempt | 21.147 s, two attempts | This is the reciprocal observation of the preceding episode, not an independent repeat. The later replacement negotiation takes 0.603 s in both runs. |

#### Linux legacy-peer episode

Artifacts: [baseline 12341850071](https://github.com/netbirdio/proxbird-tests/actions/runs/39588288742/artifacts/12341850071), [intermediate POC 12345292351](https://github.com/netbirdio/proxbird-tests/actions/runs/39597620276/artifacts/12345292351).

Within the baseline artifact, use `results/c539cfea627cd94fe7ca9b96db282128/nodes/peer-{1,2}/client-logs.tar.gz`; within the POC artifact, use `results/5093183f8aa6d7c9ec273288b045ebe7/nodes/peer-{1,2}/client-logs.tar.gz`. The member is `./client.log`.

The modern peer-1 baseline dial starts at line 276 and succeeds at 305 (0.605 s). POC attempts are lines 279–280 → 356–358 (12.031 s, failed/cancelled/Closed), 368–369 → 397–399 (12.031 s, failed/cancelled/Closed), and 449–450 → 462 (0.604 s, success). The two gaps are 2.632 and 1.829 seconds. Signal/management streams are ready before the measured interval (POC lines 131 and 143); relay establishment is logged during the first attempt (278, 283–289), with communication at 302.

On legacy peer-2, the POC first host/srflx callbacks at lines 86/88 each produce an uninitialized-agent warning (87/89) before recreation (93). The second srflx callback at 160 produces the same warning (162) before recreation (165); host arrives after initialization (173). On attempt three, both callbacks follow initialization (217–218), and success appears at 243–250. Baseline callbacks both follow agent creation (89–104). These are concrete ordering differences, not proof of mux transaction misrouting or of their sole causal role. The scenario profile is NAT with expected P2P; the case name's `connect-relay` does not mean forced relay.

#### Windows DNS episode

Artifacts: [baseline 12341942075](https://github.com/netbirdio/proxbird-tests/actions/runs/39588288742/artifacts/12341942075), [intermediate POC 12346227132](https://github.com/netbirdio/proxbird-tests/actions/runs/39597620276/artifacts/12346227132).

Baseline root: `results/8f1cd61908895d4d1bf2c564624e6905/`; POC root: `results/dda1ce3c600a97362ef7122866fdf8e2/`. Windows uses `nodes/peer-1/client-logs.zip`, member `client.log`; legacy Linux uses `nodes/peer-2/client-logs.tar.gz`, member `./client.log`. Windows timestamps carry `+02:00`; times stated here are normalized to UTC. Durations use Windows's own clock, not subtraction between hosts.

Baseline Windows first dial/failure is lines 239–241 → 286–288; its srflx callback had been rejected before initialization at 215–216. The second dial at 310–318 succeeds at 319–324. POC also rejects an early srflx callback at 215–216 and fails its first dial at 318–320. Its second dial begins at 12:32:25.829 (330–332), gathers local host/srflx (333–335), accepts remote host/srflx at .831 (336–337), and logs four mux address registrations (338–341). Legacy accepts candidates (185–186, 193) and reports success at 12:32:26 (198–204). Windows remains Checking until failure at 12:32:37.854 (363–365). Both connect on attempt three: Windows success at 12:32:42.012 (392–396), legacy success at 267–289.

The second failure cannot be explained solely by the logged candidate-before-initialization problem. Both sides accept candidates, and control/relay readiness already exists. There is no STUN transaction/removal trace to establish a packet-delivery cause. The separately reproduced old-close-watcher bug is a possible mechanism, but this artifact does not prove it occurred: the old agent was Closed at 12:32:24.985, and the watcher would have to remain delayed beyond new registrations at 25.831, about 846 milliseconds. Mux registration logs prove activity at that moment, not persistence afterward. A later lifecycle unit fix does not prove this episode resolved.

Subsequent `client-tests` repetitions reproduce the intermediate source's
asymmetric second attempt: POC run `39608305272` takes 29.796 s and three attempts,
while baseline run `39608330203` takes 20.673 s and two attempts. However, the
intended ICE roles differ in all four observations: Windows is controlling in
both baseline samples and controlled in both POC samples. This follows from
the logged local/remote public keys and the unchanged `isController` string
comparison. Actual role-conflict exchanges are not visible in these logs.
The repeated symptom is real, but this is not a matched-role experiment and
cannot isolate a source effect. Final-source comparisons must record roles.
Repeat evidence and artifact links are retained in
`/workspace/scratch/proxbird-repeat-client-tests/repeat-comparison-portable.md`
and `windows-dns-repeat-investigation.md`.

The DNS test later restarts Windows. Baseline final diagnostics show Windows Connecting and legacy Relayed, whereas the POC final diagnostics show P2P. These post-test snapshots must remain distinct from successful initial P2P assertions. Initial Windows selected candidate types also differ: baseline host/srflx versus POC host/prflx.

#### Modern routing-HA episode

Artifacts: [baseline 12342674276](https://github.com/netbirdio/proxbird-tests/actions/runs/39588288742/artifacts/12342674276), [intermediate POC 12347820615](https://github.com/netbirdio/proxbird-tests/actions/runs/39597620276/artifacts/12347820615).

Baseline root: `results/3763cb7c1306ff3dcc5dc2e7bf2a365c/`; POC root: `results/411eea42af760fbc3a6023ac7992e9a3/`. Use `nodes/peer-{1,2}/client-logs.tar.gz`, member `./client.log`. The scenario orders Linux as peer-1 and FreeBSD as peers 2 and 3. Startup lines 68 on peer-1 and 45 on peer-2 show the matching tested `ci-<SHA>` version; neither original peer is legacy.

Baseline original FreeBSD dial/success is lines 234 → 279; reciprocal Linux is 298 → 334. POC original FreeBSD attempt one is 233 → 369–370 (12.123 s), followed by an 8.421-second gap and a 0.605-second success at 391 → 402. Linux's corresponding first attempt is 307 → 421–423 (12.029 s), followed by an 8.513-second gap and a 0.605-second success at 440 → 452.

POC Linux receives remote host at line 291 and srflx at 296, each followed by an uninitialized-agent warning (292/297), before agent creation at 299. [OnRemoteCandidate at immutable POC source](https://github.com/netbirdio/netbird/blob/37dab7d7124ea1de7a7e9bdfa5a3cd445f8413dc/client/internal/peer/worker_ice.go#L181-L193) returns before `AddRemoteCandidate` on this nil-agent branch. Thus those particular callbacks are demonstrably discarded. FreeBSD accepts host/srflx after initialization (262/271) and registers mux addresses (263, 270, 272, 279). On the second attempt both sides accept candidates and connect.

This is also an existing baseline ordering problem on another edge: Linux → peer-3 baseline receives srflx at 372, warns at 373, creates its agent at 376, fails at 421–423, then succeeds on retry at 455. Its interval is 20.555 s, with reciprocal 20.557 s. The baseline handler has the same nil-agent return. One execution cannot establish whether the POC changes the occurrence rate.

Peer-2 is later restarted and replaced. The original identity is resolved from initial snapshot FQDN/host address and unique logged interface key/AllowedIPs registration, corroborated by reciprocal sessions; final peer-2 status contains the replacement key. On POC Linux, the original is removed at 1290/1297, replacement added at 1386, and replacement dial/success occurs at 1436 → 1481 (0.603 s), after the original delayed success at 452. This later sample must not be substituted for the reciprocal original negotiation.

#### Coverage limits

The exact 85-case baseline contains 182 source-built modern nodes, 16 reference nodes at 0.30.1, and four at 0.28.9. `reference: current` denotes the source-built client in these artifacts. No separate current-release binary was exercised, so current-release mixed-peer interoperability remains unproven. Kernel/userspace mode is observed through `usesKernelInterface`; embedded/netstack validation is separate from these VM scenarios.

These artifacts do not provide transaction-level proof of one STUN response per request. They also do not establish repeated-run median time to P2P, a live post-run VM/ISO absence audit, or validation of the final lifecycle source. The older-peer and modern candidate-readiness episodes are evidence, not a reason to change the out-of-scope peer worker or to declare the mux responsible. Final-source validation must use its exact pushed SHA and retain these limitations until measured.

### Three baseline and three intermediate-source client-test samples

These are 120 modern-peer ICE observations across 20 client cases and six workflow runs. They cover baseline `1e63b68c4dc243a32fef823df1bc024c997a9c60` and intermediate POC `37dab7d7124ea1de7a7e9bdfa5a3cd445f8413dc`. They validate neither lifecycle source `42b087a4b5fb0dfcb111c46864d3340194a5a748` nor newer production source `49baccd`. All use harness `a1abca530f93969ad81f11a9683dc6e89171a23c`. B1/P1 belong to the original 85-case suite; later runs select the 20 client cases, so concurrent load is not controlled.

| Label | Workflow | Source | Selection |
| --- | --- | --- | --- |
| B1 | [39588288742](https://github.com/netbirdio/proxbird-tests/actions/runs/39588288742) | `1e63b68c4dc243a32fef823df1bc024c997a9c60` | full85 |
| B2 | [39608330203](https://github.com/netbirdio/proxbird-tests/actions/runs/39608330203) | `1e63b68c4dc243a32fef823df1bc024c997a9c60` | client-tests20 |
| B3 | [39608353253](https://github.com/netbirdio/proxbird-tests/actions/runs/39608353253) | `1e63b68c4dc243a32fef823df1bc024c997a9c60` | client-tests20 |
| P1 | [39597620276](https://github.com/netbirdio/proxbird-tests/actions/runs/39597620276) | `37dab7d7124ea1de7a7e9bdfa5a3cd445f8413dc` | full85 |
| P2 | [39608305272](https://github.com/netbirdio/proxbird-tests/actions/runs/39608305272) | `37dab7d7124ea1de7a7e9bdfa5a3cd445f8413dc` | client-tests20 |
| P3 | [39608375543](https://github.com/netbirdio/proxbird-tests/actions/runs/39608375543) | `37dab7d7124ea1de7a7e9bdfa5a3cd445f8413dc` | client-tests20 |

Each new repeat B2/P2/B3/P3 has 20 passing case artifacts and 29 published artifacts total (20 cases and nine build/preparation artifacts). Each 20-case audit verified 520 evidence files, 60 complete nodes, 40 native bundles, 40 raw TRACE archives, 20 server runtime identities and 20 passing Robot reports, with zero audit errors. Each has five canonical VM-start warnings that pass readiness checks. Source selection is verified in discover logs, every result and the manifests. All four client builds and each source-built server match the stated SHA and Go 1.26.7; manifest ZIP digests and sizes match GitHub metadata.

Manifest artifacts: B2 [12350413259](https://github.com/netbirdio/proxbird-tests/actions/runs/39608330203/artifacts/12350413259); P2 [12349652752](https://github.com/netbirdio/proxbird-tests/actions/runs/39608305272/artifacts/12349652752); B3 [12352432286](https://github.com/netbirdio/proxbird-tests/actions/runs/39608353253/artifacts/12352432286); P3 [12353519346](https://github.com/netbirdio/proxbird-tests/actions/runs/39608375543/artifacts/12353519346).

B2/P2/B3/P3 workflow completion is confirmed. B3 last job completed at 2026-10-21T14:41:36Z. P3 is completed/success with workflow updated timestamp 2026-10-21T15:08:00Z. Its separately fetched jobs list still lags at 27 successful and two in progress, so the workflow conclusion and complete case-artifact audit are the completion evidence; this report does not claim all 29 job records have reached their final state.

Each value below is seconds from the first observed modern peer-1 ICE dial to first success, with attempt count in parentheses. It includes failed attempts and retry gaps, uses a single node clock, and excludes earlier setup/signalling and later application readiness. It is not application time to P2P. Legacy peer-2 lacks matching modern timing markers and is unmeasured. Candidate types are final modern-peer local/remote snapshots, which can follow a service restart; they need not equal the first successful pair. All raw first-dial/first-success member names and line numbers are retained in `six-run-series.json`.

| Case | Baseline B1 / B2 / B3 seconds (attempts) | Intermediate P1 / P2 / P3 seconds (attempts) | Final candidate types B1; B2; B3 / P1; P2; P3 | B3 / P3 artifacts |
| --- | --- | --- | --- | --- |
| `client-freebsd-nat-allowed-ports` | 0.604 (1) / 0.603 (1) / 0.603 (1) | 0.625 (1) / 0.615 (1) / 0.646 (1) | host/prflx; host/prflx; host/srflx / host/prflx; srflx/prflx; srflx/prflx | B3 [12353081937](https://github.com/netbirdio/proxbird-tests/actions/runs/39608353253/artifacts/12353081937)<br>P3 [12353489668](https://github.com/netbirdio/proxbird-tests/actions/runs/39608375543/artifacts/12353489668) |
| `client-freebsd-nat-connect-legacy` | 0.604 (1) / 0.603 (1) / 0.604 (1) | 0.604 (1) / 0.604 (1) / 0.604 (1) | host/srflx; host/srflx; host/srflx / host/srflx; host/srflx; host/srflx | B3 [12353681256](https://github.com/netbirdio/proxbird-tests/actions/runs/39608353253/artifacts/12353681256)<br>P3 [12354473379](https://github.com/netbirdio/proxbird-tests/actions/runs/39608375543/artifacts/12354473379) |
| `client-freebsd-nat-connect-relay` | 0.613 (1) / 0.604 (1) / 0.626 (1) | 0.603 (1) / 0.630 (1) / 0.616 (1) | srflx/srflx; host/srflx; host/srflx / host/srflx; host/srflx; srflx/srflx | B3 [12352309794](https://github.com/netbirdio/proxbird-tests/actions/runs/39608353253/artifacts/12352309794)<br>P3 [12354498507](https://github.com/netbirdio/proxbird-tests/actions/runs/39608375543/artifacts/12354498507) |
| `client-freebsd-nat-dns` | 0.605 (1) / 0.610 (1) / 0.637 (1) | 0.605 (1) / 0.615 (1) / 0.604 (1) | host/srflx; srflx/srflx; host/srflx / host/srflx; host/srflx; host/srflx | B3 [12353666327](https://github.com/netbirdio/proxbird-tests/actions/runs/39608353253/artifacts/12353666327)<br>P3 [12355355467](https://github.com/netbirdio/proxbird-tests/actions/runs/39608375543/artifacts/12355355467) |
| `client-freebsd-nat-exit-node` | 0.615 (1) / 0.604 (1) / 0.635 (1) | 0.605 (1) / 0.605 (1) / 0.603 (1) | host/srflx; host/srflx; host/srflx / srflx/srflx; host/srflx; host/srflx | B3 [12352782847](https://github.com/netbirdio/proxbird-tests/actions/runs/39608353253/artifacts/12352782847)<br>P3 [12355205732](https://github.com/netbirdio/proxbird-tests/actions/runs/39608375543/artifacts/12355205732) |
| `client-linux-nat-allowed-ports` | 0.606 (1) / 0.604 (1) / 0.606 (1) | 0.606 (1) / 0.606 (1) / 0.604 (1) | host/prflx; host/prflx; host/prflx / host/prflx; host/prflx; host/prflx | B3 [12352244971](https://github.com/netbirdio/proxbird-tests/actions/runs/39608353253/artifacts/12352244971)<br>P3 [12354637250](https://github.com/netbirdio/proxbird-tests/actions/runs/39608375543/artifacts/12354637250) |
| `client-linux-nat-connect-legacy` | 0.603 (1) / 0.605 (1) / 0.604 (1) | 0.605 (1) / 0.605 (1) / 0.605 (1) | srflx/srflx; host/srflx; srflx/srflx / host/srflx; host/srflx; host/srflx | B3 [12353501449](https://github.com/netbirdio/proxbird-tests/actions/runs/39608353253/artifacts/12353501449)<br>P3 [12355090677](https://github.com/netbirdio/proxbird-tests/actions/runs/39608375543/artifacts/12355090677) |
| `client-linux-nat-connect-relay` | 0.605 (1) / 0.604 (1) / 0.605 (1) | 29.127 (3) / 0.606 (1) / 0.605 (1) | host/srflx; host/srflx; host/srflx / host/prflx; host/srflx; host/srflx | B3 [12352982407](https://github.com/netbirdio/proxbird-tests/actions/runs/39608353253/artifacts/12352982407)<br>P3 [12353454688](https://github.com/netbirdio/proxbird-tests/actions/runs/39608375543/artifacts/12353454688) |
| `client-linux-nat-dns` | 0.605 (1) / 0.605 (1) / 0.606 (1) | 0.605 (1) / 0.604 (1) / 0.605 (1) | host/srflx; host/srflx; host/srflx / host/srflx; host/srflx; host/srflx | B3 [12354370100](https://github.com/netbirdio/proxbird-tests/actions/runs/39608353253/artifacts/12354370100)<br>P3 [12355645540](https://github.com/netbirdio/proxbird-tests/actions/runs/39608375543/artifacts/12355645540) |
| `client-linux-nat-exit-node` | 0.606 (1) / 0.604 (1) / 0.606 (1) | 0.605 (1) / 0.604 (1) / 0.605 (1) | host/srflx; srflx/srflx; host/srflx / srflx/srflx; host/srflx; host/srflx | B3 [12352674677](https://github.com/netbirdio/proxbird-tests/actions/runs/39608353253/artifacts/12352674677)<br>P3 [12355540990](https://github.com/netbirdio/proxbird-tests/actions/runs/39608375543/artifacts/12355540990) |
| `client-macos-nat-allowed-ports` | 0.606 (1) / 22.170 (2) / 0.603 (1) | 0.606 (1) / 0.604 (1) / 0.605 (1) | srflx/prflx; srflx/prflx; host/prflx / host/prflx; host/prflx; host/prflx | B3 [12352693160](https://github.com/netbirdio/proxbird-tests/actions/runs/39608353253/artifacts/12352693160)<br>P3 [12355755904](https://github.com/netbirdio/proxbird-tests/actions/runs/39608375543/artifacts/12355755904) |
| `client-macos-nat-connect-legacy` | 0.605 (1) / 0.606 (1) / 0.603 (1) | 0.604 (1) / 0.603 (1) / 0.605 (1) | host/srflx; srflx/srflx; host/srflx / host/srflx; host/srflx; host/srflx | B3 [12353052860](https://github.com/netbirdio/proxbird-tests/actions/runs/39608353253/artifacts/12353052860)<br>P3 [12356080189](https://github.com/netbirdio/proxbird-tests/actions/runs/39608375543/artifacts/12356080189) |
| `client-macos-nat-connect-relay` | 0.604 (1) / 0.604 (1) / 0.604 (1) | 0.605 (1) / 0.606 (1) / 0.607 (1) | host/srflx; host/srflx; srflx/srflx / srflx/srflx; host/srflx; srflx/srflx | B3 [12354260567](https://github.com/netbirdio/proxbird-tests/actions/runs/39608353253/artifacts/12354260567)<br>P3 [12354857537](https://github.com/netbirdio/proxbird-tests/actions/runs/39608375543/artifacts/12354857537) |
| `client-macos-nat-dns` | 0.606 (1) / 0.607 (1) / 0.606 (1) | 0.603 (1) / 0.606 (1) / 0.604 (1) | srflx/srflx; host/srflx; srflx/srflx / host/srflx; srflx/srflx; host/srflx | B3 [12353032860](https://github.com/netbirdio/proxbird-tests/actions/runs/39608353253/artifacts/12353032860)<br>P3 [12354862462](https://github.com/netbirdio/proxbird-tests/actions/runs/39608375543/artifacts/12354862462) |
| `client-macos-nat-exit-node` | 0.605 (1) / 0.604 (1) / 21.088 (2) | 0.605 (1) / 0.604 (1) / 0.604 (1) | srflx/srflx; host/srflx; srflx/srflx / host/srflx; host/srflx; srflx/srflx | B3 [12353302483](https://github.com/netbirdio/proxbird-tests/actions/runs/39608353253/artifacts/12353302483)<br>P3 [12355386189](https://github.com/netbirdio/proxbird-tests/actions/runs/39608375543/artifacts/12355386189) |
| `client-windows-nat-allowed-ports` | 21.180 (2) / 0.604 (1) / 13.508 (2) | 0.605 (1) / 14.062 (2) / 22.456 (2) | host/srflx; host/srflx; host/srflx / srflx/srflx; host/srflx; host/srflx | B3 [12354216213](https://github.com/netbirdio/proxbird-tests/actions/runs/39608353253/artifacts/12354216213)<br>P3 [12354957615](https://github.com/netbirdio/proxbird-tests/actions/runs/39608375543/artifacts/12354957615) |
| `client-windows-nat-connect-legacy` | 13.882 (2) / 14.247 (2) / 13.184 (2) | 13.142 (2) / 28.697 (3) / 32.401 (3) | host/srflx; host/srflx; host/srflx / srflx/srflx; host/prflx; host/srflx | B3 [12353932286](https://github.com/netbirdio/proxbird-tests/actions/runs/39608353253/artifacts/12353932286)<br>P3 [12355816149](https://github.com/netbirdio/proxbird-tests/actions/runs/39608375543/artifacts/12355816149) |
| `client-windows-nat-connect-relay` | 0.605 (1) / 0.608 (1) / 21.953 (2) | 0.604 (1) / 0.609 (1) / 16.250 (2) | host/srflx; host/srflx; host/srflx / srflx/srflx; srflx/srflx; host/srflx | B3 [12352924350](https://github.com/netbirdio/proxbird-tests/actions/runs/39608353253/artifacts/12352924350)<br>P3 [12356320575](https://github.com/netbirdio/proxbird-tests/actions/runs/39608375543/artifacts/12356320575) |
| `client-windows-nat-dns` | 21.182 (2) / 20.673 (2) / 0.610 (1) | 29.053 (3) / 29.796 (3) / 0.607 (1) | -/- [Connecting/-]; -/- [Connecting/-]; host/srflx / host/srflx; host/srflx; host/srflx | B3 [12353767824](https://github.com/netbirdio/proxbird-tests/actions/runs/39608353253/artifacts/12353767824)<br>P3 [12354753579](https://github.com/netbirdio/proxbird-tests/actions/runs/39608375543/artifacts/12354753579) |
| `client-windows-nat-exit-node` | 0.609 (1) / 0.606 (1) / 0.604 (1) | 0.607 (1) / 23.251 (2) / 20.622 (2) | host/srflx; host/srflx; host/srflx / host/srflx; srflx/srflx; srflx/srflx | B3 [12353722600](https://github.com/netbirdio/proxbird-tests/actions/runs/39608353253/artifacts/12353722600)<br>P3 [12356335407](https://github.com/netbirdio/proxbird-tests/actions/runs/39608375543/artifacts/12356335407) |

The following medians use the three native first-dial-to-first-success samples above for each source and case. They are descriptive medians with n=3 per source, including failures and retry gaps, not medians of setup or Robot-step durations. Unknown legacy timing markers remain unmeasured. C means intended controlling; D means intended controlled. Every role is derived from native local-peerID and remote-peer key records, cross-checked against both archived status public keys; all 120 key pairs and native line references are retained in `six-run-role-evidence.json`. Actual STUN role attributes and subsequent conflicts are unlogged.

Candidate-change counts compare matching B1/P1, B2/P2 and B3/P3 snapshots in both directions (six directed observations per phase). I/F means initial/final, and each count is a number of observations, not failed cases. Final snapshots can follow service restarts. The role sequences and candidate differences are confounds; these data do not isolate a source-revision cause.

| Case | Baseline median s | Intermediate median s | Difference s | Intended roles B1/B2/B3 → P1/P2/P3 | Candidate-pair changes I/F | Local-type changes I/F |
| --- | ---: | ---: | ---: | --- | ---: | ---: |
| `client-freebsd-nat-allowed-ports` | 0.603 | 0.625 | +0.022 | D/D/D → C/C/C | 2/4 | 2/4 |
| `client-freebsd-nat-connect-legacy` | 0.604 | 0.604 | +0.000 | D/D/D → D/D/D | 0/0 | 0/0 |
| `client-freebsd-nat-connect-relay` | 0.613 | 0.616 | +0.003 | C/D/C → D/C/C | 3/3 | 3/3 |
| `client-freebsd-nat-dns` | 0.610 | 0.605 | -0.005 | D/D/C → D/C/D | 2/2 | 2/2 |
| `client-freebsd-nat-exit-node` | 0.615 | 0.605 | -0.010 | C/D/C → C/D/D | 2/2 | 2/2 |
| `client-linux-nat-allowed-ports` | 0.606 | 0.606 | +0.000 | C/D/C → C/C/C | 1/0 | 1/0 |
| `client-linux-nat-connect-legacy` | 0.604 | 0.605 | +0.001 | D/D/C → D/D/C | 2/2 | 2/2 |
| `client-linux-nat-connect-relay` | 0.605 | 0.606 | +0.001 | D/D/C → D/D/C | 2/2 | 1/1 |
| `client-linux-nat-dns` | 0.605 | 0.605 | +0.000 | C/C/C → D/D/D | 0/0 | 0/0 |
| `client-linux-nat-exit-node` | 0.606 | 0.605 | -0.001 | C/D/D → C/D/C | 4/4 | 4/4 |
| `client-macos-nat-allowed-ports` | 0.606 | 0.605 | -0.001 | D/C/D → D/D/D | 0/2 | 0/2 |
| `client-macos-nat-connect-legacy` | 0.605 | 0.604 | -0.001 | D/C/D → D/D/C | 3/3 | 3/3 |
| `client-macos-nat-connect-relay` | 0.604 | 0.606 | +0.002 | D/D/D → C/C/C | 1/1 | 1/1 |
| `client-macos-nat-dns` | 0.606 | 0.604 | -0.002 | C/C/C → D/C/D | 3/3 | 3/3 |
| `client-macos-nat-exit-node` | 0.605 | 0.604 | -0.001 | D/D/C → D/D/C | 1/1 | 1/1 |
| `client-windows-nat-allowed-ports` | 13.508 | 14.062 | +0.554 | C/C/D → C/D/C | 3/2 | 1/2 |
| `client-windows-nat-connect-legacy` | 13.882 | 28.697 | +14.815 | D/D/C → C/D/D | 3/3 | 2/2 |
| `client-windows-nat-connect-relay` | 0.608 | 0.609 | +0.001 | C/D/C → C/C/D | 4/4 | 4/4 |
| `client-windows-nat-dns` | 20.673 | 29.053 | +8.380 | C/C/D → D/D/C | 4/5 | 1/5 |
| `client-windows-nat-exit-node` | 0.606 | 20.622 | +20.016 | D/D/D → C/C/C | 5/5 | 4/4 |

The largest intermediate median increases are Windows exit-node 0.606→20.622 seconds (+20.016), connect-legacy 13.882→28.697 (+14.815), DNS 20.673→29.053 (+8.380), and allowed-ports 13.508→14.062 (+0.554). Linux connect-relay is 0.605→0.606 (+0.001), despite its single long P1 episode. Windows exit-node is fully confounded by intended role: baseline D/D/D versus intermediate C/C/C. Across all cases, 33 of the 60 paired B/P samples differ in intended role, affecting 16 of 20 cases. These differences require investigation; a green case result does not establish equal connection timing.

All 20 B3/P3 initial path/status observations match. The final snapshots have one changed directed path/status: Windows DNS legacy peer-2→modern peer-1 is Connected/P2P host/prflx in B3 and Connected/Relayed with no ICE pair in P3. This follows a DNS service restart. The P3 native legacy trace subsequently reports ICE success/Connected and host/prflx at `./client.log:200–209` (15:01:48 UTC), then normal shutdown begins at line 217 in the same second. The snapshot is therefore not evidence of persistent relay fallback or a failed recovery. Modern final status is P2P. B3/P3 final candidate types differ in 13 directed observations, all including a local-type change; these are not 13 failed cases.

The Linux connect-relay intermediate slowdown appears only in P1 (29.127 seconds / three attempts); P2/P3 are 0.606/0.605 seconds / one attempt and all three baseline samples are approximately 0.605 seconds. Windows DNS is two attempts in B1/B2, three in P1/P2, and one in B3/P3. Native logs confirm asymmetric second attempts in P1/P2; P3 has no such pre-success second attempt. Windows intended role is controlling in B1/B2/P3 and controlled in P1/P2/B3. B3 succeeds immediately in the controlled role, so role alone does not explain the episodes. B3/P3 also receive remote srflx before dialing, unlike the early dropped candidate documented in P2. Actual STUN packet roles and reader-delivery paths are unlogged.

P3 Windows connect-legacy instead exhibits an asymmetric second negotiation with Linux 0.28.9: legacy reports Connected while Windows remains Checking, times out, then succeeds on its third attempt (32.401 seconds total). Windows is intended controlled. It already has local host/loopback/srflx candidates, both remote candidates and four mux address registrations. Exact native provenance is in `third/poc3-native-findings.md`, using artifact [12355816149](https://github.com/netbirdio/proxbird-tests/actions/runs/39608375543/artifacts/12355816149). This extends the observed behavior to the 0.28.9 mixed case but does not establish its mux cause.

These three-sample series show timing variability and intermittent asymmetry on the intermediate source. The per-case medians do not establish a causal revision comparison, a controlled timing benchmark, current-release interoperability, or acceptance of source42b087a or newer source49baccd. The mixed reference binaries remain 0.28.9/0.30.1. Full raw logs stay in scratch evidence; portable workflow/artifact links and internal archive paths allow independent retrieval.

## Proxbird evidence for the lifecycle source (attempt 1)

### Pinned source 42: completed attempt 1

[Run 39617144938](https://github.com/netbirdio/proxbird-tests/actions/runs/39617144938/attempts/1) completed with conclusion **failure**, updated `2026-10-21T16:19:47Z`; its last job completed at `16:19:46Z`. All 94 jobs finished: 93 success and one failure. The exact 85 selected scenarios produced **84 complete passing artifact audits and one partial setup failure**. All 94 artifacts are present: 85 case ZIPs and nine build/preparation artifacts. Every case report identifies literal client and server source `42b087a4b5fb0dfcb111c46864d3340194a5a748`; discovery and [build manifest 12356575669](https://github.com/netbirdio/proxbird-tests/actions/runs/39617144938/artifacts/12356575669) independently confirm that pin. Harness source is `a1abca530f93969ad81f11a9683dc6e89171a23c`.

This validates the older lifecycle revision `532e38be` to the extent shown below. It **does not validate** the newer pushed `145a4ab86c27b8658c18308b33aa4c41109a52a5` (production code `24817004`), which additionally has per-candidate queues and bounded retention of recent transaction ownership. No newer E2E dispatch was observed in the 16:19 UTC workflow collection.

The one failure is [FreeBSD allowed-ports job 119304353650](https://github.com/netbirdio/proxbird-tests/actions/runs/39617144938/job/119304353650), [artifact 12355883225](https://github.com/netbirdio/proxbird-tests/actions/runs/39617144938/artifacts/12355883225), internal result `results/95becb95d7003971bc7d9a00beec47bd`. Proxmox guest-exec submission returned HTTP 596/broken_pipe while stopping the lab artifact server, before installation/enrollment and ICE assertions. Both peers report `netbird: command not found`; Robot/readiness/ports/traffic/reconnect checks were not run. This is **setup failure with unvalidated mux coverage**, not a mux pass or a demonstrated mux failure. The underlying transport/guest-agent cause remains unproven. Any targeted retry must be reported separately and must preserve this attempt.

The 84 complete cases verify 2,549 inventory files, 284 complete node diagnostics, 200 native bundles, 200 raw TRACE archives, 84 LAB runtime source identities, 64 passing Robot cases, all 13 recovery/path/underlay traffic audits and 32 canonical start warnings followed by readiness. The failed case separately contributes 20 size/SHA-256-verified files and a complete LAB record whose runtime identity passes the same existing auditor, for 2,569 verified files and 85 runtime identities including this addendum. Its two peers remain incomplete. No other artifact error was found. These checks do not independently prove live host VM/ISO absence or publication receipts.

Available mode evidence matches the recipe: 81 Linux kernel-interface nodes, 55 FreeBSD userspace nodes, 32 macOS userspace nodes and 32 Windows userspace nodes. The failed case has two unavailable peer status/version records. The VM recipe supplies older 0.28.9/0.30.1 compatibility binaries, not an independently verified separate current-release VM binary.

Against baseline [39588288742](https://github.com/netbirdio/proxbird-tests/actions/runs/39588288742), source `1e63b68c4dc243a32fef823df1bc024c997a9c60`, the complete 85-row table preserves immutable artifact links and separates initial assertions from final diagnostics. Initial path/status changes: 0; final changes: 2 directed Windows DNS observations, where source 42 is Connected/P2P and the baseline post-restart snapshots were Connecting/Relayed. Four observations from the failed case are unavailable and excluded from changes. Candidate-pair type changes are 103 initial/82 final; local-type changes are 73 initial/64 final. These are directed observations, not failure counts; final captures follow test actions and are not atomic.

Native timing has 211 numeric pairs, covering every successful modern source 42 observation. Only the baseline FreeBSD allowed-ports sample lacks a source 42 pair. Intended roles match in 103 pairs and differ in 108; actual STUN role conflicts are unobserved. Seven directions across five cases are at least five seconds slower than the single B1 baseline sample: Linux allowed-ports, Windows relay, Windows exit-node, both initial FreeBSD daemon-restart directions and both original Linux/Linux HA directions. The detailed native digest distinguishes initial negotiation from planned restart/replacement convergence, candidate ordering and role confounds; no causal mux attribution is claimed. These are first-dial-to-first-success intervals, not application-observed time to P2P or a source 42 median. The separate 20-case client comparison uses three baseline samples but only one source 42 sample per measurable case.

The complete table, native digest and final audit are preserved beside this note. The final completeness auditor exits 1 for the known failed workflow/case and its missing peer mode/version evidence; exact source, run, harness, 85-job/artifact selection, 94-artifact count and 85 table rows with 170 immutable artifact links all pass. The original 84-pass/one-failure table remains unchanged by any later retry.

Attempt 1 is frozen in `/workspace/scratch/proxbird-final-42b087a/attempt-1-final-state/`: 70 metadata/report files, with manifest SHA-256 `a8297f0a67845da7000bcdcca32981b7bfd23d0574bc3a6ac27f73055fc5d2f3`. After that freeze, GitHub accepted one targeted rerun of failed job `119304353650`. Its results belong to a separate attempt-2 record; the original table below remains unchanged.

### Portable Proxbird comparison: pinned source 42b087a

Baseline [run 39588288742](https://github.com/netbirdio/proxbird-tests/actions/runs/39588288742), source `1e63b68c4dc243a32fef823df1bc024c997a9c60`; source-42 POC [run 39617144938](https://github.com/netbirdio/proxbird-tests/actions/runs/39617144938), source `42b087a4b5fb0dfcb111c46864d3340194a5a748`. Harness `a1abca530f93969ad81f11a9683dc6e89171a23c`, attempt 1, exact 85-case selection: `peer-pairs,client-tests,recovery,connectivity-repair,connectivity-underlay,routing-ha,routing-overlap`. The tested commit contains lifecycle code revision `532e38be`; this table applies only to the exact pinned source.

Each arrow is baseline → source-42 POC; `(both)` means the displayed fields match. `I` is the initial `start-clients` peer snapshot when present, otherwise `result.peers`; `F` is the final per-node diagnostic snapshot, captured after test actions. `1>2` means peer-1 reporting peer-2; `2R` means peer-2-replacement. Final snapshots are not atomic. Candidate pairs are local/remote types. The Windows DNS final Connecting/Relayed baseline follows a daemon restart even though initial P2P assertions passed.

The timing column is seconds from first observed ICE agent dial to first success for the same local node/remote identity, including failed attempts and gaps. Brackets show intended ICE role at first dial: C=controlling, D=controlled, ?=unproven, inferred from the current-process native own-key and remote-key lexical comparator. Peer-1/peer-2 labels identify nodes, not ICE roles. Actual role-conflict transitions are unobserved, and differing intended roles confound source comparisons. These intervals are not application-observed time to P2P or repeated-run medians. They exclude earlier signalling/setup and later traffic readiness; node archives can span restarts. Original and replacement identities are mapped from status and exact interface key/address logs. Unmeasured legacy/no-success observations are never zero. No mux causality is inferred solely from timing. There is one workflow per source/topology. The newer pushed revision 145a4ab86c27b8658c18308b33aa4c41109a52a5 (production code 24817004) contains per-candidate queues and bounded retention of recent transaction ownership; this source-42 run contains neither change and does not validate that newer revision.

Each B/P link is the immutable GitHub artifact ID for that case. Inside its ZIP, evidence is under `results/<controller-id>/`: `result.json`, `nodes/peer-*/status.json`, `status-detail.txt`, `debug-bundle.zip` (`status.txt`), and raw `client-logs.*`. Source identities and artifact/file SHA-256 checks were audited. These links survive copying this table into the branch progress log.

| Case | Result B/P | P2P/relay snapshots | Candidate snapshots (local/remote) | First ICE dial→success seconds B→P | Artifact IDs |
| --- | --- | --- | --- | --- | --- |
| `client-freebsd-nat-allowed-ports` | pass/fail | I: 1>2:P2P; 2>1:P2P → unavailable<br>F: 1>2:P2P; 2>1:P2P → unavailable | I: 1>2:host/srflx; 2>1:host/srflx → unavailable<br>F: 1>2:host/prflx; 2>1:host/srflx → unavailable | 1>2:0.604→unmeasured [D→?]; 2:legacy/unmeasured | B [12340654721](https://github.com/netbirdio/proxbird-tests/actions/runs/39588288742/artifacts/12340654721)<br>P [12355883225](https://github.com/netbirdio/proxbird-tests/actions/runs/39617144938/artifacts/12355883225) |
| `client-freebsd-nat-connect-legacy` | pass/pass | I: 1>2:P2P; 2>1:P2P (both)<br>F: 1>2:P2P; 2>1:P2P (both) | I: 1>2:host/srflx; 2>1:host/srflx → 1>2:srflx/srflx; 2>1:srflx/srflx<br>F: 1>2:host/srflx; 2>1:host/srflx → 1>2:srflx/srflx; 2>1:srflx/srflx | 1>2:0.604→0.622 [D→C]; 2:legacy/unmeasured | B [12342305010](https://github.com/netbirdio/proxbird-tests/actions/runs/39588288742/artifacts/12342305010)<br>P [12355269550](https://github.com/netbirdio/proxbird-tests/actions/runs/39617144938/artifacts/12355269550) |
| `client-freebsd-nat-connect-relay` | pass/pass | I: 1>2:P2P; 2>1:P2P (both)<br>F: 1>2:P2P; 2>1:P2P (both) | I: 1>2:srflx/srflx; 2>1:host/srflx → 1>2:host/srflx; 2>1:host/srflx<br>F: 1>2:srflx/srflx; 2>1:host/srflx → 1>2:host/srflx; 2>1:host/srflx | 1>2:0.613→0.604 [C→D]; 2:legacy/unmeasured | B [12341165873](https://github.com/netbirdio/proxbird-tests/actions/runs/39588288742/artifacts/12341165873)<br>P [12356651282](https://github.com/netbirdio/proxbird-tests/actions/runs/39617144938/artifacts/12356651282) |
| `client-freebsd-nat-dns` | pass/pass | I: 1>2:P2P; 2>1:P2P (both)<br>F: 1>2:P2P; 2>1:P2P (both) | I: 1>2:host/srflx; 2>1:host/srflx (both)<br>F: 1>2:host/srflx; 2>1:host/srflx (both) | 1>2:0.605→0.632 [D→C]; 2:legacy/unmeasured | B [12341410760](https://github.com/netbirdio/proxbird-tests/actions/runs/39588288742/artifacts/12341410760)<br>P [12355754010](https://github.com/netbirdio/proxbird-tests/actions/runs/39617144938/artifacts/12355754010) |
| `client-freebsd-nat-exit-node` | pass/pass | I: 1>2:P2P; 2>1:P2P (both)<br>F: 1>2:P2P; 2>1:P2P (both) | I: 1>2:host/srflx; 2>1:host/srflx → 1>2:srflx/srflx; 2>1:host/srflx<br>F: 1>2:host/srflx; 2>1:host/srflx → 1>2:srflx/srflx; 2>1:host/srflx | 1>2:0.615→0.617 [C→C]; 2:legacy/unmeasured | B [12341420754](https://github.com/netbirdio/proxbird-tests/actions/runs/39588288742/artifacts/12341420754)<br>P [12355209860](https://github.com/netbirdio/proxbird-tests/actions/runs/39617144938/artifacts/12355209860) |
| `client-linux-nat-allowed-ports` | pass/pass | I: 1>2:P2P; 2>1:P2P (both)<br>F: 1>2:P2P; 2>1:P2P (both) | I: 1>2:host/srflx; 2>1:host/srflx → 1>2:host/prflx; 2>1:srflx/srflx<br>F: 1>2:host/prflx; 2>1:host/srflx (both) | 1>2:0.606→28.735 [C→D]; 2:legacy/unmeasured | B [12341094768](https://github.com/netbirdio/proxbird-tests/actions/runs/39588288742/artifacts/12341094768)<br>P [12355659252](https://github.com/netbirdio/proxbird-tests/actions/runs/39617144938/artifacts/12355659252) |
| `client-linux-nat-connect-legacy` | pass/pass | I: 1>2:P2P; 2>1:P2P (both)<br>F: 1>2:P2P; 2>1:P2P (both) | I: 1>2:srflx/srflx; 2>1:host/srflx → 1>2:host/srflx; 2>1:host/srflx<br>F: 1>2:srflx/srflx; 2>1:host/srflx → 1>2:host/srflx; 2>1:host/srflx | 1>2:0.603→0.604 [D→D]; 2:legacy/unmeasured | B [12341034872](https://github.com/netbirdio/proxbird-tests/actions/runs/39588288742/artifacts/12341034872)<br>P [12355379464](https://github.com/netbirdio/proxbird-tests/actions/runs/39617144938/artifacts/12355379464) |
| `client-linux-nat-connect-relay` | pass/pass | I: 1>2:P2P; 2>1:P2P (both)<br>F: 1>2:P2P; 2>1:P2P (both) | I: 1>2:host/srflx; 2>1:host/srflx (both)<br>F: 1>2:host/srflx; 2>1:host/srflx (both) | 1>2:0.605→0.604 [D→D]; 2:legacy/unmeasured | B [12341850071](https://github.com/netbirdio/proxbird-tests/actions/runs/39588288742/artifacts/12341850071)<br>P [12355513657](https://github.com/netbirdio/proxbird-tests/actions/runs/39617144938/artifacts/12355513657) |
| `client-linux-nat-dns` | pass/pass | I: 1>2:P2P; 2>1:P2P (both)<br>F: 1>2:P2P; 2>1:P2P (both) | I: 1>2:host/srflx; 2>1:host/srflx → 1>2:host/srflx; 2>1:srflx/srflx<br>F: 1>2:host/srflx; 2>1:host/srflx → 1>2:host/srflx; 2>1:srflx/srflx | 1>2:0.605→0.605 [C→D]; 2:legacy/unmeasured | B [12341540836](https://github.com/netbirdio/proxbird-tests/actions/runs/39588288742/artifacts/12341540836)<br>P [12356606740](https://github.com/netbirdio/proxbird-tests/actions/runs/39617144938/artifacts/12356606740) |
| `client-linux-nat-exit-node` | pass/pass | I: 1>2:P2P; 2>1:P2P (both)<br>F: 1>2:P2P; 2>1:P2P (both) | I: 1>2:host/srflx; 2>1:host/srflx (both)<br>F: 1>2:host/srflx; 2>1:host/srflx (both) | 1>2:0.606→0.605 [C→D]; 2:legacy/unmeasured | B [12341545883](https://github.com/netbirdio/proxbird-tests/actions/runs/39588288742/artifacts/12341545883)<br>P [12356726558](https://github.com/netbirdio/proxbird-tests/actions/runs/39617144938/artifacts/12356726558) |
| `client-macos-nat-allowed-ports` | pass/pass | I: 1>2:P2P; 2>1:P2P (both)<br>F: 1>2:P2P; 2>1:P2P (both) | I: 1>2:host/srflx; 2>1:host/srflx (both)<br>F: 1>2:srflx/prflx; 2>1:host/srflx → 1>2:host/prflx; 2>1:host/srflx | 1>2:0.606→0.605 [D→D]; 2:legacy/unmeasured | B [12342480775](https://github.com/netbirdio/proxbird-tests/actions/runs/39588288742/artifacts/12342480775)<br>P [12355844324](https://github.com/netbirdio/proxbird-tests/actions/runs/39617144938/artifacts/12355844324) |
| `client-macos-nat-connect-legacy` | pass/pass | I: 1>2:P2P; 2>1:P2P (both)<br>F: 1>2:P2P; 2>1:P2P (both) | I: 1>2:host/srflx; 2>1:host/srflx (both)<br>F: 1>2:host/srflx; 2>1:host/srflx (both) | 1>2:0.605→0.606 [D→D]; 2:legacy/unmeasured | B [12342625657](https://github.com/netbirdio/proxbird-tests/actions/runs/39588288742/artifacts/12342625657)<br>P [12357000785](https://github.com/netbirdio/proxbird-tests/actions/runs/39617144938/artifacts/12357000785) |
| `client-macos-nat-connect-relay` | pass/pass | I: 1>2:P2P; 2>1:P2P (both)<br>F: 1>2:P2P; 2>1:P2P (both) | I: 1>2:host/srflx; 2>1:host/srflx (both)<br>F: 1>2:host/srflx; 2>1:host/srflx (both) | 1>2:0.604→0.605 [D→D]; 2:legacy/unmeasured | B [12342735708](https://github.com/netbirdio/proxbird-tests/actions/runs/39588288742/artifacts/12342735708)<br>P [12357050864](https://github.com/netbirdio/proxbird-tests/actions/runs/39617144938/artifacts/12357050864) |
| `client-macos-nat-dns` | pass/pass | I: 1>2:P2P; 2>1:P2P (both)<br>F: 1>2:P2P; 2>1:P2P (both) | I: 1>2:srflx/srflx; 2>1:host/srflx → 1>2:host/srflx; 2>1:host/srflx<br>F: 1>2:srflx/srflx; 2>1:host/srflx → 1>2:host/srflx; 2>1:host/srflx | 1>2:0.606→0.605 [C→D]; 2:legacy/unmeasured | B [12341906028](https://github.com/netbirdio/proxbird-tests/actions/runs/39588288742/artifacts/12341906028)<br>P [12356239678](https://github.com/netbirdio/proxbird-tests/actions/runs/39617144938/artifacts/12356239678) |
| `client-macos-nat-exit-node` | pass/pass | I: 1>2:P2P; 2>1:P2P (both)<br>F: 1>2:P2P; 2>1:P2P (both) | I: 1>2:srflx/srflx; 2>1:host/srflx → 1>2:host/srflx; 2>1:host/srflx<br>F: 1>2:srflx/srflx; 2>1:host/srflx → 1>2:host/srflx; 2>1:host/srflx | 1>2:0.605→0.606 [D→C]; 2:legacy/unmeasured | B [12341841039](https://github.com/netbirdio/proxbird-tests/actions/runs/39588288742/artifacts/12341841039)<br>P [12357135451](https://github.com/netbirdio/proxbird-tests/actions/runs/39617144938/artifacts/12357135451) |
| `client-windows-nat-allowed-ports` | pass/pass | I: 1>2:P2P; 2>1:P2P (both)<br>F: 1>2:P2P; 2>1:P2P (both) | I: 1>2:host/srflx; 2>1:host/prflx → 1>2:host/prflx; 2>1:host/srflx<br>F: 1>2:host/srflx; 2>1:host/srflx (both) | 1>2:21.180→16.263 [C→D]; 2:legacy/unmeasured | B [12341137187](https://github.com/netbirdio/proxbird-tests/actions/runs/39588288742/artifacts/12341137187)<br>P [12357110690](https://github.com/netbirdio/proxbird-tests/actions/runs/39617144938/artifacts/12357110690) |
| `client-windows-nat-connect-legacy` | pass/pass | I: 1>2:P2P; 2>1:P2P (both)<br>F: 1>2:P2P; 2>1:P2P (both) | I: 1>2:host/srflx; 2>1:host/srflx → 1>2:srflx/srflx; 2>1:host/srflx<br>F: 1>2:host/srflx; 2>1:host/srflx → 1>2:srflx/srflx; 2>1:host/srflx | 1>2:13.882→14.527 [D→C]; 2:legacy/unmeasured | B [12342086503](https://github.com/netbirdio/proxbird-tests/actions/runs/39588288742/artifacts/12342086503)<br>P [12357480493](https://github.com/netbirdio/proxbird-tests/actions/runs/39617144938/artifacts/12357480493) |
| `client-windows-nat-connect-relay` | pass/pass | I: 1>2:P2P; 2>1:P2P (both)<br>F: 1>2:P2P; 2>1:P2P (both) | I: 1>2:host/srflx; 2>1:host/srflx → 1>2:srflx/srflx; 2>1:host/prflx<br>F: 1>2:host/srflx; 2>1:host/srflx → 1>2:srflx/srflx; 2>1:host/prflx | 1>2:0.605→23.113 [C→C]; 2:legacy/unmeasured | B [12342531334](https://github.com/netbirdio/proxbird-tests/actions/runs/39588288742/artifacts/12342531334)<br>P [12356458569](https://github.com/netbirdio/proxbird-tests/actions/runs/39617144938/artifacts/12356458569) |
| `client-windows-nat-dns` | pass/pass | I: 1>2:P2P; 2>1:P2P (both)<br>F: 1>2:-(Connecting); 2>1:Relayed → 1>2:P2P; 2>1:P2P | I: 1>2:host/srflx; 2>1:host/prflx → 1>2:host/prflx; 2>1:host/srflx<br>F: 1>2:-/-; 2>1:-/- → 1>2:host/srflx; 2>1:host/prflx | 1>2:21.182→16.171 [C→D]; 2:legacy/unmeasured | B [12341942075](https://github.com/netbirdio/proxbird-tests/actions/runs/39588288742/artifacts/12341942075)<br>P [12356059621](https://github.com/netbirdio/proxbird-tests/actions/runs/39617144938/artifacts/12356059621) |
| `client-windows-nat-exit-node` | pass/pass | I: 1>2:P2P; 2>1:P2P (both)<br>F: 1>2:P2P; 2>1:P2P (both) | I: 1>2:host/srflx; 2>1:host/srflx → 1>2:srflx/srflx; 2>1:host/prflx<br>F: 1>2:host/srflx; 2>1:host/srflx → 1>2:srflx/srflx; 2>1:host/prflx | 1>2:0.609→22.465 [D→C]; 2:legacy/unmeasured | B [12341566794](https://github.com/netbirdio/proxbird-tests/actions/runs/39588288742/artifacts/12341566794)<br>P [12356937109](https://github.com/netbirdio/proxbird-tests/actions/runs/39617144938/artifacts/12356937109) |
| `connectivity-repair-freebsd-nat-path-repair` | pass/pass | I: 1>2:P2P; 2>1:P2P (both)<br>F: 1>2:Relayed; 2>1:Relayed (both) | I: 1>2:srflx/srflx; 2>1:srflx/srflx → 1>2:srflx/srflx; 2>1:host/srflx<br>F: 1>2:-/-; 2>1:-/- (both) | 1>2:0.605→0.603 [C→D]; 2>1:0.606→0.605 [D→C] | B [12341916838](https://github.com/netbirdio/proxbird-tests/actions/runs/39588288742/artifacts/12341916838)<br>P [12355964717](https://github.com/netbirdio/proxbird-tests/actions/runs/39617144938/artifacts/12355964717) |
| `connectivity-repair-linux-nat-path-repair` | pass/pass | I: 1>2:P2P; 2>1:P2P (both)<br>F: 1>2:Relayed; 2>1:Relayed (both) | I: 1>2:srflx/srflx; 2>1:srflx/srflx → 1>2:srflx/srflx; 2>1:host/srflx<br>F: 1>2:-/-; 2>1:-/- (both) | 1>2:0.604→0.603 [C→D]; 2>1:0.605→0.605 [D→C] | B [12342606512](https://github.com/netbirdio/proxbird-tests/actions/runs/39588288742/artifacts/12342606512)<br>P [12356996433](https://github.com/netbirdio/proxbird-tests/actions/runs/39617144938/artifacts/12356996433) |
| `connectivity-repair-macos-nat-path-repair` | pass/pass | I: 1>2:P2P; 2>1:P2P (both)<br>F: 1>2:Relayed; 2>1:Relayed (both) | I: 1>2:srflx/srflx; 2>1:srflx/srflx → 1>2:host/srflx; 2>1:srflx/srflx<br>F: 1>2:-/-; 2>1:-/- (both) | 1>2:0.604→0.605 [C→C]; 2>1:0.605→0.606 [D→D] | B [12342611591](https://github.com/netbirdio/proxbird-tests/actions/runs/39588288742/artifacts/12342611591)<br>P [12356667870](https://github.com/netbirdio/proxbird-tests/actions/runs/39617144938/artifacts/12356667870) |
| `connectivity-repair-windows-nat-path-repair` | pass/pass | I: 1>2:P2P; 2>1:P2P (both)<br>F: 1>2:Relayed; 2>1:Relayed (both) | I: 1>2:srflx/srflx; 2>1:srflx/srflx → 1>2:srflx/srflx; 2>1:host/srflx<br>F: 1>2:-/-; 2>1:-/- (both) | 1>2:0.605→0.604 [D→D]; 2>1:0.612→0.612 [C→C] | B [12342246693](https://github.com/netbirdio/proxbird-tests/actions/runs/39588288742/artifacts/12342246693)<br>P [12356139720](https://github.com/netbirdio/proxbird-tests/actions/runs/39617144938/artifacts/12356139720) |
| `connectivity-underlay-linux-nat-underlay-change` | pass/pass | I: 1>2:P2P; 2>1:P2P (both)<br>F: 1>2:P2P; 2>1:P2P (both) | I: 1>2:srflx/srflx; 2>1:srflx/srflx → 1>2:host/srflx; 2>1:srflx/srflx<br>F: 1>2:srflx/prflx; 2>1:host/srflx → 1>2:host/prflx; 2>1:host/srflx | 1>2:0.604→0.603 [D→C]; 2>1:0.604→0.604 [C→D] | B [12341802157](https://github.com/netbirdio/proxbird-tests/actions/runs/39588288742/artifacts/12341802157)<br>P [12357921057](https://github.com/netbirdio/proxbird-tests/actions/runs/39617144938/artifacts/12357921057) |
| `freebsd-freebsd-direct` | pass/pass | I: 1>2:P2P; 2>1:P2P (both)<br>F: 1>2:P2P; 2>1:P2P (both) | I: 1>2:srflx/srflx; 2>1:srflx/srflx → 1>2:host/host; 2>1:host/prflx<br>F: 1>2:srflx/srflx; 2>1:srflx/srflx → 1>2:host/host; 2>1:host/prflx | 1>2:0.614→0.002 [C→C]; 2>1:0.614→0.002 [D→D] | B [12342671706](https://github.com/netbirdio/proxbird-tests/actions/runs/39588288742/artifacts/12342671706)<br>P [12357720820](https://github.com/netbirdio/proxbird-tests/actions/runs/39617144938/artifacts/12357720820) |
| `freebsd-freebsd-nat` | pass/pass | I: 1>2:P2P; 2>1:P2P (both)<br>F: 1>2:P2P; 2>1:P2P (both) | I: 1>2:srflx/srflx; 2>1:srflx/srflx → 1>2:host/srflx; 2>1:srflx/srflx<br>F: 1>2:srflx/srflx; 2>1:srflx/srflx → 1>2:host/srflx; 2>1:srflx/srflx | 1>2:0.620→0.612 [D→C]; 2>1:0.621→0.613 [C→D] | B [12341192628](https://github.com/netbirdio/proxbird-tests/actions/runs/39588288742/artifacts/12341192628)<br>P [12357226963](https://github.com/netbirdio/proxbird-tests/actions/runs/39617144938/artifacts/12357226963) |
| `freebsd-freebsd-relay` | pass/pass | I: 1>2:Relayed; 2>1:Relayed (both)<br>F: 1>2:Relayed; 2>1:Relayed (both) | I: 1>2:-/-; 2>1:-/- (both)<br>F: 1>2:-/-; 2>1:-/- (both) | 1>2:unmeasured→unmeasured [C→D]; 2>1:unmeasured→unmeasured [D→C] | B [12341387476](https://github.com/netbirdio/proxbird-tests/actions/runs/39588288742/artifacts/12341387476)<br>P [12357711297](https://github.com/netbirdio/proxbird-tests/actions/runs/39617144938/artifacts/12357711297) |
| `freebsd-freebsd-slow` | pass/pass | I: 1>2:P2P; 2>1:P2P (both)<br>F: 1>2:P2P; 2>1:P2P (both) | I: 1>2:srflx/srflx; 2>1:srflx/srflx → 1>2:host/srflx; 2>1:srflx/srflx<br>F: 1>2:srflx/srflx; 2>1:srflx/srflx → 1>2:host/srflx; 2>1:srflx/srflx | 1>2:0.903→0.904 [C→C]; 2>1:0.903→0.905 [D→D] | B [12341258342](https://github.com/netbirdio/proxbird-tests/actions/runs/39588288742/artifacts/12341258342)<br>P [12357192002](https://github.com/netbirdio/proxbird-tests/actions/runs/39617144938/artifacts/12357192002) |
| `macos-macos-direct` | pass/pass | I: 1>2:P2P; 2>1:P2P (both)<br>F: 1>2:P2P; 2>1:P2P (both) | I: 1>2:host/srflx; 2>1:srflx/prflx → 1>2:host/host; 2>1:host/srflx<br>F: 1>2:host/srflx; 2>1:srflx/prflx → 1>2:host/host; 2>1:host/srflx | 1>2:1.008→0.202 [D→C]; 2>1:1.011→0.202 [C→D] | B [12341522480](https://github.com/netbirdio/proxbird-tests/actions/runs/39588288742/artifacts/12341522480)<br>P [12358156049](https://github.com/netbirdio/proxbird-tests/actions/runs/39617144938/artifacts/12358156049) |
| `macos-macos-nat` | pass/pass | I: 1>2:P2P; 2>1:P2P (both)<br>F: 1>2:P2P; 2>1:P2P (both) | I: 1>2:srflx/srflx; 2>1:srflx/srflx → 1>2:host/srflx; 2>1:srflx/srflx<br>F: 1>2:srflx/srflx; 2>1:srflx/srflx → 1>2:host/srflx; 2>1:srflx/srflx | 1>2:0.607→0.604 [C→C]; 2>1:0.607→0.605 [D→D] | B [12342402445](https://github.com/netbirdio/proxbird-tests/actions/runs/39588288742/artifacts/12342402445)<br>P [12357391811](https://github.com/netbirdio/proxbird-tests/actions/runs/39617144938/artifacts/12357391811) |
| `macos-macos-relay` | pass/pass | I: 1>2:Relayed; 2>1:Relayed (both)<br>F: 1>2:Relayed; 2>1:Relayed (both) | I: 1>2:-/-; 2>1:-/- (both)<br>F: 1>2:-/-; 2>1:-/- (both) | 1>2:unmeasured→unmeasured [D→D]; 2>1:unmeasured→unmeasured [C→C] | B [12342342613](https://github.com/netbirdio/proxbird-tests/actions/runs/39588288742/artifacts/12342342613)<br>P [12357976405](https://github.com/netbirdio/proxbird-tests/actions/runs/39617144938/artifacts/12357976405) |
| `macos-macos-slow` | pass/pass | I: 1>2:P2P; 2>1:P2P (both)<br>F: 1>2:P2P; 2>1:P2P (both) | I: 1>2:srflx/srflx; 2>1:srflx/srflx → 1>2:srflx/srflx; 2>1:host/srflx<br>F: 1>2:srflx/srflx; 2>1:srflx/srflx → 1>2:srflx/srflx; 2>1:host/srflx | 1>2:0.703→0.704 [D→D]; 2>1:0.905→0.906 [C→C] | B [12341573505](https://github.com/netbirdio/proxbird-tests/actions/runs/39588288742/artifacts/12341573505)<br>P [12358336106](https://github.com/netbirdio/proxbird-tests/actions/runs/39617144938/artifacts/12358336106) |
| `macos-windows-direct` | pass/pass | I: 1>2:P2P; 2>1:P2P (both)<br>F: 1>2:P2P; 2>1:P2P (both) | I: 1>2:host/prflx; 2>1:host/host → 1>2:host/host; 2>1:host/host<br>F: 1>2:host/prflx; 2>1:host/host → 1>2:host/host; 2>1:host/host | 1>2:1.011→0.012 [C→C]; 2>1:1.004→0.005 [D→D] | B [12341193306](https://github.com/netbirdio/proxbird-tests/actions/runs/39588288742/artifacts/12341193306)<br>P [12357926769](https://github.com/netbirdio/proxbird-tests/actions/runs/39617144938/artifacts/12357926769) |
| `macos-windows-nat` | pass/pass | I: 1>2:P2P; 2>1:P2P (both)<br>F: 1>2:P2P; 2>1:P2P (both) | I: 1>2:srflx/srflx; 2>1:srflx/srflx → 1>2:host/srflx; 2>1:srflx/srflx<br>F: 1>2:srflx/srflx; 2>1:srflx/srflx → 1>2:host/srflx; 2>1:srflx/srflx | 1>2:0.612→0.610 [C→C]; 2>1:0.605→0.603 [D→D] | B [12342137990](https://github.com/netbirdio/proxbird-tests/actions/runs/39588288742/artifacts/12342137990)<br>P [12357732318](https://github.com/netbirdio/proxbird-tests/actions/runs/39617144938/artifacts/12357732318) |
| `macos-windows-relay` | pass/pass | I: 1>2:Relayed; 2>1:Relayed (both)<br>F: 1>2:Relayed; 2>1:Relayed (both) | I: 1>2:-/-; 2>1:-/- (both)<br>F: 1>2:-/-; 2>1:-/- (both) | 1>2:unmeasured→unmeasured [C→C]; 2>1:unmeasured→unmeasured [D→D] | B [12341732793](https://github.com/netbirdio/proxbird-tests/actions/runs/39588288742/artifacts/12341732793)<br>P [12357197254](https://github.com/netbirdio/proxbird-tests/actions/runs/39617144938/artifacts/12357197254) |
| `macos-windows-slow` | pass/pass | I: 1>2:P2P; 2>1:P2P (both)<br>F: 1>2:P2P; 2>1:P2P (both) | I: 1>2:srflx/srflx; 2>1:srflx/srflx → 1>2:srflx/srflx; 2>1:host/srflx<br>F: 1>2:srflx/srflx; 2>1:srflx/srflx → 1>2:srflx/srflx; 2>1:host/srflx | 1>2:0.707→0.702 [C→D]; 2>1:0.704→0.904 [D→C] | B [12342112840](https://github.com/netbirdio/proxbird-tests/actions/runs/39588288742/artifacts/12342112840)<br>P [12357766792](https://github.com/netbirdio/proxbird-tests/actions/runs/39617144938/artifacts/12357766792) |
| `recovery-freebsd-nat-daemon-restart` | pass/pass | I: 1>2:P2P; 2>1:P2P (both)<br>F: 1>2:P2P; 2>1:P2P (both) | I: 1>2:srflx/srflx; 2>1:srflx/srflx → 1>2:host/srflx; 2>1:srflx/srflx<br>F: 1>2:srflx/srflx; 2>1:srflx/srflx → 1>2:host/srflx; 2>1:srflx/prflx | 1>2:0.604→21.232 [C→C]; 2>1:0.604→21.233 [D→D] | B [12341379155](https://github.com/netbirdio/proxbird-tests/actions/runs/39588288742/artifacts/12341379155)<br>P [12357602310](https://github.com/netbirdio/proxbird-tests/actions/runs/39617144938/artifacts/12357602310) |
| `recovery-freebsd-nat-path-failure` | pass/pass | I: 1>2:P2P; 2>1:P2P (both)<br>F: 1>2:Relayed; 2>1:Relayed (both) | I: 1>2:srflx/srflx; 2>1:srflx/srflx → 1>2:srflx/srflx; 2>1:host/srflx<br>F: 1>2:-/-; 2>1:-/- (both) | 1>2:0.603→0.604 [D→D]; 2>1:0.605→0.604 [C→C] | B [12341608003](https://github.com/netbirdio/proxbird-tests/actions/runs/39588288742/artifacts/12341608003)<br>P [12356913164](https://github.com/netbirdio/proxbird-tests/actions/runs/39617144938/artifacts/12356913164) |
| `recovery-linux-nat-daemon-restart` | pass/pass | I: 1>2:P2P; 2>1:P2P (both)<br>F: 1>2:P2P; 2>1:P2P (both) | I: 1>2:srflx/srflx; 2>1:srflx/srflx → 1>2:host/srflx; 2>1:srflx/srflx<br>F: 1>2:host/srflx; 2>1:srflx/prflx (both) | 1>2:0.604→0.604 [C→C]; 2>1:0.605→0.604 [D→D] | B [12341733274](https://github.com/netbirdio/proxbird-tests/actions/runs/39588288742/artifacts/12341733274)<br>P [12357811669](https://github.com/netbirdio/proxbird-tests/actions/runs/39617144938/artifacts/12357811669) |
| `recovery-linux-nat-path-failure` | pass/pass | I: 1>2:P2P; 2>1:P2P (both)<br>F: 1>2:Relayed; 2>1:Relayed (both) | I: 1>2:srflx/srflx; 2>1:srflx/srflx → 1>2:host/srflx; 2>1:srflx/srflx<br>F: 1>2:-/-; 2>1:-/- (both) | 1>2:0.604→0.605 [C→C]; 2>1:0.605→0.605 [D→D] | B [12341354543](https://github.com/netbirdio/proxbird-tests/actions/runs/39588288742/artifacts/12341354543)<br>P [12358610555](https://github.com/netbirdio/proxbird-tests/actions/runs/39617144938/artifacts/12358610555) |
| `recovery-macos-nat-daemon-restart` | pass/pass | I: 1>2:P2P; 2>1:P2P (both)<br>F: 1>2:P2P; 2>1:P2P (both) | I: 1>2:srflx/srflx; 2>1:srflx/srflx → 1>2:srflx/srflx; 2>1:host/srflx<br>F: 1>2:host/srflx; 2>1:srflx/prflx → 1>2:srflx/prflx; 2>1:host/srflx | 1>2:0.604→0.604 [C→D]; 2>1:0.605→0.608 [D→C] | B [12341808921](https://github.com/netbirdio/proxbird-tests/actions/runs/39588288742/artifacts/12341808921)<br>P [12357228123](https://github.com/netbirdio/proxbird-tests/actions/runs/39617144938/artifacts/12357228123) |
| `recovery-macos-nat-path-failure` | pass/pass | I: 1>2:P2P; 2>1:P2P (both)<br>F: 1>2:Relayed; 2>1:Relayed (both) | I: 1>2:host/srflx; 2>1:srflx/prflx → 1>2:srflx/srflx; 2>1:host/srflx<br>F: 1>2:-/-; 2>1:-/- (both) | 1>2:22.425→0.605 [C→D]; 2>1:22.427→0.606 [D→C] | B [12341264106](https://github.com/netbirdio/proxbird-tests/actions/runs/39588288742/artifacts/12341264106)<br>P [12358730277](https://github.com/netbirdio/proxbird-tests/actions/runs/39617144938/artifacts/12358730277) |
| `recovery-windows-nat-daemon-restart` | pass/pass | I: 1>2:P2P; 2>1:P2P (both)<br>F: 1>2:P2P; 2>1:P2P (both) | I: 1>2:srflx/srflx; 2>1:srflx/srflx → 1>2:host/srflx; 2>1:srflx/srflx<br>F: 1>2:host/srflx; 2>1:srflx/prflx (both) | 1>2:0.604→0.604 [C→C]; 2>1:0.611→0.609 [D→D] | B [12341299068](https://github.com/netbirdio/proxbird-tests/actions/runs/39588288742/artifacts/12341299068)<br>P [12357687844](https://github.com/netbirdio/proxbird-tests/actions/runs/39617144938/artifacts/12357687844) |
| `recovery-windows-nat-path-failure` | pass/pass | I: 1>2:P2P; 2>1:P2P (both)<br>F: 1>2:Relayed; 2>1:Relayed (both) | I: 1>2:srflx/srflx; 2>1:srflx/srflx → 1>2:host/srflx; 2>1:srflx/srflx<br>F: 1>2:-/-; 2>1:-/- (both) | 1>2:0.606→0.604 [C→C]; 2>1:0.610→0.612 [D→D] | B [12342713738](https://github.com/netbirdio/proxbird-tests/actions/runs/39588288742/artifacts/12342713738)<br>P [12357983198](https://github.com/netbirdio/proxbird-tests/actions/runs/39617144938/artifacts/12357983198) |
| `routing-ha-freebsd-freebsd-nat-router-ha` | pass/pass | I: 1>2:P2P; 1>3:P2P; 2>1:P2P; 2>3:P2P; 3>1:P2P; 3>2:P2P (both)<br>F: 1>2R:P2P; 1>3:P2P; 2>1:P2P; 2>3:-(Idle); 3>1:P2P; 3>2R:-(Idle) (both) | I: 1>2:srflx/srflx; 1>3:srflx/srflx; 2>1:srflx/srflx; 2>3:host/host; 3>1:srflx/srflx; 3>2:host/prflx → 1>2:srflx/srflx; 1>3:srflx/srflx; 2>1:host/srflx; 2>3:host/host; 3>1:host/srflx; 3>2:host/host<br>F: 1>2R:host/srflx; 1>3:srflx/srflx; 2>1:srflx/prflx; 2>3:-/-; 3>1:srflx/srflx; 3>2R:-/- → 1>2R:srflx/srflx; 1>3:srflx/srflx; 2>1:host/prflx; 2>3:-/-; 3>1:host/srflx; 3>2R:-/- | 1>2:0.622→0.614 [D→D]; 1>2R:1.004→1.014 [D→D]; 1>3:0.612→0.616 [D→D]; 2>1:0.623→0.614 [C→C]; 2>3:0.002→0.001 [C→D]; 3>1:0.613→0.618 [C→C]; 3>2:0.002→0.002 [D→C] | B [12342123979](https://github.com/netbirdio/proxbird-tests/actions/runs/39588288742/artifacts/12342123979)<br>P [12358127367](https://github.com/netbirdio/proxbird-tests/actions/runs/39617144938/artifacts/12358127367) |
| `routing-ha-freebsd-freebsd-relay-router-ha` | pass/pass | I: 1>2:Relayed; 1>3:Relayed; 2>1:Relayed; 2>3:P2P; 3>1:Relayed; 3>2:P2P (both)<br>F: 1>2R:Relayed; 1>3:Relayed; 2>1:Relayed; 2>3:-(Idle); 3>1:Relayed; 3>2R:-(Idle) (both) | I: 1>2:-/-; 1>3:-/-; 2>1:-/-; 2>3:host/host; 3>1:-/-; 3>2:host/prflx → 1>2:-/-; 1>3:-/-; 2>1:-/-; 2>3:host/host; 3>1:-/-; 3>2:host/host<br>F: 1>2R:-/-; 1>3:-/-; 2>1:-/-; 2>3:-/-; 3>1:-/-; 3>2R:-/- (both) | 1>2:unmeasured→unmeasured [D→C]; 1>2R:unmeasured→unmeasured [D→C]; 1>3:unmeasured→unmeasured [D→D]; 2>1:unmeasured→unmeasured [C→D]; 2>3:0.002→0.002 [C→D]; 3>1:unmeasured→unmeasured [C→C]; 3>2:0.003→0.002 [D→C] | B [12342244410](https://github.com/netbirdio/proxbird-tests/actions/runs/39588288742/artifacts/12342244410)<br>P [12357863907](https://github.com/netbirdio/proxbird-tests/actions/runs/39617144938/artifacts/12357863907) |
| `routing-ha-freebsd-linux-nat-router-ha` | pass/pass | I: 1>2:P2P; 1>3:P2P; 2>1:P2P; 2>3:P2P; 3>1:P2P; 3>2:P2P (both)<br>F: 1>2R:P2P; 1>3:P2P; 2>1:P2P; 2>3:-(Idle); 3>1:P2P; 3>2R:-(Idle) (both) | I: 1>2:srflx/srflx; 1>3:srflx/srflx; 2>1:srflx/srflx; 2>3:host/host; 3>1:srflx/srflx; 3>2:host/host → 1>2:host/srflx; 1>3:srflx/srflx; 2>1:srflx/srflx; 2>3:host/host; 3>1:host/srflx; 3>2:host/host<br>F: 1>2R:host/srflx; 1>3:srflx/srflx; 2>1:srflx/prflx; 2>3:-/-; 3>1:srflx/srflx; 3>2R:-/- → 1>2R:host/srflx; 1>3:srflx/srflx; 2>1:srflx/prflx; 2>3:-/-; 3>1:host/srflx; 3>2R:-/- | 1>2:0.603→0.603 [C→C]; 1>2R:0.603→0.603 [C→C]; 1>3:20.555→0.613 [C→D]; 2>1:0.605→0.604 [D→D]; 2>3:0.002→0.002 [D→D]; 3>1:20.557→0.615 [D→C]; 3>2:0.002→0.002 [C→C] | B [12342674276](https://github.com/netbirdio/proxbird-tests/actions/runs/39588288742/artifacts/12342674276)<br>P [12357713215](https://github.com/netbirdio/proxbird-tests/actions/runs/39617144938/artifacts/12357713215) |
| `routing-ha-freebsd-linux-relay-router-ha` | pass/pass | I: 1>2:Relayed; 1>3:Relayed; 2>1:Relayed; 2>3:P2P; 3>1:Relayed; 3>2:P2P (both)<br>F: 1>2R:Relayed; 1>3:Relayed; 2>1:Relayed; 2>3:-(Idle); 3>1:Relayed; 3>2R:-(Idle) (both) | I: 1>2:-/-; 1>3:-/-; 2>1:-/-; 2>3:host/host; 3>1:-/-; 3>2:host/prflx (both)<br>F: 1>2R:-/-; 1>3:-/-; 2>1:-/-; 2>3:-/-; 3>1:-/-; 3>2R:-/- (both) | 1>2:unmeasured→unmeasured [D→D]; 1>2R:unmeasured→unmeasured [D→C]; 1>3:unmeasured→unmeasured [C→C]; 2>1:unmeasured→unmeasured [C→C]; 2>3:0.001→0.001 [C→C]; 3>1:unmeasured→unmeasured [D→D]; 3>2:0.002→0.002 [D→D] | B [12343020042](https://github.com/netbirdio/proxbird-tests/actions/runs/39588288742/artifacts/12343020042)<br>P [12358960507](https://github.com/netbirdio/proxbird-tests/actions/runs/39617144938/artifacts/12358960507) |
| `routing-ha-freebsd-macos-nat-router-ha` | pass/pass | I: 1>2:P2P; 1>3:P2P; 2>1:P2P; 2>3:P2P; 3>1:P2P; 3>2:P2P (both)<br>F: 1>2R:P2P; 1>3:P2P; 2>1:P2P; 2>3:-(Idle); 3>1:P2P; 3>2R:-(Idle) (both) | I: 1>2:srflx/srflx; 1>3:srflx/srflx; 2>1:srflx/srflx; 2>3:host/host; 3>1:srflx/srflx; 3>2:host/host → 1>2:srflx/prflx; 1>3:host/srflx; 2>1:host/srflx; 2>3:host/host; 3>1:srflx/srflx; 3>2:host/host<br>F: 1>2R:srflx/srflx; 1>3:srflx/srflx; 2>1:srflx/prflx; 2>3:-/-; 3>1:srflx/srflx; 3>2R:-/- → 1>2R:srflx/prflx; 1>3:host/srflx; 2>1:host/srflx; 2>3:-/-; 3>1:srflx/srflx; 3>2R:-/- | 1>2:0.604→1.453 [C→D]; 1>2R:0.604→0.603 [C→D]; 1>3:0.606→0.607 [C→C]; 2>1:0.606→1.455 [D→C]; 2>3:0.001→0.002 [C→C]; 3>1:0.607→0.608 [D→D]; 3>2:0.002→0.003 [D→D] | B [12343280139](https://github.com/netbirdio/proxbird-tests/actions/runs/39588288742/artifacts/12343280139)<br>P [12356969290](https://github.com/netbirdio/proxbird-tests/actions/runs/39617144938/artifacts/12356969290) |
| `routing-ha-freebsd-macos-relay-router-ha` | pass/pass | I: 1>2:Relayed; 1>3:Relayed; 2>1:Relayed; 2>3:P2P; 3>1:Relayed; 3>2:P2P (both)<br>F: 1>2R:Relayed; 1>3:Relayed; 2>1:Relayed; 2>3:-(Idle); 3>1:Relayed; 3>2R:-(Idle) (both) | I: 1>2:-/-; 1>3:-/-; 2>1:-/-; 2>3:host/host; 3>1:-/-; 3>2:host/host (both)<br>F: 1>2R:-/-; 1>3:-/-; 2>1:-/-; 2>3:-/-; 3>1:-/-; 3>2R:-/- (both) | 1>2:unmeasured→unmeasured [D→D]; 1>2R:unmeasured→unmeasured [C→D]; 1>3:unmeasured→unmeasured [C→D]; 2>1:unmeasured→unmeasured [C→C]; 2>3:0.002→0.002 [C→C]; 3>1:unmeasured→unmeasured [D→C]; 3>2:0.001→0.003 [D→D] | B [12341719764](https://github.com/netbirdio/proxbird-tests/actions/runs/39588288742/artifacts/12341719764)<br>P [12356964659](https://github.com/netbirdio/proxbird-tests/actions/runs/39617144938/artifacts/12356964659) |
| `routing-ha-freebsd-windows-nat-router-ha` | pass/pass | I: 1>2:P2P; 1>3:P2P; 2>1:P2P; 2>3:P2P; 3>1:P2P; 3>2:P2P (both)<br>F: 1>2R:P2P; 1>3:P2P; 2>1:P2P; 2>3:-(Idle); 3>1:P2P; 3>2R:-(Idle) (both) | I: 1>2:srflx/srflx; 1>3:srflx/srflx; 2>1:srflx/srflx; 2>3:srflx/host; 3>1:srflx/srflx; 3>2:host/prflx → 1>2:srflx/srflx; 1>3:srflx/srflx; 2>1:host/srflx; 2>3:host/host; 3>1:host/srflx; 3>2:host/host<br>F: 1>2R:srflx/srflx; 1>3:srflx/srflx; 2>1:srflx/prflx; 2>3:-/-; 3>1:srflx/srflx; 3>2R:-/- → 1>2R:srflx/srflx; 1>3:srflx/srflx; 2>1:host/prflx; 2>3:-/-; 3>1:host/srflx; 3>2R:-/- | 1>2:0.605→0.605 [C→D]; 1>2R:1.094→0.848 [D→D]; 1>3:0.604→0.605 [C→D]; 2>1:0.610→0.611 [D→C]; 2>3:1.035→0.001 [D→C]; 3>1:0.610→0.610 [D→C]; 3>2:1.036→0.002 [C→D] | B [12341979890](https://github.com/netbirdio/proxbird-tests/actions/runs/39588288742/artifacts/12341979890)<br>P [12359045773](https://github.com/netbirdio/proxbird-tests/actions/runs/39617144938/artifacts/12359045773) |
| `routing-ha-freebsd-windows-relay-router-ha` | pass/pass | I: 1>2:Relayed; 1>3:Relayed; 2>1:Relayed; 2>3:P2P; 3>1:Relayed; 3>2:P2P (both)<br>F: 1>2R:Relayed; 1>3:Relayed; 2>1:Relayed; 2>3:-(Idle); 3>1:Relayed; 3>2R:-(Idle) (both) | I: 1>2:-/-; 1>3:-/-; 2>1:-/-; 2>3:host/host; 3>1:-/-; 3>2:host/prflx → 1>2:-/-; 1>3:-/-; 2>1:-/-; 2>3:host/host; 3>1:-/-; 3>2:host/host<br>F: 1>2R:-/-; 1>3:-/-; 2>1:-/-; 2>3:-/-; 3>1:-/-; 3>2R:-/- (both) | 1>2:unmeasured→unmeasured [C→C]; 1>2R:unmeasured→unmeasured [C→D]; 1>3:unmeasured→unmeasured [C→C]; 2>1:unmeasured→unmeasured [D→D]; 2>3:0.001→0.002 [C→D]; 3>1:unmeasured→unmeasured [D→D]; 3>2:0.002→0.002 [D→C] | B [12342459433](https://github.com/netbirdio/proxbird-tests/actions/runs/39588288742/artifacts/12342459433)<br>P [12359205343](https://github.com/netbirdio/proxbird-tests/actions/runs/39617144938/artifacts/12359205343) |
| `routing-ha-linux-freebsd-nat-router-ha` | pass/pass | I: 1>2:P2P; 1>3:P2P; 2>1:P2P; 2>3:P2P; 3>1:P2P; 3>2:P2P (both)<br>F: 1>2R:P2P; 1>3:P2P; 2>1:P2P; 2>3:-(Idle); 3>1:P2P; 3>2R:-(Idle) (both) | I: 1>2:srflx/srflx; 1>3:srflx/srflx; 2>1:srflx/srflx; 2>3:host/prflx; 3>1:srflx/srflx; 3>2:host/host → 1>2:host/srflx; 1>3:host/srflx; 2>1:srflx/srflx; 2>3:host/host; 3>1:srflx/srflx; 3>2:host/host<br>F: 1>2R:srflx/prflx; 1>3:srflx/srflx; 2>1:host/srflx; 2>3:-/-; 3>1:srflx/srflx; 3>2R:-/- → 1>2R:host/srflx; 1>3:host/srflx; 2>1:srflx/prflx; 2>3:-/-; 3>1:srflx/srflx; 3>2R:-/- | 1>2:0.604→0.614 [C→C]; 1>2R:0.603→0.605 [D→C]; 1>3:0.603→0.621 [D→C]; 2>1:0.605→0.615 [D→D]; 2>3:0.002→0.001 [D→D]; 3>1:0.604→0.621 [C→D]; 3>2:0.003→0.003 [C→C] | B [12343895149](https://github.com/netbirdio/proxbird-tests/actions/runs/39588288742/artifacts/12343895149)<br>P [12357474478](https://github.com/netbirdio/proxbird-tests/actions/runs/39617144938/artifacts/12357474478) |
| `routing-ha-linux-freebsd-relay-router-ha` | pass/pass | I: 1>2:Relayed; 1>3:Relayed; 2>1:Relayed; 2>3:P2P; 3>1:Relayed; 3>2:P2P (both)<br>F: 1>2R:Relayed; 1>3:Relayed; 2>1:Relayed; 2>3:-(Idle); 3>1:Relayed; 3>2R:-(Idle) (both) | I: 1>2:-/-; 1>3:-/-; 2>1:-/-; 2>3:host/host; 3>1:-/-; 3>2:host/prflx (both)<br>F: 1>2R:-/-; 1>3:-/-; 2>1:-/-; 2>3:-/-; 3>1:-/-; 3>2R:-/- (both) | 1>2:unmeasured→unmeasured [C→C]; 1>2R:unmeasured→unmeasured [D→C]; 1>3:unmeasured→unmeasured [D→C]; 2>1:unmeasured→unmeasured [D→D]; 2>3:1.006→0.002 [D→C]; 3>1:unmeasured→unmeasured [C→D]; 3>2:1.006→0.002 [C→D] | B [12342749776](https://github.com/netbirdio/proxbird-tests/actions/runs/39588288742/artifacts/12342749776)<br>P [12358363273](https://github.com/netbirdio/proxbird-tests/actions/runs/39617144938/artifacts/12358363273) |
| `routing-ha-linux-linux-nat-router-ha` | pass/pass | I: 1>2:P2P; 1>3:P2P; 2>1:P2P; 2>3:P2P; 3>1:P2P; 3>2:P2P (both)<br>F: 1>2R:P2P; 1>3:P2P; 2>1:P2P; 2>3:-(Idle); 3>1:P2P; 3>2R:-(Idle) (both) | I: 1>2:srflx/srflx; 1>3:srflx/srflx; 2>1:srflx/srflx; 2>3:host/host; 3>1:srflx/srflx; 3>2:host/prflx → 1>2:host/prflx; 1>3:host/srflx; 2>1:srflx/srflx; 2>3:host/host; 3>1:srflx/srflx; 3>2:host/prflx<br>F: 1>2R:srflx/srflx; 1>3:srflx/srflx; 2>1:srflx/srflx; 2>3:-/-; 3>1:srflx/srflx; 3>2R:-/- → 1>2R:host/srflx; 1>3:host/srflx; 2>1:srflx/prflx; 2>3:-/-; 3>1:srflx/srflx; 3>2R:-/- | 1>2:0.604→22.164 [D→C]; 1>2R:0.604→0.603 [D→C]; 1>3:0.604→0.604 [D→C]; 2>1:0.605→22.165 [C→D]; 2>3:0.001→1.006 [C→D]; 3>1:0.605→0.604 [C→D]; 3>2:0.003→1.006 [D→C] | B [12343965299](https://github.com/netbirdio/proxbird-tests/actions/runs/39588288742/artifacts/12343965299)<br>P [12359360411](https://github.com/netbirdio/proxbird-tests/actions/runs/39617144938/artifacts/12359360411) |
| `routing-ha-linux-linux-relay-router-ha` | pass/pass | I: 1>2:Relayed; 1>3:Relayed; 2>1:Relayed; 2>3:P2P; 3>1:Relayed; 3>2:P2P (both)<br>F: 1>2R:Relayed; 1>3:Relayed; 2>1:Relayed; 2>3:-(Idle); 3>1:Relayed; 3>2R:-(Idle) (both) | I: 1>2:-/-; 1>3:-/-; 2>1:-/-; 2>3:host/host; 3>1:-/-; 3>2:host/prflx → 1>2:-/-; 1>3:-/-; 2>1:-/-; 2>3:host/host; 3>1:-/-; 3>2:host/host<br>F: 1>2R:-/-; 1>3:-/-; 2>1:-/-; 2>3:-/-; 3>1:-/-; 3>2R:-/- (both) | 1>2:unmeasured→unmeasured [C→D]; 1>2R:unmeasured→unmeasured [C→D]; 1>3:unmeasured→unmeasured [C→D]; 2>1:unmeasured→unmeasured [D→C]; 2>3:0.001→0.002 [C→D]; 3>1:unmeasured→unmeasured [D→C]; 3>2:0.002→0.002 [D→C] | B [12342996420](https://github.com/netbirdio/proxbird-tests/actions/runs/39588288742/artifacts/12342996420)<br>P [12358797288](https://github.com/netbirdio/proxbird-tests/actions/runs/39617144938/artifacts/12358797288) |
| `routing-ha-linux-macos-nat-router-ha` | pass/pass | I: 1>2:P2P; 1>3:P2P; 2>1:P2P; 2>3:P2P; 3>1:P2P; 3>2:P2P (both)<br>F: 1>2R:P2P; 1>3:P2P; 2>1:P2P; 2>3:-(Idle); 3>1:P2P; 3>2R:-(Idle) (both) | I: 1>2:srflx/srflx; 1>3:srflx/srflx; 2>1:srflx/srflx; 2>3:host/host; 3>1:srflx/srflx; 3>2:host/prflx → 1>2:host/srflx; 1>3:host/srflx; 2>1:srflx/srflx; 2>3:host/host; 3>1:srflx/srflx; 3>2:host/prflx<br>F: 1>2R:host/srflx; 1>3:srflx/srflx; 2>1:srflx/prflx; 2>3:-/-; 3>1:srflx/srflx; 3>2R:-/- → 1>2R:host/srflx; 1>3:host/srflx; 2>1:srflx/prflx; 2>3:-/-; 3>1:srflx/srflx; 3>2R:-/- | 1>2:0.610→0.605 [D→C]; 1>2R:0.605→0.604 [C→C]; 1>3:0.603→0.604 [D→C]; 2>1:0.611→0.606 [C→D]; 2>3:0.001→0.001 [C→C]; 3>1:0.605→0.605 [C→D]; 3>2:0.003→0.003 [D→D] | B [12343681042](https://github.com/netbirdio/proxbird-tests/actions/runs/39588288742/artifacts/12343681042)<br>P [12359395707](https://github.com/netbirdio/proxbird-tests/actions/runs/39617144938/artifacts/12359395707) |
| `routing-ha-linux-macos-relay-router-ha` | pass/pass | I: 1>2:Relayed; 1>3:Relayed; 2>1:Relayed; 2>3:P2P; 3>1:Relayed; 3>2:P2P (both)<br>F: 1>2R:Relayed; 1>3:Relayed; 2>1:Relayed; 2>3:-(Idle); 3>1:Relayed; 3>2R:-(Idle) (both) | I: 1>2:-/-; 1>3:-/-; 2>1:-/-; 2>3:host/host; 3>1:-/-; 3>2:host/prflx → 1>2:-/-; 1>3:-/-; 2>1:-/-; 2>3:host/prflx; 3>1:-/-; 3>2:host/host<br>F: 1>2R:-/-; 1>3:-/-; 2>1:-/-; 2>3:-/-; 3>1:-/-; 3>2R:-/- (both) | 1>2:unmeasured→unmeasured [D→C]; 1>2R:unmeasured→unmeasured [C→D]; 1>3:unmeasured→unmeasured [C→D]; 2>1:unmeasured→unmeasured [C→D]; 2>3:0.001→0.002 [C→D]; 3>1:unmeasured→unmeasured [D→C]; 3>2:0.003→0.003 [D→C] | B [12342977038](https://github.com/netbirdio/proxbird-tests/actions/runs/39588288742/artifacts/12342977038)<br>P [12358239205](https://github.com/netbirdio/proxbird-tests/actions/runs/39617144938/artifacts/12358239205) |
| `routing-ha-linux-windows-nat-router-ha` | pass/pass | I: 1>2:P2P; 1>3:P2P; 2>1:P2P; 2>3:P2P; 3>1:P2P; 3>2:P2P (both)<br>F: 1>2R:P2P; 1>3:P2P; 2>1:P2P; 2>3:-(Idle); 3>1:P2P; 3>2R:-(Idle) (both) | I: 1>2:srflx/srflx; 1>3:srflx/srflx; 2>1:srflx/srflx; 2>3:host/host; 3>1:srflx/srflx; 3>2:host/prflx → 1>2:host/srflx; 1>3:host/srflx; 2>1:srflx/srflx; 2>3:host/host; 3>1:srflx/srflx; 3>2:host/host<br>F: 1>2R:srflx/srflx; 1>3:srflx/srflx; 2>1:srflx/prflx; 2>3:-/-; 3>1:srflx/srflx; 3>2R:-/- → 1>2R:host/prflx; 1>3:host/srflx; 2>1:host/srflx; 2>3:-/-; 3>1:srflx/srflx; 3>2R:-/- | 1>2:0.604→0.603 [D→C]; 1>2R:1.014→1.074 [D→C]; 1>3:0.604→0.603 [D→C]; 2>1:0.611→0.609 [C→D]; 2>3:0.002→0.002 [C→D]; 3>1:0.609→0.609 [C→D]; 3>2:0.002→0.003 [D→C] | B [12343451472](https://github.com/netbirdio/proxbird-tests/actions/runs/39588288742/artifacts/12343451472)<br>P [12359295933](https://github.com/netbirdio/proxbird-tests/actions/runs/39617144938/artifacts/12359295933) |
| `routing-ha-linux-windows-relay-router-ha` | pass/pass | I: 1>2:Relayed; 1>3:Relayed; 2>1:Relayed; 2>3:P2P; 3>1:Relayed; 3>2:P2P (both)<br>F: 1>2R:Relayed; 1>3:Relayed; 2>1:Relayed; 2>3:-(Idle); 3>1:Relayed; 3>2R:-(Idle) (both) | I: 1>2:-/-; 1>3:-/-; 2>1:-/-; 2>3:host/host; 3>1:-/-; 3>2:host/prflx → 1>2:-/-; 1>3:-/-; 2>1:-/-; 2>3:srflx/host; 3>1:-/-; 3>2:host/prflx<br>F: 1>2R:-/-; 1>3:-/-; 2>1:-/-; 2>3:-/-; 3>1:-/-; 3>2R:-/- (both) | 1>2:unmeasured→unmeasured [D→C]; 1>2R:unmeasured→unmeasured [D→C]; 1>3:unmeasured→unmeasured [D→D]; 2>1:unmeasured→unmeasured [C→D]; 2>3:1.005→1.008 [D→D]; 3>1:unmeasured→unmeasured [C→C]; 3>2:1.007→1.008 [C→C] | B [12344065894](https://github.com/netbirdio/proxbird-tests/actions/runs/39588288742/artifacts/12344065894)<br>P [12358663499](https://github.com/netbirdio/proxbird-tests/actions/runs/39617144938/artifacts/12358663499) |
| `routing-overlap-freebsd-freebsd-nat-overlap` | pass/pass | I: 1>2:P2P; 1>3:P2P; 2>1:P2P; 2>3:P2P; 3>1:P2P; 3>2:P2P (both)<br>F: 1>2:P2P; 1>3:P2P; 2>1:P2P; 2>3:P2P; 3>1:P2P; 3>2:P2P (both) | I: 1>2:srflx/srflx; 1>3:srflx/srflx; 2>1:srflx/srflx; 2>3:host/prflx; 3>1:srflx/srflx; 3>2:host/host → 1>2:srflx/srflx; 1>3:host/srflx; 2>1:host/srflx; 2>3:host/host; 3>1:srflx/srflx; 3>2:host/prflx<br>F: 1>2:srflx/srflx; 1>3:srflx/srflx; 2>1:srflx/srflx; 2>3:host/prflx; 3>1:srflx/srflx; 3>2:host/host → 1>2:srflx/srflx; 1>3:host/srflx; 2>1:host/srflx; 2>3:host/host; 3>1:srflx/srflx; 3>2:host/prflx | 1>2:0.616→0.622 [C→D]; 1>3:0.614→0.635 [D→C]; 2>1:0.616→0.623 [D→C]; 2>3:0.002→0.002 [D→C]; 3>1:0.615→0.635 [C→D]; 3>2:0.003→0.002 [C→D] | B [12343191665](https://github.com/netbirdio/proxbird-tests/actions/runs/39588288742/artifacts/12343191665)<br>P [12360050273](https://github.com/netbirdio/proxbird-tests/actions/runs/39617144938/artifacts/12360050273) |
| `routing-overlap-freebsd-freebsd-relay-overlap` | pass/pass | I: 1>2:Relayed; 1>3:Relayed; 2>1:Relayed; 2>3:P2P; 3>1:Relayed; 3>2:P2P (both)<br>F: 1>2:Relayed; 1>3:Relayed; 2>1:Relayed; 2>3:P2P; 3>1:Relayed; 3>2:P2P (both) | I: 1>2:-/-; 1>3:-/-; 2>1:-/-; 2>3:host/host; 3>1:-/-; 3>2:host/prflx (both)<br>F: 1>2:-/-; 1>3:-/-; 2>1:-/-; 2>3:host/host; 3>1:-/-; 3>2:host/prflx (both) | 1>2:unmeasured→unmeasured [C→C]; 1>3:unmeasured→unmeasured [D→D]; 2>1:unmeasured→unmeasured [D→D]; 2>3:1.013→1.005 [D→D]; 3>1:unmeasured→unmeasured [C→C]; 3>2:1.014→1.006 [C→C] | B [12343371900](https://github.com/netbirdio/proxbird-tests/actions/runs/39588288742/artifacts/12343371900)<br>P [12359605770](https://github.com/netbirdio/proxbird-tests/actions/runs/39617144938/artifacts/12359605770) |
| `routing-overlap-freebsd-linux-nat-overlap` | pass/pass | I: 1>2:P2P; 1>3:P2P; 2>1:P2P; 2>3:P2P; 3>1:P2P; 3>2:P2P (both)<br>F: 1>2:P2P; 1>3:P2P; 2>1:P2P; 2>3:P2P; 3>1:P2P; 3>2:P2P (both) | I: 1>2:srflx/srflx; 1>3:srflx/srflx; 2>1:srflx/srflx; 2>3:host/host; 3>1:srflx/srflx; 3>2:host/host → 1>2:host/srflx; 1>3:srflx/srflx; 2>1:srflx/srflx; 2>3:host/host; 3>1:host/srflx; 3>2:host/host<br>F: 1>2:srflx/srflx; 1>3:srflx/srflx; 2>1:srflx/srflx; 2>3:host/host; 3>1:srflx/srflx; 3>2:host/host → 1>2:host/srflx; 1>3:srflx/srflx; 2>1:srflx/srflx; 2>3:host/host; 3>1:host/srflx; 3>2:host/host | 1>2:0.603→0.605 [C→C]; 1>3:0.605→0.625 [C→D]; 2>1:0.604→0.605 [D→D]; 2>3:0.001→0.001 [D→D]; 3>1:0.606→0.627 [D→C]; 3>2:0.002→0.002 [C→C] | B [12343267256](https://github.com/netbirdio/proxbird-tests/actions/runs/39588288742/artifacts/12343267256)<br>P [12360320370](https://github.com/netbirdio/proxbird-tests/actions/runs/39617144938/artifacts/12360320370) |
| `routing-overlap-freebsd-linux-relay-overlap` | pass/pass | I: 1>2:Relayed; 1>3:Relayed; 2>1:Relayed; 2>3:P2P; 3>1:Relayed; 3>2:P2P (both)<br>F: 1>2:Relayed; 1>3:Relayed; 2>1:Relayed; 2>3:P2P; 3>1:Relayed; 3>2:P2P (both) | I: 1>2:-/-; 1>3:-/-; 2>1:-/-; 2>3:host/host; 3>1:-/-; 3>2:host/host → 1>2:-/-; 1>3:-/-; 2>1:-/-; 2>3:host/prflx; 3>1:-/-; 3>2:host/host<br>F: 1>2:-/-; 1>3:-/-; 2>1:-/-; 2>3:host/host; 3>1:-/-; 3>2:host/host → 1>2:-/-; 1>3:-/-; 2>1:-/-; 2>3:host/prflx; 3>1:-/-; 3>2:host/host | 1>2:unmeasured→unmeasured [D→C]; 1>3:unmeasured→unmeasured [D→C]; 2>1:unmeasured→unmeasured [C→D]; 2>3:0.002→0.002 [D→D]; 3>1:unmeasured→unmeasured [C→D]; 3>2:0.002→0.003 [C→C] | B [12344161343](https://github.com/netbirdio/proxbird-tests/actions/runs/39588288742/artifacts/12344161343)<br>P [12359741309](https://github.com/netbirdio/proxbird-tests/actions/runs/39617144938/artifacts/12359741309) |
| `routing-overlap-freebsd-macos-nat-overlap` | pass/pass | I: 1>2:P2P; 1>3:P2P; 2>1:P2P; 2>3:P2P; 3>1:P2P; 3>2:P2P (both)<br>F: 1>2:P2P; 1>3:P2P; 2>1:P2P; 2>3:P2P; 3>1:P2P; 3>2:P2P (both) | I: 1>2:srflx/srflx; 1>3:srflx/srflx; 2>1:srflx/srflx; 2>3:host/host; 3>1:srflx/srflx; 3>2:host/prflx → 1>2:srflx/srflx; 1>3:srflx/srflx; 2>1:host/srflx; 2>3:host/host; 3>1:host/srflx; 3>2:host/prflx<br>F: 1>2:srflx/srflx; 1>3:srflx/srflx; 2>1:srflx/srflx; 2>3:host/host; 3>1:srflx/srflx; 3>2:host/prflx → 1>2:srflx/srflx; 1>3:srflx/srflx; 2>1:host/srflx; 2>3:host/host; 3>1:host/srflx; 3>2:host/prflx | 1>2:0.605→0.603 [D→D]; 1>3:0.605→0.645 [D→D]; 2>1:0.607→0.605 [C→C]; 2>3:1.006→0.002 [D→C]; 3>1:0.606→0.647 [C→C]; 3>2:1.006→0.002 [C→D] | B [12343816858](https://github.com/netbirdio/proxbird-tests/actions/runs/39588288742/artifacts/12343816858)<br>P [12359667040](https://github.com/netbirdio/proxbird-tests/actions/runs/39617144938/artifacts/12359667040) |
| `routing-overlap-freebsd-macos-relay-overlap` | pass/pass | I: 1>2:Relayed; 1>3:Relayed; 2>1:Relayed; 2>3:P2P; 3>1:Relayed; 3>2:P2P (both)<br>F: 1>2:Relayed; 1>3:Relayed; 2>1:Relayed; 2>3:P2P; 3>1:Relayed; 3>2:P2P (both) | I: 1>2:-/-; 1>3:-/-; 2>1:-/-; 2>3:host/host; 3>1:-/-; 3>2:host/host → 1>2:-/-; 1>3:-/-; 2>1:-/-; 2>3:host/host; 3>1:-/-; 3>2:host/prflx<br>F: 1>2:-/-; 1>3:-/-; 2>1:-/-; 2>3:host/host; 3>1:-/-; 3>2:host/host → 1>2:-/-; 1>3:-/-; 2>1:-/-; 2>3:host/host; 3>1:-/-; 3>2:host/prflx | 1>2:unmeasured→unmeasured [C→C]; 1>3:unmeasured→unmeasured [C→C]; 2>1:unmeasured→unmeasured [D→D]; 2>3:0.002→1.002 [D→D]; 3>1:unmeasured→unmeasured [D→D]; 3>2:0.002→1.003 [C→C] | B [12343017710](https://github.com/netbirdio/proxbird-tests/actions/runs/39588288742/artifacts/12343017710)<br>P [12358943745](https://github.com/netbirdio/proxbird-tests/actions/runs/39617144938/artifacts/12358943745) |
| `routing-overlap-freebsd-windows-nat-overlap` | pass/pass | I: 1>2:P2P; 1>3:P2P; 2>1:P2P; 2>3:P2P; 3>1:P2P; 3>2:P2P (both)<br>F: 1>2:P2P; 1>3:P2P; 2>1:P2P; 2>3:P2P; 3>1:P2P; 3>2:P2P (both) | I: 1>2:srflx/srflx; 1>3:srflx/srflx; 2>1:srflx/srflx; 2>3:host/host; 3>1:srflx/srflx; 3>2:host/host → 1>2:srflx/srflx; 1>3:host/srflx; 2>1:host/srflx; 2>3:host/host; 3>1:srflx/srflx; 3>2:host/prflx<br>F: 1>2:srflx/srflx; 1>3:srflx/srflx; 2>1:srflx/srflx; 2>3:host/host; 3>1:srflx/srflx; 3>2:host/host → 1>2:srflx/srflx; 1>3:host/srflx; 2>1:host/srflx; 2>3:host/host; 3>1:srflx/srflx; 3>2:host/prflx | 1>2:0.604→0.633 [C→D]; 1>3:0.606→0.603 [C→C]; 2>1:0.608→0.640 [D→C]; 2>3:0.002→0.002 [C→C]; 3>1:0.612→0.609 [D→D]; 3>2:0.002→0.002 [D→D] | B [12343032979](https://github.com/netbirdio/proxbird-tests/actions/runs/39588288742/artifacts/12343032979)<br>P [12358979129](https://github.com/netbirdio/proxbird-tests/actions/runs/39617144938/artifacts/12358979129) |
| `routing-overlap-freebsd-windows-relay-overlap` | pass/pass | I: 1>2:Relayed; 1>3:Relayed; 2>1:Relayed; 2>3:P2P; 3>1:Relayed; 3>2:P2P (both)<br>F: 1>2:Relayed; 1>3:Relayed; 2>1:Relayed; 2>3:P2P; 3>1:Relayed; 3>2:P2P (both) | I: 1>2:-/-; 1>3:-/-; 2>1:-/-; 2>3:host/host; 3>1:-/-; 3>2:host/host → 1>2:-/-; 1>3:-/-; 2>1:-/-; 2>3:host/host; 3>1:-/-; 3>2:host/prflx<br>F: 1>2:-/-; 1>3:-/-; 2>1:-/-; 2>3:host/host; 3>1:-/-; 3>2:host/host → 1>2:-/-; 1>3:-/-; 2>1:-/-; 2>3:host/host; 3>1:-/-; 3>2:host/prflx | 1>2:unmeasured→unmeasured [C→C]; 1>3:unmeasured→unmeasured [C→C]; 2>1:unmeasured→unmeasured [D→D]; 2>3:0.001→0.001 [C→C]; 3>1:unmeasured→unmeasured [D→D]; 3>2:0.002→0.004 [D→D] | B [12343043067](https://github.com/netbirdio/proxbird-tests/actions/runs/39588288742/artifacts/12343043067)<br>P [12360316076](https://github.com/netbirdio/proxbird-tests/actions/runs/39617144938/artifacts/12360316076) |
| `routing-overlap-linux-freebsd-nat-overlap` | pass/pass | I: 1>2:P2P; 1>3:P2P; 2>1:P2P; 2>3:P2P; 3>1:P2P; 3>2:P2P (both)<br>F: 1>2:P2P; 1>3:P2P; 2>1:P2P; 2>3:P2P; 3>1:P2P; 3>2:P2P (both) | I: 1>2:srflx/srflx; 1>3:srflx/srflx; 2>1:srflx/srflx; 2>3:host/host; 3>1:srflx/srflx; 3>2:host/prflx → 1>2:srflx/srflx; 1>3:host/srflx; 2>1:host/srflx; 2>3:host/host; 3>1:srflx/srflx; 3>2:host/prflx<br>F: 1>2:srflx/srflx; 1>3:srflx/srflx; 2>1:srflx/srflx; 2>3:host/host; 3>1:srflx/srflx; 3>2:host/prflx → 1>2:srflx/srflx; 1>3:host/srflx; 2>1:host/srflx; 2>3:host/host; 3>1:srflx/srflx; 3>2:host/prflx | 1>2:0.604→0.603 [D→D]; 1>3:0.603→0.614 [D→C]; 2>1:0.606→0.605 [C→C]; 2>3:1.005→0.001 [D→C]; 3>1:0.604→0.614 [C→D]; 3>2:1.006→0.001 [C→D] | B [12343827402](https://github.com/netbirdio/proxbird-tests/actions/runs/39588288742/artifacts/12343827402)<br>P [12358664805](https://github.com/netbirdio/proxbird-tests/actions/runs/39617144938/artifacts/12358664805) |
| `routing-overlap-linux-freebsd-relay-overlap` | pass/pass | I: 1>2:Relayed; 1>3:Relayed; 2>1:Relayed; 2>3:P2P; 3>1:Relayed; 3>2:P2P (both)<br>F: 1>2:Relayed; 1>3:Relayed; 2>1:Relayed; 2>3:P2P; 3>1:Relayed; 3>2:P2P (both) | I: 1>2:-/-; 1>3:-/-; 2>1:-/-; 2>3:host/host; 3>1:-/-; 3>2:host/prflx (both)<br>F: 1>2:-/-; 1>3:-/-; 2>1:-/-; 2>3:host/host; 3>1:-/-; 3>2:host/prflx (both) | 1>2:unmeasured→unmeasured [D→C]; 1>3:unmeasured→unmeasured [D→C]; 2>1:unmeasured→unmeasured [C→D]; 2>3:1.005→0.002 [D→C]; 3>1:unmeasured→unmeasured [C→D]; 3>2:1.006→0.002 [C→D] | B [12342939237](https://github.com/netbirdio/proxbird-tests/actions/runs/39588288742/artifacts/12342939237)<br>P [12359267484](https://github.com/netbirdio/proxbird-tests/actions/runs/39617144938/artifacts/12359267484) |
| `routing-overlap-linux-linux-nat-overlap` | pass/pass | I: 1>2:P2P; 1>3:P2P; 2>1:P2P; 2>3:P2P; 3>1:P2P; 3>2:P2P (both)<br>F: 1>2:P2P; 1>3:P2P; 2>1:P2P; 2>3:P2P; 3>1:P2P; 3>2:P2P (both) | I: 1>2:srflx/srflx; 1>3:srflx/srflx; 2>1:srflx/srflx; 2>3:host/prflx; 3>1:srflx/srflx; 3>2:host/host → 1>2:srflx/srflx; 1>3:host/srflx; 2>1:host/srflx; 2>3:host/host; 3>1:srflx/srflx; 3>2:host/host<br>F: 1>2:srflx/srflx; 1>3:srflx/srflx; 2>1:srflx/srflx; 2>3:host/prflx; 3>1:srflx/srflx; 3>2:host/host → 1>2:srflx/srflx; 1>3:host/srflx; 2>1:host/srflx; 2>3:host/host; 3>1:srflx/srflx; 3>2:host/host | 1>2:0.605→0.604 [C→D]; 1>3:0.604→0.604 [C→C]; 2>1:0.605→0.605 [D→C]; 2>3:0.002→0.001 [D→C]; 3>1:0.605→0.605 [D→D]; 3>2:0.003→0.002 [C→D] | B [12343907815](https://github.com/netbirdio/proxbird-tests/actions/runs/39588288742/artifacts/12343907815)<br>P [12359687246](https://github.com/netbirdio/proxbird-tests/actions/runs/39617144938/artifacts/12359687246) |
| `routing-overlap-linux-linux-relay-overlap` | pass/pass | I: 1>2:Relayed; 1>3:Relayed; 2>1:Relayed; 2>3:P2P; 3>1:Relayed; 3>2:P2P (both)<br>F: 1>2:Relayed; 1>3:Relayed; 2>1:Relayed; 2>3:P2P; 3>1:Relayed; 3>2:P2P (both) | I: 1>2:-/-; 1>3:-/-; 2>1:-/-; 2>3:host/host; 3>1:-/-; 3>2:host/prflx (both)<br>F: 1>2:-/-; 1>3:-/-; 2>1:-/-; 2>3:host/host; 3>1:-/-; 3>2:host/prflx (both) | 1>2:unmeasured→unmeasured [C→C]; 1>3:unmeasured→unmeasured [D→C]; 2>1:unmeasured→unmeasured [D→D]; 2>3:1.005→0.002 [D→C]; 3>1:unmeasured→unmeasured [C→D]; 3>2:1.006→0.002 [C→D] | B [12343882660](https://github.com/netbirdio/proxbird-tests/actions/runs/39588288742/artifacts/12343882660)<br>P [12359083302](https://github.com/netbirdio/proxbird-tests/actions/runs/39617144938/artifacts/12359083302) |
| `routing-overlap-linux-macos-nat-overlap` | pass/pass | I: 1>2:P2P; 1>3:P2P; 2>1:P2P; 2>3:P2P; 3>1:P2P; 3>2:P2P (both)<br>F: 1>2:P2P; 1>3:P2P; 2>1:P2P; 2>3:P2P; 3>1:P2P; 3>2:P2P (both) | I: 1>2:srflx/srflx; 1>3:srflx/srflx; 2>1:srflx/srflx; 2>3:host/host; 3>1:srflx/srflx; 3>2:host/host → 1>2:srflx/srflx; 1>3:host/srflx; 2>1:host/srflx; 2>3:host/host; 3>1:srflx/srflx; 3>2:host/host<br>F: 1>2:srflx/srflx; 1>3:srflx/srflx; 2>1:srflx/srflx; 2>3:host/host; 3>1:srflx/srflx; 3>2:host/host → 1>2:srflx/srflx; 1>3:host/srflx; 2>1:host/srflx; 2>3:host/host; 3>1:srflx/srflx; 3>2:host/host | 1>2:0.605→0.604 [C→D]; 1>3:0.604→0.605 [C→C]; 2>1:0.606→0.606 [D→C]; 2>3:0.002→0.002 [D→C]; 3>1:0.605→0.606 [D→D]; 3>2:0.003→0.002 [C→D] | B [12343863067](https://github.com/netbirdio/proxbird-tests/actions/runs/39588288742/artifacts/12343863067)<br>P [12360326638](https://github.com/netbirdio/proxbird-tests/actions/runs/39617144938/artifacts/12360326638) |
| `routing-overlap-linux-macos-relay-overlap` | pass/pass | I: 1>2:Relayed; 1>3:Relayed; 2>1:Relayed; 2>3:P2P; 3>1:Relayed; 3>2:P2P (both)<br>F: 1>2:Relayed; 1>3:Relayed; 2>1:Relayed; 2>3:P2P; 3>1:Relayed; 3>2:P2P (both) | I: 1>2:-/-; 1>3:-/-; 2>1:-/-; 2>3:host/prflx; 3>1:-/-; 3>2:host/host → 1>2:-/-; 1>3:-/-; 2>1:-/-; 2>3:host/host; 3>1:-/-; 3>2:host/prflx<br>F: 1>2:-/-; 1>3:-/-; 2>1:-/-; 2>3:host/prflx; 3>1:-/-; 3>2:host/host → 1>2:-/-; 1>3:-/-; 2>1:-/-; 2>3:host/host; 3>1:-/-; 3>2:host/prflx | 1>2:unmeasured→unmeasured [C→C]; 1>3:unmeasured→unmeasured [C→D]; 2>1:unmeasured→unmeasured [D→D]; 2>3:0.002→1.006 [D→D]; 3>1:unmeasured→unmeasured [D→C]; 3>2:0.004→1.005 [C→C] | B [12344073381](https://github.com/netbirdio/proxbird-tests/actions/runs/39588288742/artifacts/12344073381)<br>P [12359058800](https://github.com/netbirdio/proxbird-tests/actions/runs/39617144938/artifacts/12359058800) |
| `routing-overlap-linux-windows-nat-overlap` | pass/pass | I: 1>2:P2P; 1>3:P2P; 2>1:P2P; 2>3:P2P; 3>1:P2P; 3>2:P2P (both)<br>F: 1>2:P2P; 1>3:P2P; 2>1:P2P; 2>3:P2P; 3>1:P2P; 3>2:P2P (both) | I: 1>2:srflx/srflx; 1>3:srflx/srflx; 2>1:srflx/srflx; 2>3:host/prflx; 3>1:srflx/srflx; 3>2:host/host → 1>2:srflx/srflx; 1>3:host/srflx; 2>1:host/srflx; 2>3:host/host; 3>1:srflx/srflx; 3>2:host/host<br>F: 1>2:srflx/srflx; 1>3:srflx/srflx; 2>1:srflx/srflx; 2>3:host/prflx; 3>1:srflx/srflx; 3>2:host/host → 1>2:srflx/srflx; 1>3:host/srflx; 2>1:host/srflx; 2>3:host/host; 3>1:srflx/srflx; 3>2:host/host | 1>2:0.605→0.604 [D→D]; 1>3:0.606→0.603 [D→C]; 2>1:0.612→0.611 [C→C]; 2>3:0.001→0.001 [D→C]; 3>1:0.612→0.609 [C→D]; 3>2:0.003→0.002 [C→D] | B [12344238383](https://github.com/netbirdio/proxbird-tests/actions/runs/39588288742/artifacts/12344238383)<br>P [12360332417](https://github.com/netbirdio/proxbird-tests/actions/runs/39617144938/artifacts/12360332417) |
| `routing-overlap-linux-windows-relay-overlap` | pass/pass | I: 1>2:Relayed; 1>3:Relayed; 2>1:Relayed; 2>3:P2P; 3>1:Relayed; 3>2:P2P (both)<br>F: 1>2:Relayed; 1>3:Relayed; 2>1:Relayed; 2>3:P2P; 3>1:Relayed; 3>2:P2P (both) | I: 1>2:-/-; 1>3:-/-; 2>1:-/-; 2>3:host/host; 3>1:-/-; 3>2:host/prflx → 1>2:-/-; 1>3:-/-; 2>1:-/-; 2>3:host/host; 3>1:-/-; 3>2:host/host<br>F: 1>2:-/-; 1>3:-/-; 2>1:-/-; 2>3:host/host; 3>1:-/-; 3>2:host/prflx → 1>2:-/-; 1>3:-/-; 2>1:-/-; 2>3:host/host; 3>1:-/-; 3>2:host/host | 1>2:unmeasured→unmeasured [C→C]; 1>3:unmeasured→unmeasured [C→C]; 2>1:unmeasured→unmeasured [D→D]; 2>3:1.004→0.002 [D→C]; 3>1:unmeasured→unmeasured [D→D]; 3>2:1.004→0.002 [C→D] | B [12344213368](https://github.com/netbirdio/proxbird-tests/actions/runs/39588288742/artifacts/12344213368)<br>P [12359518542](https://github.com/netbirdio/proxbird-tests/actions/runs/39617144938/artifacts/12359518542) |
| `windows-macos-direct` | pass/pass | I: 1>2:P2P; 2>1:P2P (both)<br>F: 1>2:P2P; 2>1:P2P (both) | I: 1>2:host/host; 2>1:host/prflx (both)<br>F: 1>2:host/host; 2>1:host/prflx (both) | 1>2:1.005→1.005 [D→D]; 2>1:1.012→1.010 [C→C] | B [12344470088](https://github.com/netbirdio/proxbird-tests/actions/runs/39588288742/artifacts/12344470088)<br>P [12360271553](https://github.com/netbirdio/proxbird-tests/actions/runs/39617144938/artifacts/12360271553) |
| `windows-macos-nat` | pass/pass | I: 1>2:P2P; 2>1:P2P (both)<br>F: 1>2:P2P; 2>1:P2P (both) | I: 1>2:srflx/srflx; 2>1:srflx/srflx → 1>2:srflx/srflx; 2>1:host/srflx<br>F: 1>2:srflx/srflx; 2>1:srflx/srflx → 1>2:srflx/srflx; 2>1:host/srflx | 1>2:0.604→0.605 [C→D]; 2>1:0.611→0.612 [D→C] | B [12344267668](https://github.com/netbirdio/proxbird-tests/actions/runs/39588288742/artifacts/12344267668)<br>P [12359828509](https://github.com/netbirdio/proxbird-tests/actions/runs/39617144938/artifacts/12359828509) |
| `windows-macos-relay` | pass/pass | I: 1>2:Relayed; 2>1:Relayed (both)<br>F: 1>2:Relayed; 2>1:Relayed (both) | I: 1>2:-/-; 2>1:-/- (both)<br>F: 1>2:-/-; 2>1:-/- (both) | 1>2:unmeasured→unmeasured [C→D]; 2>1:unmeasured→unmeasured [D→C] | B [12343304366](https://github.com/netbirdio/proxbird-tests/actions/runs/39588288742/artifacts/12343304366)<br>P [12359612635](https://github.com/netbirdio/proxbird-tests/actions/runs/39617144938/artifacts/12359612635) |
| `windows-macos-slow` | pass/pass | I: 1>2:P2P; 2>1:P2P (both)<br>F: 1>2:P2P; 2>1:P2P (both) | I: 1>2:srflx/srflx; 2>1:srflx/srflx → 1>2:host/srflx; 2>1:srflx/srflx<br>F: 1>2:srflx/srflx; 2>1:srflx/srflx → 1>2:host/srflx; 2>1:srflx/srflx | 1>2:0.703→0.706 [C→C]; 2>1:0.709→0.711 [D→D] | B [12343384214](https://github.com/netbirdio/proxbird-tests/actions/runs/39588288742/artifacts/12343384214)<br>P [12360287322](https://github.com/netbirdio/proxbird-tests/actions/runs/39617144938/artifacts/12360287322) |
| `windows-windows-direct` | pass/pass | I: 1>2:P2P; 2>1:P2P (both)<br>F: 1>2:P2P; 2>1:P2P (both) | I: 1>2:host/host; 2>1:host/host (both)<br>F: 1>2:host/host; 2>1:host/host (both) | 1>2:0.003→0.005 [D→D]; 2>1:0.003→0.012 [C→C] | B [12343094771](https://github.com/netbirdio/proxbird-tests/actions/runs/39588288742/artifacts/12343094771)<br>P [12360566620](https://github.com/netbirdio/proxbird-tests/actions/runs/39617144938/artifacts/12360566620) |
| `windows-windows-nat` | pass/pass | I: 1>2:P2P; 2>1:P2P (both)<br>F: 1>2:P2P; 2>1:P2P (both) | I: 1>2:srflx/srflx; 2>1:srflx/srflx → 1>2:srflx/srflx; 2>1:host/srflx<br>F: 1>2:srflx/srflx; 2>1:srflx/srflx → 1>2:srflx/srflx; 2>1:host/srflx | 1>2:0.607→0.607 [D→D]; 2>1:0.678→0.605 [C→C] | B [12343848656](https://github.com/netbirdio/proxbird-tests/actions/runs/39588288742/artifacts/12343848656)<br>P [12360791116](https://github.com/netbirdio/proxbird-tests/actions/runs/39617144938/artifacts/12360791116) |
| `windows-windows-relay` | pass/pass | I: 1>2:Relayed; 2>1:Relayed (both)<br>F: 1>2:Relayed; 2>1:Relayed (both) | I: 1>2:-/-; 2>1:-/- (both)<br>F: 1>2:-/-; 2>1:-/- (both) | 1>2:unmeasured→unmeasured [D→D]; 2>1:unmeasured→unmeasured [C→C] | B [12344585735](https://github.com/netbirdio/proxbird-tests/actions/runs/39588288742/artifacts/12344585735)<br>P [12359454619](https://github.com/netbirdio/proxbird-tests/actions/runs/39617144938/artifacts/12359454619) |
| `windows-windows-slow` | pass/pass | I: 1>2:P2P; 2>1:P2P (both)<br>F: 1>2:P2P; 2>1:P2P (both) | I: 1>2:srflx/srflx; 2>1:srflx/srflx → 1>2:srflx/srflx; 2>1:host/srflx<br>F: 1>2:srflx/srflx; 2>1:srflx/srflx → 1>2:srflx/srflx; 2>1:host/srflx | 1>2:0.704→0.703 [D→D]; 2>1:0.906→0.911 [C→C] | B [12344133648](https://github.com/netbirdio/proxbird-tests/actions/runs/39588288742/artifacts/12344133648)<br>P [12360547086](https://github.com/netbirdio/proxbird-tests/actions/runs/39617144938/artifacts/12360547086) |

### Source42 single samples versus three-run baseline medians

This comparison covers exactly 20 client cases in [source42 run 39617144938](https://github.com/netbirdio/proxbird-tests/actions/runs/39617144938), pinned to `42b087a4b5fb0dfcb111c46864d3340194a5a748`. Nineteen cases pass and provide one modern-peer ICE timing sample each. FreeBSD allowed-ports fails before client installation and remains unmeasured. The surrounding 85-case workflow is outside this table; this comparison does not claim its overall result or validate later production revisions.

The baseline is `1e63b68c4dc243a32fef823df1bc024c997a9c60`: B1 [39588288742](https://github.com/netbirdio/proxbird-tests/actions/runs/39588288742), B2 [39608330203](https://github.com/netbirdio/proxbird-tests/actions/runs/39608330203), and B3 [39608353253](https://github.com/netbirdio/proxbird-tests/actions/runs/39608353253). Each baseline median uses three native first-dial-to-first-success observations for the same case. B1 and source42 use the larger 85-case selection; B2/B3 select the 20 client cases. All use harness `a1abca530f93969ad81f11a9683dc6e89171a23c`.

The interval starts at the first observed modern peer-1 ICE dial and ends at its first success, including failed attempts and retry gaps, measured within one node clock. It excludes earlier setup/signalling and later application readiness. It is not a setup-step duration or application-observed time to P2P. Legacy peer-2 timing markers are incompatible and remain unmeasured. Source42 has **one observation, not a median**, for each measurable case.

C means intended controlling and D means intended controlled, derived from native own/remote public keys using the unchanged source comparator. Actual STUN role attributes and role conflicts are unlogged. The baseline role sequence is B1/B2/B3. A positive difference means the single source42 sample took longer than the descriptive baseline median; it is not proof of a revision-caused regression.

| Case | Baseline median s (n=3) | Source42 single s | Difference s | Source42 attempts | Intended roles B1/B2/B3 → source42 | Source42 artifact |
| --- | ---: | ---: | ---: | ---: | --- | --- |
| `client-freebsd-nat-allowed-ports` | 0.603 | unmeasured: setup failure | — | — | D/D/D → unmeasured | [12355883225](https://github.com/netbirdio/proxbird-tests/actions/runs/39617144938/artifacts/12355883225) |
| `client-freebsd-nat-connect-legacy` | 0.604 | 0.622 | +0.018 | 1 | D/D/D → C | [12355269550](https://github.com/netbirdio/proxbird-tests/actions/runs/39617144938/artifacts/12355269550) |
| `client-freebsd-nat-connect-relay` | 0.613 | 0.604 | -0.009 | 1 | C/D/C → D | [12356651282](https://github.com/netbirdio/proxbird-tests/actions/runs/39617144938/artifacts/12356651282) |
| `client-freebsd-nat-dns` | 0.610 | 0.632 | +0.022 | 1 | D/D/C → C | [12355754010](https://github.com/netbirdio/proxbird-tests/actions/runs/39617144938/artifacts/12355754010) |
| `client-freebsd-nat-exit-node` | 0.615 | 0.617 | +0.002 | 1 | C/D/C → C | [12355209860](https://github.com/netbirdio/proxbird-tests/actions/runs/39617144938/artifacts/12355209860) |
| `client-linux-nat-allowed-ports` | 0.606 | 28.735 | +28.129 | 3 | C/D/C → D | [12355659252](https://github.com/netbirdio/proxbird-tests/actions/runs/39617144938/artifacts/12355659252) |
| `client-linux-nat-connect-legacy` | 0.604 | 0.604 | +0.000 | 1 | D/D/C → D | [12355379464](https://github.com/netbirdio/proxbird-tests/actions/runs/39617144938/artifacts/12355379464) |
| `client-linux-nat-connect-relay` | 0.605 | 0.604 | -0.001 | 1 | D/D/C → D | [12355513657](https://github.com/netbirdio/proxbird-tests/actions/runs/39617144938/artifacts/12355513657) |
| `client-linux-nat-dns` | 0.605 | 0.605 | +0.000 | 1 | C/C/C → D | [12356606740](https://github.com/netbirdio/proxbird-tests/actions/runs/39617144938/artifacts/12356606740) |
| `client-linux-nat-exit-node` | 0.606 | 0.605 | -0.001 | 1 | C/D/D → D | [12356726558](https://github.com/netbirdio/proxbird-tests/actions/runs/39617144938/artifacts/12356726558) |
| `client-macos-nat-allowed-ports` | 0.606 | 0.605 | -0.001 | 1 | D/C/D → D | [12355844324](https://github.com/netbirdio/proxbird-tests/actions/runs/39617144938/artifacts/12355844324) |
| `client-macos-nat-connect-legacy` | 0.605 | 0.606 | +0.001 | 1 | D/C/D → D | [12357000785](https://github.com/netbirdio/proxbird-tests/actions/runs/39617144938/artifacts/12357000785) |
| `client-macos-nat-connect-relay` | 0.604 | 0.605 | +0.001 | 1 | D/D/D → D | [12357050864](https://github.com/netbirdio/proxbird-tests/actions/runs/39617144938/artifacts/12357050864) |
| `client-macos-nat-dns` | 0.606 | 0.605 | -0.001 | 1 | C/C/C → D | [12356239678](https://github.com/netbirdio/proxbird-tests/actions/runs/39617144938/artifacts/12356239678) |
| `client-macos-nat-exit-node` | 0.605 | 0.606 | +0.001 | 1 | D/D/C → C | [12357135451](https://github.com/netbirdio/proxbird-tests/actions/runs/39617144938/artifacts/12357135451) |
| `client-windows-nat-allowed-ports` | 13.508 | 16.263 | +2.755 | 2 | C/C/D → D | [12357110690](https://github.com/netbirdio/proxbird-tests/actions/runs/39617144938/artifacts/12357110690) |
| `client-windows-nat-connect-legacy` | 13.882 | 14.527 | +0.645 | 2 | D/D/C → C | [12357480493](https://github.com/netbirdio/proxbird-tests/actions/runs/39617144938/artifacts/12357480493) |
| `client-windows-nat-connect-relay` | 0.608 | 23.113 | +22.505 | 2 | C/D/C → C | [12356458569](https://github.com/netbirdio/proxbird-tests/actions/runs/39617144938/artifacts/12356458569) |
| `client-windows-nat-dns` | 20.673 | 16.171 | -4.502 | 2 | C/C/D → D | [12356059621](https://github.com/netbirdio/proxbird-tests/actions/runs/39617144938/artifacts/12356059621) |
| `client-windows-nat-exit-node` | 0.606 | 22.465 | +21.859 | 2 | D/D/D → C | [12356937109](https://github.com/netbirdio/proxbird-tests/actions/runs/39617144938/artifacts/12356937109) |

Candidate and path evidence below separates the **initial assertion snapshot (I)** from the **final diagnostic snapshot (F)**. M denotes modern peer-1→legacy peer-2; L denotes the reverse direction. All available source42 I/F observations are Connected/P2P. Baseline modern observations are also Connected/P2P unless an exception is shown; additionally, B1 Windows DNS legacy final status is Connected/Relayed with no ICE pair. Candidate strings are local/remote types, not packet paths or proof of which candidate reader handled a STUN message. I/F snapshots need not match the first successful ICE pair, especially after DNS or reconnect actions. All baseline reverse-direction snapshots, exact source42 native first-dial/success references and stable artifact/internal paths are retained in the companion JSON.

| Case | Baseline modern I → F (B1; B2; B3) | Source42 modern I → F | Source42 legacy I → F |
| --- | --- | --- | --- |
| `client-freebsd-nat-allowed-ports` | B1: host/srflx → host/prflx<br>B2: host/srflx → host/prflx<br>B3: host/srflx → host/srflx | unmeasured → unmeasured | unmeasured → unmeasured |
| `client-freebsd-nat-connect-legacy` | B1: host/srflx → host/srflx<br>B2: host/srflx → host/srflx<br>B3: host/srflx → host/srflx | srflx/srflx → srflx/srflx | srflx/srflx → srflx/srflx |
| `client-freebsd-nat-connect-relay` | B1: srflx/srflx → srflx/srflx<br>B2: host/srflx → host/srflx<br>B3: host/srflx → host/srflx | host/srflx → host/srflx | host/srflx → host/srflx |
| `client-freebsd-nat-dns` | B1: host/srflx → host/srflx<br>B2: srflx/srflx → srflx/srflx<br>B3: host/srflx → host/srflx | host/srflx → host/srflx | host/srflx → host/srflx |
| `client-freebsd-nat-exit-node` | B1: host/srflx → host/srflx<br>B2: host/srflx → host/srflx<br>B3: host/srflx → host/srflx | srflx/srflx → srflx/srflx | host/srflx → host/srflx |
| `client-linux-nat-allowed-ports` | B1: host/srflx → host/prflx<br>B2: host/srflx → host/prflx<br>B3: host/srflx → host/prflx | host/prflx → host/prflx | srflx/srflx → host/srflx |
| `client-linux-nat-connect-legacy` | B1: srflx/srflx → srflx/srflx<br>B2: host/srflx → host/srflx<br>B3: srflx/srflx → srflx/srflx | host/srflx → host/srflx | host/srflx → host/srflx |
| `client-linux-nat-connect-relay` | B1: host/srflx → host/srflx<br>B2: host/srflx → host/srflx<br>B3: host/srflx → host/srflx | host/srflx → host/srflx | host/srflx → host/srflx |
| `client-linux-nat-dns` | B1: host/srflx → host/srflx<br>B2: host/srflx → host/srflx<br>B3: host/srflx → host/srflx | host/srflx → host/srflx | srflx/srflx → srflx/srflx |
| `client-linux-nat-exit-node` | B1: host/srflx → host/srflx<br>B2: srflx/srflx → srflx/srflx<br>B3: host/srflx → host/srflx | host/srflx → host/srflx | host/srflx → host/srflx |
| `client-macos-nat-allowed-ports` | B1: host/srflx → srflx/prflx<br>B2: host/srflx → srflx/prflx<br>B3: host/srflx → host/prflx | host/srflx → host/prflx | host/srflx → host/srflx |
| `client-macos-nat-connect-legacy` | B1: host/srflx → host/srflx<br>B2: srflx/srflx → srflx/srflx<br>B3: host/srflx → host/srflx | host/srflx → host/srflx | host/srflx → host/srflx |
| `client-macos-nat-connect-relay` | B1: host/srflx → host/srflx<br>B2: host/srflx → host/srflx<br>B3: srflx/srflx → srflx/srflx | host/srflx → host/srflx | host/srflx → host/srflx |
| `client-macos-nat-dns` | B1: srflx/srflx → srflx/srflx<br>B2: host/srflx → host/srflx<br>B3: srflx/srflx → srflx/srflx | host/srflx → host/srflx | host/srflx → host/srflx |
| `client-macos-nat-exit-node` | B1: srflx/srflx → srflx/srflx<br>B2: host/srflx → host/srflx<br>B3: srflx/srflx → srflx/srflx | host/srflx → host/srflx | host/srflx → host/srflx |
| `client-windows-nat-allowed-ports` | B1: host/srflx → host/srflx<br>B2: host/srflx → host/srflx<br>B3: host/srflx → host/srflx | host/prflx → host/srflx | host/srflx → host/srflx |
| `client-windows-nat-connect-legacy` | B1: host/srflx → host/srflx<br>B2: host/srflx → host/srflx<br>B3: host/srflx → host/srflx | srflx/srflx → srflx/srflx | host/srflx → host/srflx |
| `client-windows-nat-connect-relay` | B1: host/srflx → host/srflx<br>B2: host/srflx → host/srflx<br>B3: host/srflx → host/srflx | srflx/srflx → srflx/srflx | host/prflx → host/prflx |
| `client-windows-nat-dns` | B1: host/srflx → -/- [Connecting/-]<br>B2: host/srflx → -/- [Connecting/-]<br>B3: host/srflx → host/srflx | host/prflx → host/srflx | host/srflx → host/prflx |
| `client-windows-nat-exit-node` | B1: host/srflx → host/srflx<br>B2: host/srflx → host/srflx<br>B3: host/srflx → host/srflx | srflx/srflx → srflx/srflx | host/prflx → host/prflx |

The largest positive single-sample differences are Linux allowed-ports 0.606→28.735 seconds (+28.129; three attempts), Windows connect-relay 0.608→23.113 (+22.505; two), and Windows exit-node 0.606→22.465 (+21.859; two). Windows DNS is 20.673→16.171 (−4.502; two). These are comparisons against baseline medians, not repeated source42 estimates. The longer first-success intervals require investigation even when the eventual case passes.

Among the 19 measurable cases, source42's intended role differs from 33 of the 57 individual baseline observations. Windows exit-node is baseline D/D/D versus source42 C; Linux allowed-ports is C/D/C versus D; Windows connect-relay is C/D/C versus C. Role, candidate ordering and concurrent workload remain confounds. No causal mux attribution follows from this table.

Comparing the single source42 snapshot against each baseline run in both directions yields 114 directed snapshot comparisons per phase, reusing source42's 38 directed observations. Initial path/status changes: 0; final: 3. All three final differences are Windows DNS: modern-peer baseline Connecting snapshots in B1/B2 and legacy B1 Connected/Relayed, versus both directions Connected/P2P in source42 after the service-restart action. Candidate-pair type changes are 55 initial and 45 final; local-type changes are 39 initial and 41 final. These counts describe snapshot differences, not failed cases or independent source42 samples.

FreeBSD allowed-ports must remain null: [artifact 12355883225](https://github.com/netbirdio/proxbird-tests/actions/runs/39617144938/artifacts/12355883225), [job 119304353650](https://github.com/netbirdio/proxbird-tests/actions/runs/39617144938/job/119304353650), `results/95becb95d7003971bc7d9a00beec47bd/robot/output.xml:10–12` records Proxmox guest-exec HTTP596 while stopping the artifact server, before installation. Readiness, reconnect and traffic keywords are NOT RUN; both peer status files report `netbird: command not found`, bundles are absent and log archives are empty/invalid. Its 20 inventoried files match recorded hashes/sizes, which preserves failure evidence without making it complete native evidence. The focused `freebsd-allowed-ports-failure.md` and JSON retain the classification and exact provenance.

The companion `source42-client-vs-baseline-median.json` retains all 60 baseline samples and role evidence, 19 measured source42 records plus the null case, both directions of I/F candidate/path snapshots, native archive members/line numbers, immutable workflow/artifact links and input snapshot hashes. Timing input snapshot: `2026-10-21T15:39:33.741947+00:00`. The mixed references remain 0.28.9/0.30.1; this table does not establish current-release interoperability or validate later production fixes.

### Source42 native findings — nine focus cases

**Scope:** nine reviewed focus cases from [run 39617144938](https://github.com/netbirdio/proxbird-tests/actions/runs/39617144938), pinned to [42b087a](https://github.com/netbirdio/netbird/commit/42b087a4b5fb0dfcb111c46864d3340194a5a748). These nine artifacts passed their scenario checks; their timing observations and limitations are detailed below. Aggregate workflow coverage is tracked separately. Baseline is [run 39588288742](https://github.com/netbirdio/proxbird-tests/actions/runs/39588288742) at [1e63b68c](https://github.com/netbirdio/netbird/commit/1e63b68c4dc243a32fef823df1bc024c997a9c60).

This run does **not** validate newer pushed [145a4ab8](https://github.com/netbirdio/netbird/commit/145a4ab86c27b8658c18308b33aa4c41109a52a5), whose production code is unchanged from [24817004](https://github.com/netbirdio/netbird/commit/24817004b0889477fee849999c6c6fad664f7415). Source42 lacks the newer per-candidate queues and bounded recent-owner retention for legacy duplicates.

**Metric and limits:** first observed modern `agent dial` → first `agent dial succeeded` for a local archive role and exact remote key, including failed attempts and retry gaps. It excludes earlier setup and ends before application readiness. These paired native comparisons use one workflow per source/topology and do not establish application time-to-P2P or repeated-run medians. All subtraction is within one native node clock; older legacy markers remain unmeasured, not zero. Intended role uses native client-start/own-key provenance and the unchanged lexical key comparison. Actual ICE role-conflict transitions are unobserved. Callback ordering and address registration do not trace individual STUN delivery or establish a mux cause.

#### Timings and portable anchors

Numbers are **seconds / attempts**. `P1` and `P2` mean archive node labels, not ICE roles. `C` = intended controlling; `D` = intended controlled. A line pair is first dial → first success. Original HA peer-2 and its replacement are distinct keys.

| Focus | Baseline → source42 | Intended role baseline → 42 | Native line pair baseline → 42 |
|---|---|---|---|
| Linux relay, P1 | 0.605/1 → 0.604/1 | D → D | P1 276→305; 276→307 |
| Linux allowed ports, P1 | 0.606/1 → 28.735/3 | C → D | P1 293→312; 300→462 |
| Windows legacy, P1 | 13.882/2 → 14.527/2 | D → C | P1 222→299; 222→296 |
| Windows DNS, P1 | 21.182/2 → 16.171/2 | C → D | P1 240→324; 237→317 |
| Windows relay, P1 | 0.605/1 → 23.113/2 | C → C | P1 243→257; 246→341 |
| Windows exit node, P1 | 0.609/1 → 22.465/2 | D → C | P1 236→260; 236→340 |
| FreeBSD restart, initial P1/P2 | 0.604/1, 0.604/1 → 21.232/2, 21.233/2 | P1 C→C; P2 D→D | P1 226→277; 231→326. P2 265→301; 226→303 |
| FreeBSD/Linux HA, original P1/P2 | 0.603/1, 0.605/1 → 0.603/1, 0.604/1 | P1 C→C; P2 D→D | P1 298→334; 339→361. P2 234→279; 213→261 |
| Linux/Linux HA, original P1/P2 | 0.604/1, 0.605/1 → 22.164/2, 22.165/2 | P1 D→C; P2 C→D | P1 252→290; 267→381. P2 223→247; 226→349 |

For each artifact below, archive paths are **`results/<result-id>/nodes/peer-N/client-logs.tar.gz`**, member **`./client.log`**. The four Windows P1 archives instead use **`client-logs.zip`**, member **`client.log`**. All references are one-based native line numbers. Windows timestamps retain `+02:00`; other logs use UTC; legacy versions log whole seconds.

| Focus / exact case | Baseline artifact / result-id | Source42 artifact / result-id |
|---|---|---|
| Linux relay — `client-linux-nat-connect-relay` | [12341850071](https://github.com/netbirdio/proxbird-tests/actions/runs/39588288742/artifacts/12341850071) / `c539cfea627cd94fe7ca9b96db282128` | [12355513657](https://github.com/netbirdio/proxbird-tests/actions/runs/39617144938/artifacts/12355513657) / `78d4d9762191c0a4d76b234f8521223b` |
| Linux allowed ports — `client-linux-nat-allowed-ports` | [12341094768](https://github.com/netbirdio/proxbird-tests/actions/runs/39588288742/artifacts/12341094768) / `e74be20acd9df3dd87ca7f0781288c35` | [12355659252](https://github.com/netbirdio/proxbird-tests/actions/runs/39617144938/artifacts/12355659252) / `64fdd90d8973f15bec267e68024a2bcd` |
| Windows legacy — `client-windows-nat-connect-legacy` | [12342086503](https://github.com/netbirdio/proxbird-tests/actions/runs/39588288742/artifacts/12342086503) / `f3d9286bf5ee910c882ec861ec0e5482` | [12357480493](https://github.com/netbirdio/proxbird-tests/actions/runs/39617144938/artifacts/12357480493) / `9a29698d0f7e8a1399a980474e791e6a` |
| Windows DNS — `client-windows-nat-dns` | [12341942075](https://github.com/netbirdio/proxbird-tests/actions/runs/39588288742/artifacts/12341942075) / `8f1cd61908895d4d1bf2c564624e6905` | [12356059621](https://github.com/netbirdio/proxbird-tests/actions/runs/39617144938/artifacts/12356059621) / `40c606956c9c79f6d51f18c158517529` |
| Windows relay — `client-windows-nat-connect-relay` | [12342531334](https://github.com/netbirdio/proxbird-tests/actions/runs/39588288742/artifacts/12342531334) / `0f3d9894502435b6c5b6716d1b068678` | [12356458569](https://github.com/netbirdio/proxbird-tests/actions/runs/39617144938/artifacts/12356458569) / `564728c6dd06daf410f570368a357cba` |
| Windows exit node — `client-windows-nat-exit-node` | [12341566794](https://github.com/netbirdio/proxbird-tests/actions/runs/39588288742/artifacts/12341566794) / `ab3ac74b7c35458061d9959cf5773f5b` | [12356937109](https://github.com/netbirdio/proxbird-tests/actions/runs/39617144938/artifacts/12356937109) / `43cb1741dfbe961afc8ca724eabdfcb4` |
| FreeBSD restart — `recovery-freebsd-nat-daemon-restart` | [12341379155](https://github.com/netbirdio/proxbird-tests/actions/runs/39588288742/artifacts/12341379155) / `6bbcaaf830d24d2a32171c17d99a633b` | [12357602310](https://github.com/netbirdio/proxbird-tests/actions/runs/39617144938/artifacts/12357602310) / `347f361a177ff32ca7d96bf118693ea6` |
| FreeBSD/Linux HA — `routing-ha-freebsd-linux-nat-router-ha` | [12342674276](https://github.com/netbirdio/proxbird-tests/actions/runs/39588288742/artifacts/12342674276) / `3763cb7c1306ff3dcc5dc2e7bf2a365c` | [12357713215](https://github.com/netbirdio/proxbird-tests/actions/runs/39617144938/artifacts/12357713215) / `99c0df67a87d3b9bdfe00b72c48ecec0` |
| Linux/Linux HA — `routing-ha-linux-linux-nat-router-ha` | [12343965299](https://github.com/netbirdio/proxbird-tests/actions/runs/39588288742/artifacts/12343965299) / `a9fdf7eff9d9438ac1ef83679da3570e` | [12359360411](https://github.com/netbirdio/proxbird-tests/actions/runs/39617144938/artifacts/12359360411) / `3390eadd121c080880eed61f0cba2364` |

#### Concrete source42 findings

- **Linux relay:** both sides connect first attempt. Legacy 0.30.1 P2 rejects early host 86–87, initializes 91, accepts srflx 108, succeeds 112. Modern P1 accepts host/srflx 296/299 and succeeds 307. Thus an early candidate warning alone does not imply failure. Despite its name, this case expects NAT/P2P.
- **Linux allowed ports:** both sides fail attempts 1/2, then connect attempt3. Legacy P2 rejects host 86–87 and srflx 89–90 before initialization 93; second srflx 160–161 precedes initialization 167, while host 175 follows it. Third initialization 202 precedes srflx 209/host 210 and success 224. Modern P1 failures 356–358/432–434 precede success 462; it receives both remote candidates each time. No one-sided Connected/Checking failure is observed. Role differs from baseline.
- **Windows legacy:** both sides fail first, then connect second; the earlier three-attempt pattern does not recur. Windows rejects first srflx 214–215, accepts host 220, fails 270–272; second primary/loopback/srflx 283–285 and remote candidates 286–287 lead to success 296. Legacy 0.28.9 fails 111/114, then accepts second candidates 124/131/133 and becomes Connected 141. Role differs from baseline.
- **Windows DNS:** **first-attempt asymmetry remains**, while both second attempts connect. Windows rejects early host 214–215, accepts srflx 235, then fails 283–285. Legacy 0.30.1 initializes 93, accepts loopback 108/primary 109/srflx 115, succeeds 125/Connected 132, then disconnects 152. Second Windows candidates 303–305/308–309 lead to success 317; legacy second success 188/Connected 195. This first episode differs from the earlier source37 second-attempt episode where both remote candidates were accepted. Role differs from baseline.
- **Windows relay:** both fail first, then connect second; no one-sided Connected/Checking failure. Windows rejects first srflx 215–216, fails 291–293, retries 315–328, succeeds 341; legacy fails 140–143 and succeeds 183/Connected 192. Breakdown: **12.028 s failed dial + 10.481 s gap + 0.604 s success**. Intended controlling role matches baseline; control-plane readiness precedes dial.
- **Windows exit node:** both fail first, then connect second. Windows rejects first srflx 215–216, fails 289–291, accepts second candidates 324–325 and succeeds 340. Legacy fails 140–143, then initializes 162, accepts candidates 174/177–178 and succeeds 185. Breakdown: **12.024 s failed dial + 9.839 s gap + 0.602 s success**. Role differs from baseline.
- **FreeBSD restart:** the delay is **initial negotiation, before the planned restart**. FreeBSD P1 srflx 223/warning 224 occurs after OnNewOffer 222 but before initialization 226; Linux P2 accepts both candidates 246/249 after initialization 213. Both fail/close (P1 282–284; P2 263–265), then succeed on retry (326/303). Baseline accepts both after initialization on both nodes. P1's first success is 15:35:27.380; shutdown 358 occurs 40.430, restart 434 occurs 45.225. Separate post-restart dial intervals are 0.604 s each (P1 592→616; P2 412→432). Harness `checks/2/details` separately reports `recovery_seconds=1.87209384`, with traffic starting 15:35:35.721Z; this is not the initial 21-second metric.
- **FreeBSD/Linux HA:** original directions succeed first attempt; source37's ~21 s episode does not recur. P1 logs early host 320/warning 325, accepts srflx 346, succeeds 361; original P2 initializes 200–201, accepts host 228/srflx 239, succeeds 261. Original P2 native own-key 59 matches P1's first remote key; initial snapshot `checks/0/details/peers/1` maps through interface/AllowedIPs 304. Replacement own-key 1528 follows new epoch 1515 and matches final status; it differs from original 59. Replacement snapshot `checks/7/details/replacement/new_status` has **no publicKey**, so native/final-status proof supplies the association. P1→replacement remains separate at 0.603 s (1393→1418). Local archives span restarts/replacement; this metric does not enumerate every later local-key generation or measure full HA convergence.

- **Linux/Linux HA:** both original peers fail first, then connect second. P1 receives host 243/warning 244 and srflx 247/warning 248 before initialization 251; P2 initializes 203 before host 231/srflx 241. P1 fails/closes 357–359, P2 322–324; after second initialization both accept both candidates and succeed at P1 381/P2 349. Baseline accepts both after initialization without warnings. Intended roles reverse. Original P2 key 61 matches the initial interface mapping (P1 201); later replacement key 1458, following start 1443, differs and matches final status. P1→replacement is separate at 0.603 s (1339→1375). The delayed initial success precedes P2 shutdown 522/restart 579; no one-sided Connected/Checking failure is observed.

Native start/own-key anchors for role verification are P1 **68/84** in the two Linux client cases, **69/88** in the four Windows cases; FreeBSD restart P1 **68/82**, P2 **45/61**; FreeBSD/Linux HA P1 **68/84**, original P2 **45/59**; Linux/Linux HA P1 **68/84**, original P2 **45/61**. Final replacement status is never substituted for an original native key.

#### Earlier source37 is separate evidence

[Run 39597620276](https://github.com/netbirdio/proxbird-tests/actions/runs/39597620276) at [37dab7d](https://github.com/netbirdio/netbird/commit/37dab7d7124ea1de7a7e9bdfa5a3cd445f8413dc) observed Linux relay 29.127 s/3, Windows DNS 29.053 s/3, and original FreeBSD/Linux HA 21.147/21.149 s over two attempts. Those observations and later source37 repeat episodes are not source42 measurements or latest145/248 validation. Source42's different outcomes do not isolate a causal fix; candidate ordering, intended-role differences where shown, unobserved role conflicts, and missing transaction delivery traces limit attribution. Detailed per-case notes and JSON evidence remain alongside this portable digest.

## Final report and remaining acceptance work

The implementation remains entirely in NetBird's mux. Outgoing STUN requests
register their header transaction ID before sending, and known success/error
responses go only to that sending connection. Requests retain the existing
pair-ID preference, then use the USERNAME host connection. Unknown responses
retain the original fallback. The bounded tracker and connection lifecycle
fixes cover expiry, removal, replacement, retransmission errors, concurrent
address registration and shutdown. Production changes are confined to
`client/iface/udpmux`; the two necessary test-only changes are documented above.
There is no dependency, pion fork, wire-format, config, flag or security-control
change.

Real fork agents with NAT connect in the one-, two- and twenty-pair tests,
including both mixed pair-ID roles and the nomination-before-response ordering
case. The newer multi-host and duplicate-response tests additionally verify
exact candidate ownership, including both response copies from an older
broadcaster. Ordinary observed requests handled by the POC have at most one
answer; the legacy duplication fixture deliberately emits two peer answers. These tests do not prove loss-free delivery
of every check in every network. The repeated virtual-NAT comparison adds 96
clean POC ownership samples for each of `532e38be` and the newer `24817004`.
Formatting, both lint targets, the required race suites, source-built netstack
and official-release netstack interoperability pass for the newer implementation
with the explicit comment-only source bridge documented above. Its complete
unit command has 253 passing packages and six baseline-matched failures; the
full command remains red.
Both baseline and intermediate POC VM runs pass all 85 scenarios, and every
initial P2P/relay status matches. Those artifacts cover Linux kernel mode and
Windows/macOS/FreeBSD userspace mode on `37dab7d`, not the later lifecycle fixes.
The lifecycle-source run at `42b087a4` subsequently adds 84 passing scenarios and
one pre-install setup failure in attempt 1, with unchanged observed initial
paths and the timing/candidate differences recorded in its complete table.
Its targeted retry is separate evidence. Neither VM source contains the newer
candidate-queue and recently-answered-owner corrections.

Candidate selection is observably different. In the repeated pair-ID NAT
fixture, the POC's controlling side selects host/srflx while baseline selects
srflx/srflx; the controlled side remains srflx/srflx. The local endpoint displayed
therefore changes. Earlier sources shared candidate read queues; the revised
implementation separates them and tests the physical/loopback case explicitly.
Routing by a mapped address to preserve the old display was tested and rejected because it can
prevent connection when nomination arrives before buffered responses. No such
workaround or pion modification is part of this branch.

The acceptance conditions are not all met:

- Run `39617144938` is testing verified source `42b087a4`, which includes
  the `532e38be` lifecycle fixes. Attempt 1 finished with 84 passing cases and
  one classified setup failure; the targeted retry was accepted after evidence
  preservation and remains separately recorded.
  The newer candidate-queue/recent-owner implementation at `24817004`
  requires its own immutable-source VM run; its local checks are complete.
- One workflow per source and topology cannot prove no worse median time to
  P2P. Repeated local measurements are documented above; the intermediate lab
  traces include slower episodes as well as faster ones. The latest twenty-pair
  pair-ID local median is 0.847 ms higher, as explicitly recorded above. The Windows DNS
  asymmetric retry remains unexplained by the available packet-level evidence.
- Actual current-release interoperability is proven only for official nblink
  v0.81.3 against the POC embedded peer on the local Docker network. The VM lab's
  older references are 0.28.9 and 0.30.1; `reference: current` selects the source
  build, not a release binary. Full OS-client/NAT coverage remains unproven.
- The complete unit command still fails on baseline/environment dependencies,
  with focused local-proxy corrections reported separately. Mobile runtime
  coverage and broader multi-interface/dual-stack candidate ownership remain
  outside the evidence collected here.

The configured shell network policy rejects `api.github.com`. The supported
GitHub interface can collect runs and artifacts but has no workflow-dispatch
write. No workflow trigger, repository configuration, network policy or
credential was changed to create another dispatch route. The user subsequently
launched lifecycle-source run `39617144938` through the existing workflow.
The next command pins the newer validated source instead of resolving a moving
branch. It queues the full 85 cases and two client-suite repetitions for the
three-sample comparison. Check for an existing dispatch of this literal source
before running it; these are new-source validations, not retries of source42:

```sh
for scenario in \
  peer-pairs,client-tests,recovery,connectivity-repair,connectivity-underlay,routing-ha,routing-overlap \
  client-tests \
  client-tests
do
  gh workflow run e2e.yml --repo netbirdio/proxbird-tests --ref main \
    -f client_source=netbird-main \
    -f lab_source=source-build \
    -f netbird_sha=145a4ab86c27b8658c18308b33aa4c41109a52a5 \
    -f scenario="$scenario" || break
done
```

Reuse baseline run 39588288742. Audit the final-source reports and native bundles,
then compare repeated native timing for the newer source with the three existing
baseline client-case samples rather than averaging unrelated topologies.
Investigate any reproduced slowdown before declaring equivalence. The actual
current-release netstack binary is covered, but full OS-client release coverage
is still absent. No PR or ticket has been created.

Step 2 is separate work: adapt the mux integration to upstream pion/ice v5,
preserve the per-candidate queue ownership now established in this mux, and
prove requests no longer need the pair-ID preference before
removing `candidateConnMap`, `0x8100` handling and the `cid` extension. The current
tests should remain ownership regressions during that migration, augmented by
multi-interface/dual-stack and mixed-release coverage. Dependency and wire
changes belong to that later task, after the unresolved acceptance evidence
above is addressed; this POC does not authorize or implement them. Neither mux
redirection nor an upstream upgrade alone has been shown to preserve baseline
candidate types and nomination behavior.
