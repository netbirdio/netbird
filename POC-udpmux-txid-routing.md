# UDP mux transaction routing POC

## Baseline and scope

- Baseline: `1e63b68c4dc243a32fef823df1bc024c997a9c60`, fetched from
  `netbirdio/netbird` `origin/main` on 2026-10-21.
- Branch: `poc/udpmux-txid-routing`, created with `--no-track`.
- No pull request or ticket. Implementation is confined to
  `client/iface/udpmux`; this requested progress log is the documentation exception.
- Keep dependencies, fork, candidate extension, wire format, and overlay STUN
  filtering unchanged. The supplied design authorizes this connectivity POC.

## Decisions and milestones

### Preparation

- Read the repository guidance and the Proxbird README, AGENTS, getting-started,
  and GitHub Actions documentation. The requested scenario selection validates
  unchanged and selects 85 cases with a lab parallelism limit of 11.
- Use the installed Go 1.26.7 toolchain at
  `/workspace/.tools/go1.26.7/bin`, with writable module/build caches under
  `/workspace/.cache`. `/usr/bin/go` is a different program.
- Header parsing follows RFC 8489 section 5: 20-byte header, class bits 8/4,
  magic cookie, aligned message length, and transaction ID bytes 8 through 19.
  The write path will not decode STUN attributes.
- Preserve the existing address and username fallback when a transaction is
  unknown. Begin by testing host-only request routing; retain pair-ID routing for
  requests if candidate selection differs, as permitted by the task.
- Baseline inspection identifies a possible selected-candidate change: the fork
  passes the receiving candidate into request handling and nomination. A request
  formerly routed to srflx can nominate host after username-only routing.
- Baseline `go fmt ./...` succeeds but formats 25 unrelated baseline files.
  Restore those formatting-only changes so this POC stays within scope.

### External validation access

- Git fetch works with the executor's network permission. The connected GitHub
  app can read the repositories. The shell cannot reach `api.github.com`:
  workflow listing and the baseline dispatch return `Forbidden` under the
  environment network policy. The connected app has no workflow dispatch tool.
- No Proxbird workflow has been created; no run IDs or measurements exist yet.
  Do not treat missing evidence as equivalence or as a passing check.
- The selection's legacy cases use 0.28.9/0.30.1. Additional coverage is needed
  for a separately pinned current release, netstack/embed, and repeated-run
  medians. Its `current` peers use the selected source SHA.

### Implementation experiment and stopping decision

- Added a transaction-ID cache for outgoing STUN requests. Header-only parsing
  checks the cookie, class bits, top bits, and aligned declared length. Requests
  are registered before the socket write; send-error cleanup removes only the
  matching registration. Success and error responses consume the entry and go
  only to its sending connection.
- Cache TTL is one minute, capacity is 4,096, and retransmission refreshes the
  entry. The oldest outstanding transaction is evicted at capacity. Expiration
  is checked on registration and lookup; an idle sweeper physically releases
  expired entries within two minutes. Removal and close synchronously purge
  transactions. Unknown, consumed, expired, or evicted IDs retain address-map
  and username fallback, which can fan out; exclusivity is not claimed for
  arbitrary duplicate network responses after the entry is consumed.
- Initially tested username-only requests/indications. Real-agent NAT tests
  passed delivery assertions, but selected local candidates changed to host on
  both sides. Retained `candidateConnMap` and pair-ID routing first for
  requests/indications, followed by username-to-host, then existing fallback.
  This hybrid still changes the controlling peer's selected candidate.
- **Hard stop: selected-candidate behavior differs from baseline and cannot be
  preserved by the specified routing change within scope.** No dependency,
  wire-format, fork, priority, or reporting workaround was introduced.

The cause is visible in the pinned fork. A host check crossing NAT arrives from
the public endpoint advertised by the sender's srflx candidate. The receiver
resolves that endpoint by address, so its response's pair-ID targets srflx.
Baseline routes the response there, although host sent the request. Transaction
routing delivers it to host, and ICE makes that higher-priority host pair valid.
Retaining pair-ID routing for incoming requests cannot change this response path.
Restoring the baseline would require misrouting responses again or changing
candidate selection beyond this design.

Source evidence in the existing module cache's `github.com/netbirdio/ice/v4`
replacement: `agent.go:961-976` (remote lookup), `agent.go:998-1023` (response),
`candidatepair.go:127-131` (pair-ID target), `agent.go:1110-1125` (inbound local
candidate), and `selection.go:155-167` (successful/selected pair).

The task explicitly anticipated reporting candidate-type changes, but also
requires stopping on a behavior difference that cannot be eliminated within
scope. Following its conservative ambiguity rule, treat this change as that
hard stop rather than claiming equivalence or silently changing acceptance.

## Validation results

### Real-agent regression tests

`agent_routing_test.go` uses real pinned fork agents, two independent vnet NATs,
a real virtual STUN server, and the production mux. Each agent gathers both host
and actual STUN-derived srflx candidates. Observation wrappers record the writer
and reader of each transaction and count requests and responses.

| Case | Baseline with new tests | Host-only experiment | Retained pair-ID requests |
| --- | --- | --- | --- |
| One host + srflx agent per shared mux | Fails response ownership / duplicate assertions | Pass | Pass |
| Two overlapping agents per shared mux, same remote endpoint | Fails response ownership / duplicate assertions | Pass | Pass |
| Twenty agents per shared mux on each side | Fails response ownership / duplicate assertions | Pass | Pass |
| Both peers carry pair IDs | Fails response ownership assertions | Pass | Pass |
| One peer omits pair IDs | Fails response ownership / duplicate assertions | Pass | Pass |

The hybrid agent tests also pass under `go test -race`; no race is reported.
These test concurrent overlapping agents, not a full daemon reconnect/re-gather
sequence. Test wrappers strip the trailing optional pair-ID attribute from one
peer; they do not replace running an actual old release binary.

### Candidate and timing evidence

Ten repetitions per peer variant, identical virtual NAT topology and 20 ms ICE
check interval. These are local microbenchmarks, not Proxbird medians and not
evidence of no timing regression across platforms or topologies.

| Peer variant | Baseline connect median | Hybrid connect median | Baseline selected local/remote | Hybrid selected local/remote |
| --- | ---: | ---: | --- | --- |
| Both carry pair IDs | 21.013118 ms | 21.0694805 ms | Both sides srflx/srflx, 10/10 | Controlling host/srflx and controlled srflx/srflx, 10/10 |
| One omits pair IDs | 21.0598955 ms | 20.8853465 ms | Controlling host/srflx 7/10 and srflx/srflx 3/10; controlled srflx/srflx 10/10 | Controlling host/srflx and controlled srflx/srflx, 10/10 |

Both variants connect directly through the test NATs. The both-ID median is
0.0563625 ms higher in this sample; this is not a supported claim of either
equivalent or regressed real-world latency. The both-ID candidate change is
repeatable, whereas baseline missing-ID selection already varies with broadcast
delivery order. These values come from `GetSelectedCandidatePair`, the same pair
used by `worker_ice.go` for candidate reporting; no daemon `netbird status -d`
debug bundles have been collected.

### Cache and fallback tests

`transaction_test.go` uses real muxes and sockets. Success/error routing,
same-ID retransmission, request/indication routing, header-only parsing, write
error cleanup, bounded capacity, idle TTL cleanup, removal/close cleanup, and
concurrent writers/removal pass in the focused run.

`TestSTUNRemovedConnectionPreservesAddressFallback` fails on both baseline and
the experiment: removing one connection deletes the entire address entry, so
another registered connection gets zero fallback packets instead of one. This
pre-existing issue remains visible in the stopped branch; it was not fixed after
the hard stop. The replacement-close test passes but does not prove replacement
registration survives: address fallback can mask that existing lifecycle issue.

### Two-pass concurrency analysis

1. Identified pre-send registration, stale send-error cleanup, removal versus
   in-flight registration, and mux/conn close lock ordering before implementation.
2. Reviewed final map/list access under `m.mu`, registered-pointer checks,
   response consumption, expiration ordering, and close. No new cache race or
   lock inversion found. Mux close releases the mutex before closing each conn;
   expiry stops through `closedChan`. The actual agent race run passes.

Existing address registration/removal and stale close-watcher logical races
remain separate limits; no assertion of complete lifecycle correctness is made.

### Command evidence

Final broad-check outcomes are recorded below when their bounded attempts finish.
Local logs are retained in `/workspace/scratch/validation`,
`/workspace/scratch/proxbird`, and `/workspace/scratch/agent-routing-*.log`.
Focused socket results are in `/workspace/scratch/transaction-before.log` and
`/workspace/scratch/transaction-after-verbose.log`. These paths are workspace
artifacts, not files committed to the repository.

## Baseline / POC comparison

| Cases | Baseline result | POC result | P2P / relay | Connect time | Local / remote candidates |
| --- | --- | --- | --- | --- | --- |
| 85 selected Proxbird cases | Not dispatched: API access denied | Not dispatched | Not measured | Not measured | Not measured |

## Final report

The POC is stopped at the requested behavior-difference hard stop. Transaction
routing corrects response ownership and removes duplicate responses in the
tested virtual NAT scenarios, but it also changes candidate selection. The
fallback request pair-ID path is retained; this branch has not removed the
fork dependency and is not ready for integration.

Proven locally: real-agent connectivity for 1/2/20 pairs, exclusive delivery for
tracked transactions, one response per received request in those scenarios,
mixed optional-attribute handling, and bounded transaction lifecycle behavior.
Not proven: cross-platform kernel/userspace/netstack operation, actual current
and legacy release interoperability, recovery scenarios, all topology P2P/relay
equivalence, no latency regression, or daemon status details. Full green unit,
race, lint, and e2e acceptance is not claimed.

Step 2 requires an explicit decision about the selected-candidate semantics
before moving to upstream pion/ice v5. Repeat this harness with upstream ICE and
resolve how candidate types and selected endpoints should be represented. Only
after that design and Proxbird comparisons should the pair-ID request path,
candidate-ID API extensions, custom attribute, and fork be removed in a separate
change. No such dependency or wire-format change belongs in this stopped POC.
