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

## Validation results

Pending implementation and test runs. Local command evidence is retained in
`/workspace/scratch/validation` and `/workspace/scratch/proxbird` for resumption.

## Baseline / POC comparison

| Cases | Baseline result | POC result | P2P / relay | Connect time | Local / remote candidates |
| --- | --- | --- | --- | --- | --- |
| 85 selected Proxbird cases | Not dispatched: API access denied | Not dispatched | Not measured | Not measured | Not measured |

## Final report

Work is in progress. No claim of completion or behavioral equivalence is made.
