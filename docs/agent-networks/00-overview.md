# agent-networks PR — overview

Single-entry point for reviewers. Scope, commit roll-up, ownership
matrix, cross-cutting risk hot-list, and links into every per-module
guide.

## TL;DR

This PR pair introduces an **LLM-aware reverse-proxy middleware system**
plus **account-level controls** (budget rules, log collection toggles,
PII redaction) for NetBird agent-networks. The management server
synthesises a per-peer middleware chain that the proxy executes on
every LLM request; the chain enforces quotas, injects identity, redacts
PII, parses tokens/cost, and emits access-log entries. The dashboard
exposes the surface as a single **AI Observability** page with four
tabs.

- **Backend branch:** `feature/agent-networks-backend` on
  `/Users/maycon/projects/netbird` — 28 commits vs merge-base
  `14af17955`, **~28,000 net LOC added** across 150 files.
- **Dashboard branch:** `feature/agent-networks` on
  `/Users/maycon/projects/dashboard` — ~70 commits vs `main`,
  **~10,000 net LOC added** across 82 files.

## Reading order

| # | Doc | Why |
|---|-----|-----|
| 1 | [01-end-to-end-flows.md](01-end-to-end-flows.md) | Get the three big diagrams in your head first. |
| 2 | [modules/10-shared-api.md](modules/10-shared-api.md) | Wire contracts — every other module either produces or consumes these. |
| 3 | [modules/21-management-agentnetwork.md](modules/21-management-agentnetwork.md) | The largest module; everything the proxy executes originates here. |
| 4 | [modules/30-proxy-middleware-framework.md](modules/30-proxy-middleware-framework.md) | The generic plugin system on the proxy side. |
| 5 | [modules/31-proxy-middleware-builtin.md](modules/31-proxy-middleware-builtin.md) | The 8 LLM middlewares that ride on the framework. |
| 6 | Everything else in any order. | |

## Ownership matrix

11 review-able modules. Each is described in detail in its own file
under [`modules/`](modules/).

| # | Module | Suggested reviewer | Expertise required | Est. time | Risk | BC impact |
|---|--------|--------------------|--------------------|-----------|------|-----------|
| 10 | [shared/api](modules/10-shared-api.md) — proto + OpenAPI | API/contracts maintainer | protobuf + oapi-codegen + wire-format reasoning | 30 min | Low | Additive only |
| 20 | [management/store](modules/20-management-store.md) — SQL persistence | Storage maintainer | gorm + sqlite/postgres + migrations | 45 min | Medium | Auto-migrate (additive) |
| 21 | [management/agentnetwork](modules/21-management-agentnetwork.md) — domain layer + synthesizer | Management server maintainer | network-map controller + policy engine + Go concurrency | **2–3 h** | **High** | Additive |
| 22 | [management/handlers + wiring](modules/22-management-handlers-wiring.md) — HTTP API + gRPC delivery | Management infra maintainer | REST handlers + RBAC + gRPC streaming + controller wiring | 90 min | Medium | Additive |
| 30 | [proxy/middleware-framework](modules/30-proxy-middleware-framework.md) — generic plugin system | Proxy maintainer | net/http composition + request lifecycle + Go context | 60 min | High | Additive |
| 31 | [proxy/middleware-builtin](modules/31-proxy-middleware-builtin.md) — 8 LLM middlewares | Proxy + LLM owner | OpenAI/Anthropic semantics + the framework above | **2 h** | High | Additive |
| 32 | [proxy/llm-parsers](modules/32-proxy-llm-parsers.md) — SDK adapters + pricing | LLM/proxy owner | OpenAI Responses API + Anthropic Messages API + SSE framing | 75 min | Medium | Additive |
| 33 | [proxy/runtime](modules/33-proxy-runtime.md) — translate + serve + access-log | Proxy maintainer | existing reverseproxy.go lifecycle + access-log emission + synth ingestion | 90 min | High | Additive (touches hot path) |
| 40 | [dashboard](modules/40-dashboard.md) — UI for everything above | Dashboard maintainer | Next.js app router + existing Tabs/Modal/Table patterns + Providers/Permissions/Groups context | **2 h** | Medium | Sidebar reshape |
| 50 | [path-routed-providers](modules/50-path-routed-providers.md) — Vertex AI + Bedrock | Proxy + LLM owner | URL-path routing + GCP OAuth + AWS Bedrock runtime + catalog↔pricing | 45 min | Medium | Additive (new catalog entries) |
| — | E2E scripts under `scripts/e2e/agent-network-policy/` | Whoever runs the e2e suite | bash + tilt | 30 min | Low | New only |

**Total wall-clock review estimate:** ~13–15 hours if reviewers
serialize. With per-module fan-out (one reviewer per row) the critical
path is ~3 hours (the management/agentnetwork module).

## Commit roll-up

### Backend (28 commits, oldest → newest)

| SHA | Module(s) | Subject |
|-----|-----------|---------|
| `06ff17b38` | shared/api, agentnetwork/types, proxy/llm | AN-0: additive proto + OpenAPI schemas + base types |
| `f810a4e35` | management/store | AN-1: store layer for providers/policies/guardrails/settings |
| `77b407632` | management/agentnetwork | AN-2: agentnetwork module (manager, synthesizer, catalog, policyselect) |
| `09e8059b6` | management/handlers+wiring | AN-2b: wire synth services into the network map |
| `9ecb6449d` | management/handlers+wiring | AN-3: HTTP API handlers + route registration |
| `00bf0d328` | proxy/middleware-framework | AN-4: proxy middleware framework |
| `3ed29d855` | proxy/runtime | AN-4b: middleware plumbing in the proxy request path |
| `e64ea4b02` | proxy/middleware-builtin | AN-5: built-in middlewares + registry registration |
| `0f9f56a58` | proxy/runtime | AN-5b: activate the middleware system in the proxy server |
| `9a1547143` | shared/api, proxy/runtime, accesslog | AN-6: access-log agent_network flag end-to-end |
| `8cb9c187d` | shared/api, agentnetwork, runtime | AN-7: enforcement + synth-service delivery to the proxy |
| `9ebe219fd` | proxy/runtime | test: lock the auth→middleware group-propagation wiring |
| `665575932` | agentnetwork tests | test: real-store integration coverage (no MockStore) |
| `263dabd73` | proxy/runtime | fix: preserve ProxyMapping.Private on per-proxy live updates |
| `5adee2cb4` | agentnetwork tests | Add no-mock agent-network provider-CRUD fan-out test |
| `9ae476ea7` | agentnetwork tests | Add no-mock baseline guards for enforcement and guardrail synthesis |
| `a436b5fb3` | agentnetwork, store, shared/api | GC-0: account budget rule type + collection toggles + store CRUD |
| `5b408b0ef` | agentnetwork | GC-1: budget-rule manager CRUD + settings update |
| `b22d5a181` | agentnetwork, builtin | GC-2: enforce account budget rules as a min-wins ceiling |
| `945f17f1a` | agentnetwork, store, builtin | GC-3: account-level prompt-collection master switch |
| `23bdf6871` | handlers, agentnetwork, shared/api | GC-4: HTTP API for budget rules + settings update |
| `468875cb4` | management+proxy | Wire EnableLogCollection to suppress access-log for opted-out requests |
| `7072f8125` | agentnetwork, builtin | Account toggle is sole control for prompt capture + broader PII redaction |
| `b1e66bca2` | builtin, agentnetwork | Broaden phone redactor + fixture-driven Go test + smoke --groups |
| `b438a7194` | agentnetwork, proxy/runtime | Fix budget enforcement + extend PII redaction to all metadata channels |
| `19e03d688` | agentnetwork tests | Self-contained Go tests for the redact-pii wiring across parsers |
| `2a0d4991b` | proxy/runtime | Self-contained full-chain integration test for agent-network requests |
| `4836d5a19` | agentnetwork, builtin | Gate prompt + completion capture on EnablePromptCollection |

### Dashboard (recent → oldest, abbreviated)

- `3fbe44e` Merge Global Controls + Access Log into AI Observability (today)
- `1988e92` agent-network: Global Controls page with account toggles + budget rules
- `2157fec` Consumption page: charts + filters + access-log style
- `62a85b5` add policy Limits tab; slim Guardrails to allowlist + capture
- `2b7f746` Wire Agent Network guardrails to backend
- `5e10a2b` Wire Agent Network policies to backend
- `4d3ac8d` Wire Agent Network providers to backend API
- …plus ~50 other UI iterations
- Full list: `git -C /Users/maycon/projects/dashboard log --oneline main..HEAD`

## Risk hot-list (cross-cutting)

Pulled from the per-module guides; these are the items most likely to
bite production. Each is fully documented in the linked module guide.

1. **Capture-pointer semantics** (`*bool` for `capture_prompt` and
   `capture_completion`): nil = legacy emit, false = suppress, true =
   emit. Fixed at `4836d5a19`. Reviewers should verify nil-vs-false is
   handled at every json hop. See
   [21-management-agentnetwork.md](modules/21-management-agentnetwork.md)
   and [31-proxy-middleware-builtin.md](modules/31-proxy-middleware-builtin.md).
2. **ProxyMapping.Private preservation** on per-proxy live updates.
   Fix at `263dabd73`. Failure mode: `auth` skips
   `ValidateTunnelPeer` → `CapturedData.UserGroups` empty → `llm_router`
   denies. See [33-proxy-runtime.md](modules/33-proxy-runtime.md).
3. **respInput carrying `UserEmail`/`UserGroups`/`UserGroupNames` onto
   the response leg** at `reverseproxy.go:196-223` (fix at `b438a7194`).
   Load-bearing wire that lets `llm_limit_record` ship non-empty
   `group_ids` on `RecordLLMUsage`. See
   [33-proxy-runtime.md](modules/33-proxy-runtime.md).
4. **Min-wins all-must-pass budget rule semantics**. Every matching
   rule's remaining quota must be > 0 for the request to proceed; one
   exhausted rule blocks the whole call. Documented in
   [21-management-agentnetwork.md](modules/21-management-agentnetwork.md)
   and the `llm_limit_check` middleware in
   [31-proxy-middleware-builtin.md](modules/31-proxy-middleware-builtin.md).
5. **body-tap memory bounds**: per-direction 1 MiB cap, shared 256 MiB
   budget, `LimitReader(r.Body, limit+1)` for truncation detection with
   `replayReadCloser` fallback so upstream still sees the full body.
   `cloneInputFor` deep-copies the body up to 16 times per chain — a
   perf hot-spot worth confirming benchmarks for. See
   [30-proxy-middleware-framework.md](modules/30-proxy-middleware-framework.md).
6. **UpstreamRewrite.AuthHeader bypasses the header denylist**
   deliberately. Confirm the runtime consumer only unpacks it via the
   trusted upstream-build path. See
   [30-proxy-middleware-framework.md](modules/30-proxy-middleware-framework.md).
7. **Codegen reproducibility gap**:
   `shared/management/http/api/generate.sh:14` pulls
   `oapi-codegen@latest` while the AN-0 commit message claims v2.7.0 is
   pinned. A future regen could produce a different `types.gen.go`. See
   [10-shared-api.md](modules/10-shared-api.md).
8. **`disable_access_log` default-false semantics**: synth target sets
   it true, all other targets must leave it false. Worth a
   synthesizer-side audit. See
   [10-shared-api.md](modules/10-shared-api.md).
9. **String-typed `decision` / `deny_code`** on
   `CheckLLMPolicyLimitsResponse` — would benefit from enum pinning
   before external consumers integrate. See
   [10-shared-api.md](modules/10-shared-api.md).
10. **agent_network_chain_realstack_test drift risk**: it inlines the
    proto→Spec mapping instead of calling
    `proxy/middleware_translate.go`. Test will pass even if translate
    regresses. See [33-proxy-runtime.md](modules/33-proxy-runtime.md).
11. **MOCK_GROUPS still in production paths** via
    `AgentPoliciesTable.tsx:45,76` as a name-lookup fallback. Other
    `MOCK_*` constants are unreferenced. See
    [40-dashboard.md](modules/40-dashboard.md).
12. **`updateProvider` / `updatePolicy` / `updateBudgetRule` use `??`
    on `enabled`** — toggle paths are safe but an explicit
    `enabled:false` from a form would be silently dropped. See
    [40-dashboard.md](modules/40-dashboard.md).
13. **Dashboard lint gate is broken** (`next lint` was removed in Next
    16). Pre-existing, but this branch effectively ships without a
    lint check. See [40-dashboard.md](modules/40-dashboard.md).
14. **Zero Cypress / component test coverage for new agent-network
    UI.** See [40-dashboard.md](modules/40-dashboard.md).
15. **Bodytap truncation-replay test missing**; **Dispatcher
    timeout/panic tests missing**; **concurrent Budget exhaustion
    test missing**; **InvalidateMiddleware + LiveServiceCheck race
    test missing**. See
    [30-proxy-middleware-framework.md](modules/30-proxy-middleware-framework.md).

## Explicit non-goals

- **Reaper / GC pass over stale synth services** — designed but scope-cut
  per AN-0 commit message; not migrated.
- **URL-sync for tab state on AI Observability** — read path is wired
  (`?tab=`) but write path isn't. Future work.
- **Lint-gate restoration on the dashboard** — pre-existing,
  out-of-scope.
- **CI golden-file regen-and-diff for `types.gen.go` /
  `proxy_service.pb.go`** — would catch codegen drift; not in this PR.

## Where to read the code

- Backend: `git -C /Users/maycon/projects/netbird diff 14af17955..HEAD`
- Dashboard: `git -C /Users/maycon/projects/dashboard diff main..HEAD`
- Per-module file scopes are listed in each module guide.

## Where this doc lives

`~/projects/claude-contexts/netbird/agent-networks-pr/`. Not committed
to either repo. Move pieces into `docs/` if/when ready.
