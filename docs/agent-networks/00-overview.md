# Agent Networks — overview

Single-entry point. Feature scope, the module map, and the cross-cutting
topics worth keeping in mind, with links into every per-module guide.

## TL;DR

Agent Networks introduces an **LLM-aware reverse-proxy middleware system**
plus **account-level controls** (budget rules, log collection toggles,
PII redaction). The management server synthesises a per-peer middleware
chain that the proxy executes on every LLM request; the chain enforces
quotas, injects identity, redacts PII, parses tokens/cost, and emits
access-log entries. The dashboard exposes the surface as a single **AI
Observability** page with four tabs.

- **Backend** lives in this repo, primarily under
  `management/server/agentnetwork`, `proxy/internal/middleware`, and
  `proxy/internal/llm`, with wire contracts in `shared/management`.
- **Dashboard** lives in the dashboard repo under
  `src/modules/agent-network/` and `src/app/(dashboard)/agent-network/`.

## Reading order

| # | Doc | Why |
|---|-----|-----|
| 1 | [01-end-to-end-flows.md](01-end-to-end-flows.md) | Get the three big diagrams in your head first. |
| 2 | [modules/10-shared-api.md](modules/10-shared-api.md) | Wire contracts — every other module either produces or consumes these. |
| 3 | [modules/21-management-agentnetwork.md](modules/21-management-agentnetwork.md) | The largest module; everything the proxy executes originates here. |
| 4 | [modules/30-proxy-middleware-framework.md](modules/30-proxy-middleware-framework.md) | The generic plugin system on the proxy side. |
| 5 | [modules/31-proxy-middleware-builtin.md](modules/31-proxy-middleware-builtin.md) | The 8 LLM middlewares that ride on the framework. |
| 6 | Everything else in any order. | |

## Module map

11 modules. Each is described in detail in its own file under
[`modules/`](modules/).

| # | Module | Risk | BC impact |
|---|--------|------|-----------|
| 10 | [shared/api](modules/10-shared-api.md) — proto + OpenAPI | Low | Additive only |
| 20 | [management/store](modules/20-management-store.md) — SQL persistence | Medium | Auto-migrate (additive) |
| 21 | [management/agentnetwork](modules/21-management-agentnetwork.md) — domain layer + synthesizer | **High** | Additive |
| 22 | [management/handlers + wiring](modules/22-management-handlers-wiring.md) — HTTP API + gRPC delivery | Medium | Additive |
| 30 | [proxy/middleware-framework](modules/30-proxy-middleware-framework.md) — generic plugin system | High | Additive |
| 31 | [proxy/middleware-builtin](modules/31-proxy-middleware-builtin.md) — 8 LLM middlewares | High | Additive |
| 32 | [proxy/llm-parsers](modules/32-proxy-llm-parsers.md) — SDK adapters + pricing | Medium | Additive |
| 33 | [proxy/runtime](modules/33-proxy-runtime.md) — translate + serve + access-log | High | Additive (touches hot path) |
| 40 | [dashboard](modules/40-dashboard.md) — UI for everything above | Medium | Sidebar reshape |
| 50 | [path-routed-providers](modules/50-path-routed-providers.md) — Vertex AI + Bedrock | Medium | Additive (new catalog entries) |

The largest and highest-risk module is `management/agentnetwork`: it is
the single writer of the middleware chain the proxy executes.

## Cross-cutting topics

These are the items most likely to bite production. Each is fully
documented in the linked module guide.

1. **Capture-pointer semantics** (`*bool` for `capture_prompt` and
   `capture_completion`): nil = legacy emit, false = suppress, true =
   emit. nil-vs-false must be handled at every JSON hop. See
   [21-management-agentnetwork.md](modules/21-management-agentnetwork.md)
   and [31-proxy-middleware-builtin.md](modules/31-proxy-middleware-builtin.md).
2. **`ProxyMapping.Private` preservation** on per-proxy live updates.
   Failure mode: `auth` skips `ValidateTunnelPeer` →
   `CapturedData.UserGroups` empty → `llm_router` denies. See
   [33-proxy-runtime.md](modules/33-proxy-runtime.md).
3. **respInput carrying `UserEmail`/`UserGroups`/`UserGroupNames` onto
   the response leg** in `reverseproxy.go`. Load-bearing wire that lets
   `llm_limit_record` ship non-empty `group_ids` on `RecordLLMUsage`. See
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
   perf hot-spot. See
   [30-proxy-middleware-framework.md](modules/30-proxy-middleware-framework.md).
6. **UpstreamRewrite.AuthHeader bypasses the header denylist**
   deliberately. The runtime consumer only unpacks it via the
   trusted upstream-build path. See
   [30-proxy-middleware-framework.md](modules/30-proxy-middleware-framework.md).
7. **`disable_access_log` default-false semantics**: the synth target
   sets it true, all other targets leave it false. See
   [10-shared-api.md](modules/10-shared-api.md).
8. **String-typed `decision` / `deny_code`** on
   `CheckLLMPolicyLimitsResponse` — would benefit from enum pinning
   before external consumers integrate. See
   [10-shared-api.md](modules/10-shared-api.md).

## Explicit non-goals

- **Reaper / GC pass over stale synth services** — designed but cut from
  scope.
- **URL-sync for tab state on AI Observability** — read path is wired
  (`?tab=`) but write path isn't. Future work.
- **CI golden-file regen-and-diff for `types.gen.go` /
  `proxy_service.pb.go`** — would catch codegen drift; not yet in place.

## Where to read the code

Per-module file scopes are listed in each module guide. Behaviour is
covered by Go tests co-located with each package (and an end-to-end
chain integration test under `proxy/internal/proxy`).
