# proxy/middleware-builtin — the LLM chain

The registry-mounted middleware set the proxy executes on every agent-network
LLM request. The two highest-blast-radius areas are the **capture-pointer
semantics** and the **limit_check ⇒ limit_record** record-once invariant.

Sibling module: [32-proxy-llm-parsers.md](./32-proxy-llm-parsers.md) — the SDK
adapters + pricing catalog this chain delegates to.

---

## Module boundary

This module is the registry-mounted middleware set the proxy executes on
every agent-network LLM request. Each sub-package registers itself via
`init()`
([builtin.go:32–34](../../../proxy/internal/middleware/builtin/builtin.go));
the proxy server anonymous-imports the set
([all_test.go:11–19](../../../proxy/internal/middleware/builtin/all_test.go))
so the registry is populated at boot. The chain is wired by the management
synthesiser and executed by the framework
(`proxy/internal/middleware/{chain,dispatcher,accumulator}.go` — both out
of scope). Everything here reads from / writes to one envelope: the
`middleware.KV` metadata bag plus `middleware.Mutations` for header/body
rewrites.

## The 8 middlewares

| Name | Slot | Inputs (metadata read) | Outputs (metadata written) | Side effects |
|---|---|---|---|---|
| `llm_request_parser` | OnRequest | `Input.{URL,Body,BodyTruncated}` | `llm.{provider,model,stream,request_prompt_raw,capture_truncated}` | none |
| `llm_router` | OnRequest | `llm.model`, `Input.{URL,UserGroups}` | `llm.{resolved_provider_id,authorising_groups}`, `llm_policy.{decision,reason}` | upstream rewrite + auth strip/inject |
| `llm_limit_check` | OnRequest | `llm.{resolved_provider_id,model}`, `Input.{AccountID,UserID,UserGroups}` | `llm.{selected_policy_id,attribution_group_id,attribution_window_seconds}`, `llm_policy.{decision,reason}` | gRPC `CheckLLMPolicyLimits` |
| `llm_identity_inject` | OnRequest | `llm.{resolved_provider_id,authorising_groups}`, `Input.{UserEmail,UserID,UserGroups,UserGroupNames}` | none | header strip/inject + optional body rewrite |
| `llm_guardrail` | OnRequest | `llm.{model,request_prompt_raw}` | `llm_policy.{decision,reason}`, `llm.request_prompt` | none (model allowlist deny) |
| `llm_response_parser` | OnResponse | `llm.provider`, `Input.{RespHeaders,RespBody,Status}` | `llm.{input,output,total,cached_input,cache_creation}_tokens`, `llm.response_completion` | none |
| `cost_meter` | OnResponse | `llm.{provider,model}`, token buckets | `cost.usd_total` or `cost.skipped` | pricing lookup |
| `llm_limit_record` | OnResponse | `llm.{attribution_group_id,attribution_window_seconds,input_tokens,output_tokens}`, `cost.usd_total` | none | gRPC `RecordLLMUsage` |

[all_test.go:26–40](../../../proxy/internal/middleware/builtin/all_test.go)
locks the ID set; adding or removing one is a conscious extension.

## Files

| File | LOC | Notes |
|---|---:|---|
| `builtin.go` | 86 | Registry + `FactoryContext` (ctx, data dir, meter, logger, mgmt client) |
| `all_test.go` | 41 | Locks the 8-ID registry surface |
| `agentnetwork_chain_integration_test.go` | 319 | Live sqlite + real gRPC bufconn; gate→recorder wire path |
| `llm_request_parser/*` | 162 / 66 / 356 | Provider detection, body parse, prompt extraction with capture-pointer gating |
| `llm_router/*` | 385 / 84 / 586 | Three-pass route selection (model → groups → path-prefix) |
| `llm_limit_check/*` | 196 / 38 / 182 | Pre-flight `CheckLLMPolicyLimits` (2s, fail-open) |
| `llm_identity_inject/*` | 440 / 108 / 666 | HeaderPair (LiteLLM) + JSONMetadata (Portkey) + ExtraHeaders |
| `llm_guardrail/*` | 176 / 82 / 75 / 219 / 217 | Model allowlist + optional prompt capture with PII redaction |
| `llm_response_parser/*` | 258 / 222 / 43 / 433 / 169 / 111 | Buffered + SSE accumulation; AWS event-stream accumulator (`streaming_bedrock.go`) for Bedrock; capture-pointer gates completion emit |
| `cost_meter/*` | 181 / 84 / 439 | Token → USD via `proxy/internal/llm/pricing` |
| `llm_limit_record/*` | 144 / 35 / 191 | Post-flight `RecordLLMUsage` (5s, debug-on-error) |

## Per-middleware

### llm_request_parser

Detects the LLM provider via `llm.DetectParser` (URL sniff) or by name via
`llm.ParserByName` when synthesiser stamps `provider_id`
([middleware.go:96–99](../../../proxy/internal/middleware/builtin/llm_request_parser/middleware.go)).
**Path-routed providers short-circuit first:** `parseVertexPath` and
`parseBedrockPath` ([middleware.go:85–94](../../../proxy/internal/middleware/builtin/llm_request_parser/middleware.go))
pull the model + vendor out of the URL before parser selection runs — Vertex
from `/v1/projects/.../publishers/{pub}/models/{model}:{action}` (publisher →
vendor via `vertexPublisherVendor`), Bedrock from `/model/{id}/{action}` with
`normalizeBedrockModel` stripping the region prefix + version suffix. See
[50-path-routed-providers.md](./50-path-routed-providers.md) for the full path
grammar. For body-routed providers it decodes the body into `RequestFacts`
(model + stream) and extracts the prompt. On
`capture_prompt=true` (or absent — see capture-pointer semantics below) the
prompt is run through `llm_guardrail.RedactPII` when `redact_pii=true` and
truncated rune-safely to 3500 bytes
([middleware.go:109–122](../../../proxy/internal/middleware/builtin/llm_request_parser/middleware.go)).
**Key invariant:** redaction is parser-side, not guardrail-side — access-log
reads `llm.request_prompt_raw` directly.

### llm_router

Three-pass route selection in `matchRoute`
([middleware.go:241–300](../../../proxy/internal/middleware/builtin/llm_router/middleware.go)):
filter by `Models` claim → vendor-pin (a vendor-tagged request never crosses to
another vendor's route) → filter by `AllowedGroupIDs` intersection → model
precedence over path → tie-break by longest `UpstreamPath` prefix match.
Model-miss returns `llm_policy.model_not_routable`; known-but-unauthorised
returns `llm_policy.no_authorised_provider`. **Key invariant:** auth-header
strip+inject rides on `UpstreamRewrite.{StripHeaders,AuthHeader}`
([middleware.go:606–646](../../../proxy/internal/middleware/builtin/llm_router/middleware.go))
— NOT `HeadersAdd/HeadersRemove` — because the framework's mutation gate
blocks `Authorization` on the generic header path.

**Path-routed providers route before the model table.** `Invoke` checks
`isVertexPath` / `isBedrockPath`
([middleware.go:138–216](../../../proxy/internal/middleware/builtin/llm_router/middleware.go))
ahead of the model lookup, so a path-carried model can't be claimed by a
same-vendor body-routed provider. `matchPathRoute` enforces the route's `Models`
allowlist (empty = catch-all) even though the model came from the URL.
Two path-only behaviours:
- **Vertex unmeterable publisher** — when `llm_request_parser` emits no
  `llm.provider` (e.g. Gemini/`google`), the router denies with
  `llm_policy.unmeterable_publisher` (403) rather than forward it uncounted.
- **GCP token minting** — when the route carries `GCPServiceAccountKeyB64`
  (set from a `keyfile::` api_key), `gcpBearer` mints + caches a short-lived
  OAuth2 token per request instead of injecting a static value; a bad key or
  unreachable token endpoint denies with `llm_policy.upstream_auth_failed`
  (502). Bedrock uses its static bearer token directly (no minting).
- **`/bedrock` prefix** — an optional `/bedrock` gateway-namespace prefix is
  accepted and stripped via `RewriteUpstream.StripPathPrefix` so the native
  `/model/...` path reaches the upstream.

Full treatment in [50-path-routed-providers.md](./50-path-routed-providers.md).

### llm_limit_check

Pre-flight gate. Reads `llm.resolved_provider_id`, calls
`CheckLLMPolicyLimits` with a 2s context timeout
([middleware.go:24, 97–106](../../../proxy/internal/middleware/builtin/llm_limit_check/middleware.go)),
on allow stamps `llm.selected_policy_id`, `llm.attribution_group_id`,
`llm.attribution_window_seconds`. **Key invariant:** fail-open. Nil
`MgmtClient`, empty provider id, or RPC error returns `allowNoAttribution()`
— management outage doesn't take down every LLM request. Operators audit via
the access-log; a future flag may switch this to fail-closed.

### llm_identity_inject

Dispatches per-rule between LiteLLM-shaped `HeaderPair`
([middleware.go:169](../../../proxy/internal/middleware/builtin/llm_identity_inject/middleware.go))
and Portkey-shaped `JSONMetadata`
([middleware.go:292](../../../proxy/internal/middleware/builtin/llm_identity_inject/middleware.go)).
Identity is the peer's email (or `UserID` fallback); tags are the
**authorising-groups intersection** emitted by `llm_router`, not the full
`UserGroups` — a peer in 5 groups authorised under 1 only tags as that 1.
**Anti-spoof:** every `HeadersAdd` is preceded by a `HeadersRemove` of the
same name; the framework runs `Remove` before `Add` so client-supplied
identity never reaches the upstream. Body-level inject (`tags_in_body`,
`end_user_id_in_body`) is skipped on empty / truncated / non-JSON bodies so
header attribution stays intact.

### llm_guardrail

Model allowlist deny + optional prompt-capture-with-redaction. Allowlist
match is case-insensitive via `normaliseModel`; empty allowlist disables the
check. Prompt capture reads `llm.request_prompt_raw` and emits
`llm.request_prompt` only when `prompt_capture.enabled`
([middleware.go:149–165](../../../proxy/internal/middleware/builtin/llm_guardrail/middleware.go)).
**Key invariant:** `RedactPII` is the exported function the parsers call —
single PII contract across all three keys.

### llm_response_parser

Buffered and SSE paths share one `Invoke`
([middleware.go:102–127](../../../proxy/internal/middleware/builtin/llm_response_parser/middleware.go)):
content-type sniffing dispatches to `invokeBuffered` (JSON, status<400) or
`invokeStreaming` (text/event-stream, partial bodies tolerated). Streaming
delegates to `accumulateStream`
([streaming.go:21–30](../../../proxy/internal/middleware/builtin/llm_response_parser/streaming.go))
using `llm.NewScanner`. A third path, `accumulateBedrockStream`
([streaming_bedrock.go](../../../proxy/internal/middleware/builtin/llm_response_parser/streaming_bedrock.go)),
decodes the AWS binary event-stream (`application/vnd.amazon.eventstream`)
returned by Bedrock's `-stream` actions — InvokeModel `chunk` frames wrap a
base64 Anthropic event, Converse frames carry text + a trailing usage block.
Cached / cache-creation buckets emit only when non-zero, preserving the existing
token schema.

### cost_meter

Reads `llm.provider` + `llm.model` + token buckets, looks up per-1k rate via
`pricing.Loader`, emits `cost.usd_total` or a closed-set `cost.skipped`
reason (`missing_provider/model/tokens`, `unparseable_tokens`, `zero_tokens`,
`unknown_model`). Loader's hot-reload goroutine is bound to proxy-lifetime
context via `startReloader`. **Key invariant:** provider-shape switch lives
in `pricing.Table.Cost` (sibling doc) — `cost_meter` stays provider-agnostic.

### llm_limit_record

Post-flight write. Always returns `DecisionAllow`; response has already been
served so RPC errors mustn't surface (logged at `Debugf`). Skip-on-no-signal
at line 81 (zero tokens + zero cost). **Key invariant:** the
skip-on-missing-attribution guard at line 98 is a safety net independent of
the framework's deny short-circuit — if the gate denied and the framework
still runs the recorder, the recorder skips on absent
`UserID`+`groupID`+`UserGroups` and no phantom counter materialises.

## Full-chain diagram (canonical order)

```mermaid
flowchart TD
    A[HTTP request] --> B[llm_request_parser<br/>OnRequest]
    B -->|llm.provider, llm.model,<br/>llm.stream, llm.request_prompt_raw| C[llm_router<br/>OnRequest]
    C -->|llm.resolved_provider_id,<br/>llm.authorising_groups,<br/>upstream rewrite + auth| D[llm_limit_check<br/>OnRequest]
    D -->|deny path| Z1[403 llm_policy.*]
    D -->|allow + llm.selected_policy_id,<br/>llm.attribution_group_id,<br/>llm.attribution_window_seconds| E[llm_identity_inject<br/>OnRequest]
    E -->|header strip+inject<br/>+ optional body rewrite| F[llm_guardrail<br/>OnRequest]
    F -->|deny: model_blocked| Z2[403 llm_policy.model_blocked]
    F -->|allow + llm.request_prompt| G[upstream LLM call]
    G --> H[llm_response_parser<br/>OnResponse]
    H -->|llm.{input,output,total,cached_input,cache_creation}_tokens,<br/>llm.response_completion| I[cost_meter<br/>OnResponse]
    I -->|cost.usd_total or cost.skipped| J[llm_limit_record<br/>OnResponse]
    J --> K[response to client]
```

## limit_check ⇒ limit_record record-once invariant

```mermaid
sequenceDiagram
    participant LC as llm_limit_check
    participant M as management gRPC
    participant U as upstream LLM
    participant LR as llm_limit_record
    participant DB as sqlite consumption table

    LC->>M: CheckLLMPolicyLimits (2s)
    alt allow
        M-->>LC: selected_policy_id, attribution_group_id, window_s
        LC->>U: stamps attribution metadata
        U-->>LR: response + tokens (via llm_response_parser + cost_meter)
        LR->>M: RecordLLMUsage (5s, debug-on-error)
        M->>DB: increment (user, group, window) row
    else deny
        M-->>LC: llm_policy.token_cap_exceeded
        Note over LR: framework short-circuits; even if invoked,<br/>recorder skips on absent UserID+groupID+UserGroups
    else mgmt nil / rpc error
        LC-->>LC: allowNoAttribution() — fail open
        Note over LR: no window_s ⇒ recorder books only account-level<br/>budget rules (which run independently)
    end
```

The integration test
[agentnetwork_chain_integration_test.go](../../../proxy/internal/middleware/builtin/agentnetwork_chain_integration_test.go)
exercises all three branches against a real sqlite store + bufconn gRPC —
no mocks. Tests: `TestChain_AllowPath_StampsAttributionAndRecordsCounter`
(line 130), `TestChain_DenyPath_GateRejectsAndNoConsumptionWritten` (line
207), `TestChain_CapExhaustTransition` (line 265).

## Public contracts (per-middleware JSON config)

| Middleware | Config shape |
|---|---|
| `llm_request_parser` | `{provider_id?, redact_pii?, capture_prompt?: *bool}` ([factory.go:19–37](../../../proxy/internal/middleware/builtin/llm_request_parser/factory.go)) |
| `llm_router` | `{providers: [{id, models, upstream_scheme, upstream_host, upstream_path?, auth_header_name, auth_header_value, allowed_group_ids}]}` |
| `llm_limit_check` | `{}` — pulls `MgmtClient` from `FactoryContext` |
| `llm_identity_inject` | `{providers: [{provider_id, header_pair?|json_metadata?, extra_headers?}]}` |
| `llm_guardrail` | `{model_allowlist: []string, prompt_capture: {enabled, redact_pii}}` |
| `llm_response_parser` | `{redact_pii?, capture_completion?: *bool}` |
| `cost_meter` | `{pricing_path?}` (basename inside data-dir; defaults `pricing.yaml`) |
| `llm_limit_record` | `{}` — same pattern as `llm_limit_check` |

All factories accept empty / null / `{}` / whitespace as zero-value config;
only structurally invalid JSON is rejected so misconfig surfaces at chain
build time.

## Invariants

1. **limit_check ↔ limit_record paired.** They MUST appear together. Gate
   stamps attribution metadata on the request leg; recorder reads it on the
   response leg. If a chain contains only the recorder, the
   skip-on-missing-attribution guard at
   [llm_limit_record/middleware.go:81–87, 98–103](../../../proxy/internal/middleware/builtin/llm_limit_record/middleware.go)
   keeps counters consistent but no enforcement runs. Only-gate means
   counters never tick and headroom appears infinite.

2. **`capture_prompt` / `capture_completion` pointer semantics.** Both are
   `*bool`. `nil` = "preserve legacy emit" (back-compat default for
   non-agent-network callers and pre-toggle tests). `false` = suppress the
   key entirely (access-log row carries zero prompt / completion content).
   `true` = emit. The synthesiser sets the pointer explicitly to the
   account's `EnablePromptCollection` toggle. The handling lives
   in [llm_request_parser/factory.go:55–61](../../../proxy/internal/middleware/builtin/llm_request_parser/factory.go)
   and the symmetric [llm_response_parser/middleware.go:62–68](../../../proxy/internal/middleware/builtin/llm_response_parser/middleware.go);
   a missing pointer must not be treated as `false` (that would suppress
   capture for legacy non-agent-network callers).
   `redact_pii` is an orthogonal `bool` controlling **form** of emitted
   content, not whether it's emitted.

3. **`redact_pii` is parser-side.** Both parsers import
   `llm_guardrail.RedactPII` and run it BEFORE stamping the metadata bag.
   Load-bearing because the access-log sink reads `llm.request_prompt_raw`
   and `llm.response_completion` directly — by the time `llm_guardrail`
   runs its own pass on `llm.request_prompt`, the raw key has already been
   stamped. Tests: `TestInvoke_RedactPii_RedactsBeforeEmittingRawPrompt`,
   `TestInvoke_RedactPii_RedactsCompletionBeforeEmit`.

4. **Metadata allowlist enforcement.** Every middleware declares
   `MetadataKeys()`. The framework accumulator drops any KV outside that
   allowlist. When adding a new key, also extend the docstring in
   `middleware/keys.go`.

5. **Closed deny-code set.** All deny paths emit one of:
   `llm_policy.model_not_routable`, `llm_policy.no_authorised_provider`,
   `llm_policy.model_blocked`, `llm_policy.token_cap_exceeded`,
   `llm_policy.unmeterable_publisher` (path-routed Vertex publisher with no
   parser → 403), `llm_policy.upstream_auth_failed` (GCP token mint failure →
   502), or the management-supplied code on `llm_limit_check`. These surface
   verbatim; arbitrary middleware text never reaches the wire.

## Things to scrutinise

**Correctness.** `llm_router` model match treats an empty `Models` slice as
"claim every model"
([middleware.go:238–248](../../../proxy/internal/middleware/builtin/llm_router/middleware.go))
for gateway-style providers — confirm no real provider record ships with an
empty `Models` by accident. Path-prefix tie-break falls back to declaration
order when no candidate prefix-matches, so the synthesiser must emit a
deterministic order. `llm_limit_record` discards `strconv.ParseInt` errors
([middleware.go:78–80](../../../proxy/internal/middleware/builtin/llm_limit_record/middleware.go))
— relies on `llm_response_parser` always emitting parseable values; spot-check
the streaming partial path on truncated bodies.

**Security.** Auth headers must NEVER appear on `Mutations.HeadersAdd/Remove`
for the router — a direct headers path would bypass the framework gate. The
capture-pointer handling is the kind of place a bug ships PII to logs
silently; every synthesiser config path must set the pointer explicitly.
`llm_identity_inject` body inject silently skips on a
non-object `metadata` field
([middleware.go:262–270](../../../proxy/internal/middleware/builtin/llm_identity_inject/middleware.go))
— header path still attributes, but body-level tag-budget enforcement
doesn't run for that request.

**Concurrency.** `cost_meter` shares a `pricing.Loader` via
`atomic.Pointer[Table]`; readers always see a consistent table. Every
middleware is a stateless value receiver. Integration test uses real bufconn
gRPC — race detector is the meaningful bar.

**Perf.** Hot path is `lookupKV` linear scan over <10 KVs; `cost_meter.Cost`
is O(1); SSE accumulation is single-pass. No map allocation per call.

**Observability.** Every deny stamps `llm_policy.decision=deny` and a
matching `llm_policy.reason` — access-log can pivot on either.
`llm_limit_record` only logs at `Debugf` on RPC failure
([middleware.go:125–130](../../../proxy/internal/middleware/builtin/llm_limit_record/middleware.go));
operators need an alternate signal (metric on `RecordLLMUsage` failures) for
counter accuracy.

## Test coverage

| File | Tests | Notes |
|---|---:|---|
| `all_test.go` | 1 | Registry surface lock |
| `agentnetwork_chain_integration_test.go` | 3 | Allow/deny/cap-exhaust vs live sqlite + bufconn gRPC |
| `llm_request_parser/middleware_test.go` | 18 | `provider_id` bypass, redaction, capture-pointer, rune-safe truncation |
| `llm_router/middleware_test.go` | 19 | Three-pass match, deny codes, path-prefix tie-break, header strip+inject |
| `llm_limit_check/middleware_test.go` | 6 | Allow/deny, fail-open on nil mgmt / RPC error, attribution stamping |
| `llm_identity_inject/middleware_test.go` | 28 | HeaderPair, JSONMetadata, ExtraHeaders, body inject, anti-spoof |
| `llm_guardrail/middleware_test.go` | 15 | Allowlist case-insensitivity, prompt capture toggle, deny shape |
| `llm_guardrail/redact_test.go` | 15 | Email, SSN, phone (E.164 + NA), bearer, IPv4; fixture-driven |
| `llm_response_parser/middleware_test.go` | 18 | Buffered OAI+Anthro, capture-pointer, redact, truncation |
| `llm_response_parser/streaming_test.go` | 7 | OAI usage frame, Anthro message_delta, truncated body best-effort |
| `cost_meter/middleware_test.go` | 17 | Each skip reason, provider-shape, pricing loader integration |
| `llm_limit_record/middleware_test.go` | 7 | Skip-on-no-signal, skip-on-missing-attribution, RPC failure swallowed |

## Cross-references

- Sibling: [32-proxy-llm-parsers.md](./32-proxy-llm-parsers.md) — SDK adapters
  + SSE framer + pricing loader.
- Path-routed providers (Vertex AI + Bedrock), `keyfile::` credential, GCP
  token minting, `/bedrock` prefix:
  [50-path-routed-providers.md](./50-path-routed-providers.md).
- Upstream config: `management/server/agentnetwork/synthesizer` (out of scope).
- Framework: `proxy/internal/middleware/{chain,dispatcher,accumulator,registry}.go`.
- Metadata key registry: `proxy/internal/middleware/keys.go`.
- gRPC surface: `proto.ProxyServiceClient.{CheckLLMPolicyLimits,RecordLLMUsage}`.
