# path-routed providers — Vertex AI + Bedrock

This guide pulls the **path-routed** provider story together in one place
because it crosses the catalog, the synthesiser, the request parser, and the
router. The relevant building blocks are the `llm_router` /
`llm_request_parser` middlewares
([31-proxy-middleware-builtin.md](31-proxy-middleware-builtin.md)), the
per-provider parser surface ([32-proxy-llm-parsers.md](32-proxy-llm-parsers.md)),
and the synthesiser's catalog → `ProviderRoute` mapping
([21-management-agentnetwork.md](21-management-agentnetwork.md)).

Sibling modules: [31-proxy-middleware-builtin.md](31-proxy-middleware-builtin.md)
(router + request parser) and [32-proxy-llm-parsers.md](32-proxy-llm-parsers.md)
(Bedrock parser + pricing).

---

## What "path-routed" means

Most catalog providers carry the model in the request **body** (`{"model": …}`),
so `llm_router` selects an upstream by matching the model name against each
provider's `Models` claim. Two providers instead carry the model in the **URL
path**, so they are routed by path before the model/vendor table is consulted:

| Catalog id | Style flag | Request path shape |
|---|---|---|
| `vertex_ai_api` | `IsVertexPathStyle` → `ProviderRoute.Vertex` | `/v1/projects/{project}/locations/{region}/publishers/{publisher}/models/{model}:{action}` |
| `bedrock_api` | `IsBedrockPathStyle` → `ProviderRoute.Bedrock` | `/model/{modelId}/{action}` (optionally behind `/bedrock`) |

The catalog declares the style with
[`catalog.IsVertexPathStyle` / `catalog.IsBedrockPathStyle`](../../../management/server/agentnetwork/catalog/catalog.go)
and the synthesiser copies the result onto the router route as the `Vertex` /
`Bedrock` booleans
([synthesizer.go:450-451](../../../management/server/agentnetwork/synthesizer.go)).
On the request leg `llm_router.Invoke` dispatches `isVertexPath` / `isBedrockPath`
**before** the model lookup
([llm_router/middleware.go:138-216](../../../proxy/internal/middleware/builtin/llm_router/middleware.go))
so a model the parser extracted from the path can't be claimed by a same-vendor
*body-routed* provider (e.g. `claude-*` on `api.anthropic.com`).

## Google Vertex AI (`vertex_ai_api`)

### Catalog entry

`KindProvider`, parser surface left unset on the catalog entry — the request
parser picks the parser from the URL **publisher** segment, not from
`ParserID`. Upstream host is `<region>-aiplatform.googleapis.com`
(`https://aiplatform.googleapis.com` for the `global` location). The catalog
lists the Claude-on-Vertex lineup (`claude-opus-4-*`, `claude-sonnet-4-*`,
`claude-haiku-4-5`, `claude-fable-5`) at the same per-token rates as the
first-party Anthropic entry
([catalog.go:333-363](../../../management/server/agentnetwork/catalog/catalog.go)).

### Credential — service-account OAuth (`keyfile::`)

Vertex does **not** accept a static API key. The operator sets the provider
`api_key` to:

```
keyfile::<base64 of the GCP service-account JSON key>
```

The synthesiser recognises the `keyfile::` prefix in `providerAuthHeader`
([synthesizer.go:897-903](../../../management/server/agentnetwork/synthesizer.go)),
emits **no** static auth value, and carries the base64 key material on the
route as `GCPServiceAccountKeyB64`
([factory.go:56-61](../../../proxy/internal/middleware/builtin/llm_router/factory.go)).
At request time the router mints a short-lived OAuth2 access token from the key
(cloud-platform scope) and injects `Authorization: Bearer <access-token>` —
never the key itself
([llm_router/middleware.go:621-692](../../../proxy/internal/middleware/builtin/llm_router/middleware.go)):

- One auto-refreshing `oauth2.TokenSource` is cached per key (keyed by a
  SHA-256 of the base64 material), so token minting happens once and refreshes
  amortise across requests.
- Mint / refresh is bounded by a 10s timeout HTTP client (`gcpTokenTimeout`) so
  a slow Google token endpoint can't hang the request.
- A malformed key or an unreachable token endpoint fails the request with
  `llm_policy.upstream_auth_failed` at HTTP **502** (an upstream problem, not a
  policy denial) — see `denyUpstreamAuth`.

### Metering — Anthropic-on-Vertex only

The request parser extracts `{publisher, model, action}` from the path
(`parseVertexPath`, [llm_request_parser/middleware.go:237-263](../../../proxy/internal/middleware/builtin/llm_request_parser/middleware.go)),
strips the `@version` suffix from the model, and maps the publisher to a parser
surface via `vertexPublisherVendor`:

- `anthropic` → `llm.provider="anthropic"` → metered through the Anthropic
  parser, priced under the **`anthropic`** block in `defaults_pricing.yaml`
  (the parser emits the standard Anthropic provider label, so Vertex Claude
  reuses first-party Anthropic prices).
- `openai` → `llm.provider="openai"` (reserved; not in the catalog lineup
  today).
- anything else (notably `google` / Gemini) → empty vendor → **no parser**.

**Gemini is intentionally denied as unmeterable.** When the parser emits no
`llm.provider` for a Vertex publisher, `llm_router` returns
`llm_policy.unmeterable_publisher` (403) rather than forwarding the request
uncounted — serving it would bypass token / budget metering
([llm_router/middleware.go:144-162, 712-728](../../../proxy/internal/middleware/builtin/llm_router/middleware.go)).
A Gemini parser would lift this restriction; until then the `google` publisher
is omitted from the catalog.

> Caveat: cross-region inference profiles in `eu` / `apac` carry a ~10% price
> premium that the base per-token rates do **not** model — cost annotations for
> those regions read low. Operators who need exact regional billing override
> the affected entries in `pricing.yaml`.

## AWS Bedrock (`bedrock_api`)

### Catalog entry

`KindProvider`, upstream host `bedrock-runtime.<region>.amazonaws.com`. Metered
models are the Anthropic-on-Bedrock lineup (`anthropic.claude-*`) plus Amazon
Nova and Llama 3.3 entries
([catalog.go:300-332](../../../management/server/agentnetwork/catalog/catalog.go)).
Anthropic-on-Bedrock reuses the first-party Claude prices (with additive cache
buckets); Nova / Llama report no cache, so cost is `input + output`.

### Credential — static bearer token

Bedrock uses the **AWS Bedrock API key** as a static bearer. The operator sets
the provider `api_key` directly (no `keyfile::` prefix); the catalog template
is `Authorization: Bearer ${API_KEY}`
([catalog.go:306-307](../../../management/server/agentnetwork/catalog/catalog.go)).
No token minting — the synthesiser substitutes the key into the template and
the router injects the resulting `Authorization` header after stripping inbound
vendor auth (including client-supplied AWS SigV4 material: `X-Amz-Date`,
`X-Amz-Security-Token`, `X-Amz-Content-Sha256`, see `strippedAuthHeaders`).

### Model id form — cross-region inference profiles

Bedrock model ids in the request path must be the cross-region
**inference-profile** form, e.g.
`eu.anthropic.claude-sonnet-4-5-20250929-v1:0`. The bare
`anthropic.claude-…` id is rejected by AWS. `normalizeBedrockModel`
([llm_request_parser/middleware.go:398-414](../../../proxy/internal/middleware/builtin/llm_request_parser/middleware.go))
strips the region prefix (`us.` / `eu.` / `apac.` / `global.`), an optional ARN
wrapper, and the `-YYYYMMDD-vN[:N]` version/throughput suffix so the normalised
id (`anthropic.claude-sonnet-4-5`) matches the catalog/pricing key.

### Supported endpoints + actions

`/model/{modelId}/{action}` where action ∈ `invoke`,
`invoke-with-response-stream`, `converse`, `converse-stream`
([llm_request_parser/middleware.go:363-390](../../../proxy/internal/middleware/builtin/llm_request_parser/middleware.go)).
`invoke` / `converse` are non-streaming; the `-stream` actions set the streaming
flag.

- **InvokeModel** body uses the vendor-native shape — for Anthropic that means
  `"anthropic_version":"bedrock-2023-05-31"` and snake_case usage with additive
  cache buckets.
- **Converse** uses the unified camelCase shape with a precomputed `totalTokens`.
- The `BedrockParser` reads both shapes on the response leg
  ([bedrock.go](../../../proxy/internal/llm/bedrock.go)); the request parser
  doesn't need to distinguish them (`ParseRequest` is a no-op — model + stream
  come from the path).

### Streaming — AWS binary event-stream

The `-stream` actions return `application/vnd.amazon.eventstream` (the AWS
binary event-stream framing), and streaming **is metered**.
`accumulateBedrockStream`
([llm_response_parser/streaming_bedrock.go](../../../proxy/internal/middleware/builtin/llm_response_parser/streaming_bedrock.go))
decodes the frames with `aws-sdk-go-v2/aws/protocol/eventstream`:

- InvokeModel `chunk` frames wrap a base64 `{"bytes":…}` payload carrying a
  vendor-native (Anthropic) stream event — folded through the shared Anthropic
  stream accumulator.
- Converse `contentBlockDelta` frames carry text; the trailing `metadata` frame
  carries the final usage block.
- A truncated stream (cut at the body-tap capture cap) decodes best-effort:
  frames up to the cut are applied and partial usage is returned.

### Optional `/bedrock` gateway-namespace prefix

Clients may place an optional `/bedrock` prefix before the native path
(`/bedrock/model/{modelId}/{action}`) to disambiguate Bedrock from other
providers that also use `/model/...`. Both the request parser
(`trimBedrockNamespace`) and the router (`splitBedrockNamespace`) accept it.
When the prefix is present, the router sets
`RewriteUpstream.StripPathPrefix = "/bedrock"` so the **native** path
(`/model/...`) is what reaches `bedrock-runtime.<region>.amazonaws.com`
([llm_router/middleware.go:168-184, 320-348](../../../proxy/internal/middleware/builtin/llm_router/middleware.go)).

## Model allowlist on path-routed providers

Because the model lives in the URL rather than the body, a path-routed provider
credential could otherwise be used for any model the upstream supports. The
router still enforces the route's `Models` allowlist via `matchPathRoute`
([llm_router/middleware.go:370-416](../../../proxy/internal/middleware/builtin/llm_router/middleware.go)):

1. Filter to routes of the matching style (`Vertex` / `Bedrock`).
2. Filter to routes whose `AllowedGroupIDs` authorise the caller's groups
   (else `no_authorised_provider`).
3. Filter to routes that **claim the requested model**. As with body-routed
   providers, an **empty `Models` list = catch-all** (serve any model);
   a non-empty list serves only the listed models (else `model_not_routable`).
4. Multiple survivors disambiguate by longest `UpstreamPath` prefix match.

So an operator who lists explicit models on a Vertex/Bedrock provider gets a
hard allowlist; an operator who leaves `Models` empty accepts every model the
upstream serves (still subject to the unmeterable-publisher gate on Vertex).

Model-less OpenAI endpoints (`GET /v1/models`) are **never** routed to a
Vertex/Bedrock provider — `matchModelless` skips path-routed routes
([llm_router/middleware.go:427-462](../../../proxy/internal/middleware/builtin/llm_router/middleware.go))
so a model-listing call can't be rewritten onto an upstream that would 404 it.

## Catalog ↔ pricing cross-check

Catalog prices and context windows are cross-checked against LiteLLM's
`model_prices_and_context_window.json`. The proxy's embedded
`defaults_pricing.yaml` covers **every metered first-party model** the catalog
enumerates — guarded by
`TestDefaultTable_FirstPartyModelCoverage`
([pricing/defaults_coverage_test.go](../../../proxy/internal/llm/pricing/defaults_coverage_test.go)),
which fails if a catalog model has no embedded price. Bedrock entries are keyed
by the **normalised** id the request parser emits (region prefix + version
suffix stripped). Vertex Claude carries no Bedrock-style prefix, so it prices
straight off the `anthropic` block.

## Things to scrutinise

**Security.** The Vertex service-account key is never forwarded — only a minted
short-lived bearer. Confirm the key material stays out of access logs (it lives
on `ProviderRoute.GCPServiceAccountKeyB64`, not in any emitted metadata key).
The unmeterable-publisher deny is the only thing standing between an
operator-misconfigured Vertex provider and unmetered Gemini traffic; verify
`vertexPublisherVendor` stays conservative (deny by default for unknown
publishers).

**Correctness.** `normalizeBedrockModel` is the join between the wire id and the
pricing key — a model that normalises to something not in `defaults_pricing.yaml`
meters at `cost.skipped=unknown_model` rather than failing the request. The
`/bedrock` prefix strip must run on both the parser side (so the model is
extracted) and the router side (so the upstream path is native); a regression in
either silently breaks the other.

**Metering caveats.** eu/apac cross-region Bedrock + Vertex profiles carry a
~10% premium not modelled by base pricing — flagged in both the catalog comment
and `defaults_pricing.yaml`. Operators needing exact regional billing override
the relevant entries.

## Cross-references

- Router + request-parser detail: [31-proxy-middleware-builtin.md](31-proxy-middleware-builtin.md)
- Bedrock parser + pricing + SSE / event-stream: [32-proxy-llm-parsers.md](32-proxy-llm-parsers.md)
- Catalog → route synthesis + `keyfile::` handling: [21-management-agentnetwork.md](21-management-agentnetwork.md)
- Overview: [../00-overview.md](../00-overview.md)
