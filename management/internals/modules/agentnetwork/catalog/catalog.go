// Package catalog defines the static set of Agent Network providers
// recognized by the management server. The catalog is consulted both to
// validate provider_id on create/update and to surface the available
// providers (and their models) to the dashboard.
package catalog

import "github.com/netbirdio/netbird/shared/management/http/api"

// Model is the in-memory representation of a catalog model.
type Model struct {
	ID            string
	Label         string
	InputPer1k    float64
	OutputPer1k   float64
	ContextWindow int
}

// ProviderKind groups catalog entries for UI presentation. The split
// is semantic, not technical:
//   - KindProvider: the upstream is a vendor's first-party API (OpenAI,
//     Anthropic, Mistral, Bedrock, etc.) — NetBird talks straight to
//     the model provider.
//   - KindGateway: the upstream is itself a routing / aggregation layer
//     in front of multiple providers (LiteLLM, Portkey, Helicone, …).
//     These typically need NetBird identity stamped onto upstream
//     requests so the gateway's analytics and budgets attribute to the
//     real caller; that's what IdentityInjection is for.
//   - KindCustom: the catch-all "OpenAI-compatible self-hosted endpoint"
//     entry (vLLM, Ollama, custom inference servers).
//
// Frontend uses Kind to group the provider Select in the modal so an
// operator can spot at a glance which catalog entries proxy other
// providers vs. talk straight to one. Backend doesn't dispatch on Kind
// today; it's purely a presentation hint.
type ProviderKind string

const (
	KindProvider ProviderKind = "provider"
	KindGateway  ProviderKind = "gateway"
	KindCustom   ProviderKind = "custom"
)

// Provider is the in-memory representation of a catalog provider.
type Provider struct {
	ID          string
	Name        string
	Description string
	DefaultHost string
	// Kind groups this entry for UI presentation; see ProviderKind.
	Kind ProviderKind
	// AuthHeaderName is the HTTP header the provider's API expects
	// the credential under (e.g. "Authorization" for OpenAI,
	// "x-api-key" for Anthropic). Combined with AuthHeaderTemplate
	// at synthesis time to inject the auth header on every upstream
	// request.
	AuthHeaderName     string
	AuthHeaderTemplate string
	DefaultContentType string
	BrandColor         string
	// ParserID names the proxy LLM parser surface this provider
	// speaks (matches llm.Parser.ProviderName: "openai",
	// "anthropic"). Multiple catalog ids may share a parser surface
	// (e.g. azure_openai_api and mistral_api both speak the OpenAI
	// shape). Empty when no parser is yet implemented for the
	// surface — the proxy middleware then falls back to URL sniffing
	// or skips request-side enrichment.
	ParserID string
	// IdentityInjection, when non-nil, instructs the proxy to stamp
	// the caller's NetBird identity onto upstream requests under the
	// configured header names. Used for gateways like LiteLLM that
	// key budgets and attribution off request headers (the gateway
	// otherwise has no way to learn which user / group made the call).
	// The proxy strips the same header names from the inbound request
	// before stamping ours, so an app can't spoof identity by setting
	// these headers itself.
	IdentityInjection *IdentityInjection
	// ExtraHeaders is a catalog-declared list of additional per-
	// provider routing/config headers the proxy stamps on every
	// upstream request. Distinct from AuthHeaderName/Template (which
	// always carries the API_KEY) and from IdentityInjection (caller
	// identity). Each entry surfaces an optional input on the
	// dashboard's provider modal whose value lives on the provider
	// record's ExtraValues map (keyed by ExtraHeader.Name). Empty
	// list = no extra inputs rendered. Used today by Portkey for
	// "x-portkey-config: pc-..." (a saved-config id that resolves
	// upstream provider + credentials on Portkey's hosted side).
	ExtraHeaders []ExtraHeader
	Models       []Model
}

// ExtraHeader names a single optional per-provider routing/config
// header. Catalog declares N of these per provider type; the operator
// fills any subset on the provider record (see Provider.ExtraValues).
// At synth time, only entries with a non-empty operator value are
// stamped; the proxy's identity-inject middleware applies anti-spoof
// (Remove + Add) so a client can't supply these headers themselves.
//
// UI copy (label / help text / tooltip) for each known Name lives on
// the dashboard, not here — the backend's job is just to declare
// which wire headers are accepted. New provider needs an extra
// header? Add the Name here AND the matching UI copy on the dashboard.
type ExtraHeader struct {
	// Name is the wire header name, e.g. "x-portkey-config".
	Name string
}

// IdentityInjection describes how the proxy stamps NetBird identity onto
// upstream gateway requests. Exactly one shape must be set — they're
// mutually exclusive and dispatched by the inject middleware.
//
// Shape choice tracks the wire convention the upstream gateway uses,
// not the vendor name. New gateways with a known shape become a catalog
// entry, not a new code path.
type IdentityInjection struct {
	// HeaderPair emits separate headers per identity dimension
	// (end-user id, tags as CSV). LiteLLM and OpenAI-compatible
	// self-hosted gateways that read identity from dedicated headers.
	HeaderPair *HeaderPairInjection
	// JSONMetadata emits a single header carrying a JSON object with
	// reserved keys for user / groups / etc. Portkey, Helicone-style
	// metadata headers, anything that wants a structured envelope.
	JSONMetadata *JSONMetadataInjection
}

// HeaderPairInjection is the LiteLLM-style wire convention.
type HeaderPairInjection struct {
	// Customizable, when true, marks the wire header names as
	// operator-overridable: the dashboard surfaces EndUserIDHeader
	// and TagsHeader as editable inputs (defaults shown as
	// placeholders) and the synthesizer pulls the actual values from
	// the provider record's IdentityHeader* fields rather than from
	// these defaults. An empty operator value disables stamping for
	// that dimension. Used today for Bifrost, whose log-metadata /
	// telemetry header prefix (x-bf-lh-* vs x-bf-dim-*) is a
	// per-operator choice; LiteLLM and similar gateways with a fixed
	// wire protocol leave this false so the catalog defaults are
	// authoritative.
	Customizable bool
	// EndUserIDHeader receives the caller's display identity (user
	// email when the peer is attached to a user, else peer.Name),
	// e.g. "x-litellm-end-user-id".
	EndUserIDHeader string
	// TagsHeader receives the caller's NetBird group display names
	// as a CSV, e.g. "x-litellm-tags".
	TagsHeader string
	// TagsInBody, when true, additionally writes the tag list into
	// the request body's metadata.tags array (a JSON path the
	// gateway parses for budget enforcement). LiteLLM only honours
	// metadata.tags for tag-budget gating — its x-litellm-tags
	// header path feeds spend tracking but bypasses
	// _tag_max_budget_check entirely. Body inject is skipped when
	// the request body is empty, truncated, non-JSON, or when an
	// existing metadata field is a non-object value (defensive: we
	// never clobber a client-supplied non-object). The header path
	// remains a robust fallback for spend tracking in those cases.
	TagsInBody bool
	// EndUserIDInBody, when true, additionally writes the display
	// identity into the request body's top-level "user" field (the
	// OpenAI-standard end-user identifier). LiteLLM resolves the end
	// user id from headers first then body, so for LiteLLM this is
	// belt-and-suspenders. It matters when an OpenAI-compatible
	// gateway downstream of LiteLLM (or OpenAI direct, bypassing
	// LiteLLM) only reads the body, and as anti-spoof: client-
	// supplied "user" values are overwritten with our trusted
	// identity. Same skip rules as TagsInBody.
	EndUserIDInBody bool
}

// JSONMetadataInjection is the Portkey-style wire convention: a single
// header carrying a JSON object. NetBird identity fields land under the
// configured reserved keys; missing keys (empty string) are skipped at
// emit time.
type JSONMetadataInjection struct {
	// Customizable, when true, marks the JSON keys as operator-
	// overridable. The dashboard surfaces UserKey and GroupsKey as
	// editable inputs (the catalog values shown as placeholders) and
	// the synthesizer pulls the actual JSON-key names from the
	// provider record's IdentityHeader* fields. Same field reuse as
	// HeaderPair's customizable path — the dimensions (user identity,
	// groups) are the same, only the wire encoding differs (JSON key
	// vs HTTP header name). An empty operator value disables emission
	// for that dimension. Used today for Cloudflare AI Gateway, whose
	// cf-aig-metadata header accepts arbitrary JSON keys; Portkey
	// leaves this false because its keys are reserved by the Portkey
	// schema.
	Customizable bool
	// Header is the wire header name carrying the JSON payload, e.g.
	// "x-portkey-metadata".
	Header string
	// UserKey is the JSON key for the caller's display identity.
	// Portkey reserves "_user" for this dimension.
	UserKey string
	// GroupsKey is the JSON key for the caller's NetBird groups,
	// emitted as a CSV string value (Portkey requires string values).
	GroupsKey string
	// MaxValueLength caps each emitted JSON value, in bytes. Portkey
	// enforces a 128-char limit per value; oversized values are
	// truncated rather than failing the request. 0 disables the cap.
	MaxValueLength int
}

// providers is the canonical list of supported Agent Network providers.
// Update this list together with the dashboard's PROVIDER_CATALOG.
var providers = []Provider{
	{
		ID:                 "openai_api",
		Kind:               KindProvider,
		Name:               "OpenAI API",
		Description:        "GPT, Responses API, and Embeddings",
		DefaultHost:        "api.openai.com",
		AuthHeaderName:     "Authorization",
		AuthHeaderTemplate: "Bearer ${API_KEY}",
		DefaultContentType: "application/json",
		BrandColor:         "#10A37F",
		ParserID:           "openai",
		// Pricing + context windows cross-checked against LiteLLM's
		// model_prices_and_context_window.json. Notable corrections from
		// earlier values: o4-mini repriced from $4/$16 to $1.10/$4.40
		// per MTok, gpt-4o from $5/$15 to $2.50/$10, and the GPT-5
		// family context windows split between 1.05M for full-size
		// models and 272K for mini/nano/codex variants.
		Models: []Model{
			{ID: "gpt-5.5", Label: "GPT-5.5", InputPer1k: 0.005, OutputPer1k: 0.030, ContextWindow: 1050000},
			{ID: "gpt-5.5-pro", Label: "GPT-5.5 Pro", InputPer1k: 0.030, OutputPer1k: 0.180, ContextWindow: 1050000},
			{ID: "gpt-5.4", Label: "GPT-5.4", InputPer1k: 0.0025, OutputPer1k: 0.015, ContextWindow: 1050000},
			{ID: "gpt-5.4-pro", Label: "GPT-5.4 Pro", InputPer1k: 0.030, OutputPer1k: 0.180, ContextWindow: 1050000},
			{ID: "gpt-5.4-mini", Label: "GPT-5.4 Mini", InputPer1k: 0.00075, OutputPer1k: 0.0045, ContextWindow: 272000},
			{ID: "gpt-5.4-nano", Label: "GPT-5.4 Nano", InputPer1k: 0.0002, OutputPer1k: 0.00125, ContextWindow: 272000},
			{ID: "gpt-5.3-codex", Label: "GPT-5.3 Codex", InputPer1k: 0.00175, OutputPer1k: 0.014, ContextWindow: 272000},
			{ID: "gpt-5.3-chat-latest", Label: "GPT-5.3 Chat", InputPer1k: 0.00175, OutputPer1k: 0.014, ContextWindow: 128000},
			{ID: "o4-mini", Label: "o4-mini", InputPer1k: 0.0011, OutputPer1k: 0.0044, ContextWindow: 200000},
			{ID: "gpt-4.1", Label: "GPT-4.1", InputPer1k: 0.002, OutputPer1k: 0.008, ContextWindow: 1047576},
			{ID: "gpt-4.1-mini", Label: "GPT-4.1 mini", InputPer1k: 0.0004, OutputPer1k: 0.0016, ContextWindow: 1047576},
			{ID: "gpt-4.1-nano", Label: "GPT-4.1 nano", InputPer1k: 0.0001, OutputPer1k: 0.0004, ContextWindow: 1047576},
			{ID: "gpt-4o", Label: "GPT-4o", InputPer1k: 0.0025, OutputPer1k: 0.010, ContextWindow: 128000},
			{ID: "gpt-4o-mini", Label: "GPT-4o mini", InputPer1k: 0.00015, OutputPer1k: 0.0006, ContextWindow: 128000},
			{ID: "gpt-4-turbo", Label: "GPT-4 Turbo", InputPer1k: 0.01, OutputPer1k: 0.03, ContextWindow: 128000},
			{ID: "gpt-3.5-turbo", Label: "GPT-3.5 Turbo", InputPer1k: 0.0005, OutputPer1k: 0.0015, ContextWindow: 16385},
			{ID: "text-embedding-3-large", Label: "text-embedding-3-large", InputPer1k: 0.00013, OutputPer1k: 0, ContextWindow: 8191},
			{ID: "text-embedding-3-small", Label: "text-embedding-3-small", InputPer1k: 0.00002, OutputPer1k: 0, ContextWindow: 8191},
		},
	},
	{
		ID:                 "anthropic_api",
		Kind:               KindProvider,
		Name:               "Anthropic API",
		Description:        "Claude Messages API",
		DefaultHost:        "api.anthropic.com",
		AuthHeaderName:     "x-api-key",
		AuthHeaderTemplate: "${API_KEY}",
		DefaultContentType: "application/json",
		BrandColor:         "#D97757",
		ParserID:           "anthropic",
		// Per Anthropic's current model lineup. Pricing in USD per 1k
		// tokens. Context windows: 4.6+ family is 1M; Haiku 4.5 stays at
		// 200K. claude-3-7-sonnet and claude-3-5-haiku retired
		// 2026-02-19 — dropped from the catalog. claude-opus-4-1
		// deprecated, retires 2026-08-05 — kept until the cutover.
		// claude-mythos-5 omitted: Project Glasswing access only, not a
		// general-availability target. claude-fable-5 requires the
		// account to be on >= 30-day data retention or all requests
		// 400.
		Models: []Model{
			{ID: "claude-fable-5", Label: "Claude Fable 5", InputPer1k: 0.010, OutputPer1k: 0.050, ContextWindow: 1000000},
			{ID: "claude-opus-4-8", Label: "Claude Opus 4.8", InputPer1k: 0.005, OutputPer1k: 0.025, ContextWindow: 1000000},
			{ID: "claude-opus-4-7", Label: "Claude Opus 4.7", InputPer1k: 0.005, OutputPer1k: 0.025, ContextWindow: 1000000},
			{ID: "claude-opus-4-6", Label: "Claude Opus 4.6", InputPer1k: 0.005, OutputPer1k: 0.025, ContextWindow: 1000000},
			{ID: "claude-opus-4-1", Label: "Claude Opus 4.1 (deprecated, retires 2026-08-05)", InputPer1k: 0.015, OutputPer1k: 0.075, ContextWindow: 200000},
			{ID: "claude-sonnet-4-6", Label: "Claude Sonnet 4.6", InputPer1k: 0.003, OutputPer1k: 0.015, ContextWindow: 1000000},
			{ID: "claude-sonnet-4-5", Label: "Claude Sonnet 4.5", InputPer1k: 0.003, OutputPer1k: 0.015, ContextWindow: 200000},
			{ID: "claude-haiku-4-5", Label: "Claude Haiku 4.5", InputPer1k: 0.001, OutputPer1k: 0.005, ContextWindow: 200000},
		},
	},
	{
		ID:                 "azure_openai_api",
		Kind:               KindProvider,
		Name:               "Azure OpenAI API",
		Description:        "Azure-hosted OpenAI deployments",
		DefaultHost:        "<resource>.openai.azure.com",
		AuthHeaderName:     "api-key",
		AuthHeaderTemplate: "${API_KEY}",
		DefaultContentType: "application/json",
		BrandColor:         "#0078D4",
		ParserID:           "openai",
		// Mirrors openai_api pricing — Azure resells OpenAI models at the
		// same per-token rates, just under different deployment names.
		Models: []Model{
			{ID: "gpt-5.5", Label: "GPT-5.5 (Azure)", InputPer1k: 0.005, OutputPer1k: 0.030, ContextWindow: 1050000},
			{ID: "gpt-5.4", Label: "GPT-5.4 (Azure)", InputPer1k: 0.0025, OutputPer1k: 0.015, ContextWindow: 1050000},
			{ID: "gpt-5.4-mini", Label: "GPT-5.4 Mini (Azure)", InputPer1k: 0.00075, OutputPer1k: 0.0045, ContextWindow: 272000},
			{ID: "gpt-5.4-nano", Label: "GPT-5.4 Nano (Azure)", InputPer1k: 0.0002, OutputPer1k: 0.00125, ContextWindow: 272000},
			{ID: "o4-mini", Label: "o4-mini (Azure)", InputPer1k: 0.0011, OutputPer1k: 0.0044, ContextWindow: 200000},
			{ID: "gpt-4.1", Label: "GPT-4.1 (Azure)", InputPer1k: 0.002, OutputPer1k: 0.008, ContextWindow: 1047576},
			{ID: "gpt-4.1-mini", Label: "GPT-4.1 mini (Azure)", InputPer1k: 0.0004, OutputPer1k: 0.0016, ContextWindow: 1047576},
			{ID: "gpt-4o", Label: "GPT-4o (Azure)", InputPer1k: 0.0025, OutputPer1k: 0.010, ContextWindow: 128000},
			{ID: "gpt-4o-mini", Label: "GPT-4o mini (Azure)", InputPer1k: 0.00015, OutputPer1k: 0.0006, ContextWindow: 128000},
			{ID: "gpt-35-turbo", Label: "GPT-3.5 Turbo (Azure)", InputPer1k: 0.0005, OutputPer1k: 0.0015, ContextWindow: 16385},
		},
	},
	{
		ID:                 "bedrock_api",
		Kind:               KindProvider,
		Name:               "AWS Bedrock API",
		Description:        "Anthropic, Meta, Cohere via Bedrock",
		DefaultHost:        "bedrock-runtime.<region>.amazonaws.com",
		AuthHeaderName:     "Authorization",
		AuthHeaderTemplate: "Bearer ${API_KEY}",
		DefaultContentType: "application/json",
		BrandColor:         "#FF9900",
		// Anthropic models on Bedrock take the anthropic.* prefix and
		// follow the same lineup / pricing as the first-party Anthropic
		// catalog entry above. claude-3-7-sonnet and claude-3-5-haiku
		// were retired upstream on 2026-02-19 — dropped from the
		// Bedrock list too. Amazon Nova entries cross-checked against
		// LiteLLM (added Nova Micro + the new Nova 2 Lite preview).
		// Llama 3.3 70B entry kept unchanged — LiteLLM tracks only
		// per-region Llama 3 entries; standalone 3.3 not yet listed.
		Models: []Model{
			{ID: "anthropic.claude-opus-4-8", Label: "Claude Opus 4.8 (Bedrock)", InputPer1k: 0.005, OutputPer1k: 0.025, ContextWindow: 1000000},
			{ID: "anthropic.claude-opus-4-7", Label: "Claude Opus 4.7 (Bedrock)", InputPer1k: 0.005, OutputPer1k: 0.025, ContextWindow: 1000000},
			{ID: "anthropic.claude-opus-4-6", Label: "Claude Opus 4.6 (Bedrock)", InputPer1k: 0.005, OutputPer1k: 0.025, ContextWindow: 1000000},
			{ID: "anthropic.claude-opus-4-1", Label: "Claude Opus 4.1 (Bedrock, deprecated 2026-08-05)", InputPer1k: 0.015, OutputPer1k: 0.075, ContextWindow: 200000},
			{ID: "anthropic.claude-sonnet-4-6", Label: "Claude Sonnet 4.6 (Bedrock)", InputPer1k: 0.003, OutputPer1k: 0.015, ContextWindow: 1000000},
			{ID: "anthropic.claude-sonnet-4-5", Label: "Claude Sonnet 4.5 (Bedrock)", InputPer1k: 0.003, OutputPer1k: 0.015, ContextWindow: 200000},
			{ID: "anthropic.claude-haiku-4-5", Label: "Claude Haiku 4.5 (Bedrock)", InputPer1k: 0.001, OutputPer1k: 0.005, ContextWindow: 200000},
			{ID: "meta.llama3-3-70b-instruct", Label: "Llama 3.3 70B (Bedrock)", InputPer1k: 0.00072, OutputPer1k: 0.00072, ContextWindow: 128000},
			{ID: "amazon.nova-2-lite", Label: "Amazon Nova 2 Lite (Bedrock, preview)", InputPer1k: 0.0003, OutputPer1k: 0.0025, ContextWindow: 1000000},
			{ID: "amazon.nova-pro", Label: "Amazon Nova Pro (Bedrock)", InputPer1k: 0.0008, OutputPer1k: 0.0032, ContextWindow: 300000},
			{ID: "amazon.nova-lite", Label: "Amazon Nova Lite (Bedrock)", InputPer1k: 0.00006, OutputPer1k: 0.00024, ContextWindow: 300000},
			{ID: "amazon.nova-micro", Label: "Amazon Nova Micro (Bedrock)", InputPer1k: 0.000035, OutputPer1k: 0.00014, ContextWindow: 128000},
		},
	},
	{
		ID:                 "vertex_ai_api",
		Kind:               KindProvider,
		Name:               "Google Vertex AI API",
		Description:        "Anthropic Claude models hosted on Vertex AI",
		DefaultHost:        "<region>-aiplatform.googleapis.com",
		AuthHeaderName:     "Authorization",
		AuthHeaderTemplate: "Bearer ${API_KEY}",
		DefaultContentType: "application/json",
		BrandColor:         "#4285F4",
		// Vertex carries the model in the URL path and authenticates with a
		// service-account-minted OAuth token (api_key = "keyfile::<base64 SA>").
		// Only Anthropic-on-Vertex is metered today: the request parser maps the
		// anthropic publisher to the Anthropic parser, so the lineup + prices
		// mirror the first-party Anthropic catalog (LiteLLM vertex_ai/claude-*
		// confirms the same per-token rates; cross-region profiles in eu/apac
		// carry a ~10% premium that base pricing does not model). Gemini (the
		// google publisher) is intentionally omitted until a Gemini parser
		// exists — the router denies unmeterable publishers rather than forward
		// them uncounted.
		Models: []Model{
			{ID: "claude-fable-5", Label: "Claude Fable 5 (Vertex)", InputPer1k: 0.010, OutputPer1k: 0.050, ContextWindow: 1000000},
			{ID: "claude-opus-4-8", Label: "Claude Opus 4.8 (Vertex)", InputPer1k: 0.005, OutputPer1k: 0.025, ContextWindow: 1000000},
			{ID: "claude-opus-4-7", Label: "Claude Opus 4.7 (Vertex)", InputPer1k: 0.005, OutputPer1k: 0.025, ContextWindow: 1000000},
			{ID: "claude-opus-4-6", Label: "Claude Opus 4.6 (Vertex)", InputPer1k: 0.005, OutputPer1k: 0.025, ContextWindow: 1000000},
			{ID: "claude-opus-4-1", Label: "Claude Opus 4.1 (Vertex, deprecated 2026-08-05)", InputPer1k: 0.015, OutputPer1k: 0.075, ContextWindow: 200000},
			{ID: "claude-sonnet-4-6", Label: "Claude Sonnet 4.6 (Vertex)", InputPer1k: 0.003, OutputPer1k: 0.015, ContextWindow: 1000000},
			{ID: "claude-sonnet-4-5", Label: "Claude Sonnet 4.5 (Vertex)", InputPer1k: 0.003, OutputPer1k: 0.015, ContextWindow: 200000},
			{ID: "claude-haiku-4-5", Label: "Claude Haiku 4.5 (Vertex)", InputPer1k: 0.001, OutputPer1k: 0.005, ContextWindow: 200000},
		},
	},
	{
		ID:                 "mistral_api",
		Kind:               KindProvider,
		Name:               "Mistral API",
		Description:        "Mistral cloud API",
		DefaultHost:        "api.mistral.ai",
		AuthHeaderName:     "Authorization",
		AuthHeaderTemplate: "Bearer ${API_KEY}",
		DefaultContentType: "application/json",
		BrandColor:         "#FF7000",
		ParserID:           "openai",
		// Pricing + context windows cross-checked against LiteLLM. Key
		// gotchas the marketing page hides:
		//   - `mistral-medium-latest` aliases to Medium 3.1 ($0.40/$2),
		//     NOT Medium 3.5 ($1.50/$7.50). Catalog exposes both.
		//   - `mistral-large-latest` aliases to Large 3 — 262K context,
		//     cheaper than Medium 3.5.
		//   - Magistral models are tuned for reasoning but cap context
		//     at only 40K (vs 128K-262K elsewhere).
		//   - `codestral-latest` still routes to the old 2405 build
		//     ($1/$3) per LiteLLM; the newer codestral-2508 is both
		//     cheaper and longer-context. Both exposed.
		//   - Pixtral was folded into the main Large/Medium series; no
		//     standalone vision entry.
		Models: []Model{
			{ID: "mistral-large-latest", Label: "Mistral Large 3", InputPer1k: 0.0005, OutputPer1k: 0.0015, ContextWindow: 262144},
			{ID: "mistral-medium-latest", Label: "Mistral Medium 3.1", InputPer1k: 0.0004, OutputPer1k: 0.002, ContextWindow: 131072},
			{ID: "mistral-medium-3-5", Label: "Mistral Medium 3.5", InputPer1k: 0.0015, OutputPer1k: 0.0075, ContextWindow: 262144},
			{ID: "mistral-small-latest", Label: "Mistral Small 3.2", InputPer1k: 0.00006, OutputPer1k: 0.00018, ContextWindow: 131072},
			{ID: "magistral-medium-latest", Label: "Magistral Medium (reasoning)", InputPer1k: 0.002, OutputPer1k: 0.005, ContextWindow: 40000},
			{ID: "magistral-small-latest", Label: "Magistral Small (reasoning)", InputPer1k: 0.0005, OutputPer1k: 0.0015, ContextWindow: 40000},
			{ID: "devstral-medium-latest", Label: "Devstral Medium 2 (coding)", InputPer1k: 0.0004, OutputPer1k: 0.002, ContextWindow: 256000},
			{ID: "devstral-small-latest", Label: "Devstral Small 2 (coding)", InputPer1k: 0.0001, OutputPer1k: 0.0003, ContextWindow: 256000},
			{ID: "codestral-2508", Label: "Codestral 2508", InputPer1k: 0.0003, OutputPer1k: 0.0009, ContextWindow: 256000},
			{ID: "codestral-latest", Label: "Codestral (legacy 2405)", InputPer1k: 0.001, OutputPer1k: 0.003, ContextWindow: 32000},
			{ID: "ministral-3-14b-2512", Label: "Ministral 3 14B", InputPer1k: 0.0002, OutputPer1k: 0.0002, ContextWindow: 262144},
			{ID: "ministral-8b-latest", Label: "Ministral 8B", InputPer1k: 0.00015, OutputPer1k: 0.00015, ContextWindow: 262144},
			{ID: "ministral-3-3b-2512", Label: "Ministral 3 3B", InputPer1k: 0.0001, OutputPer1k: 0.0001, ContextWindow: 131072},
			{ID: "mistral-embed", Label: "Mistral Embed", InputPer1k: 0.0001, OutputPer1k: 0, ContextWindow: 8192},
		},
	},
	{
		ID:                 "litellm_proxy",
		Kind:               KindGateway,
		Name:               "LiteLLM Proxy",
		Description:        "Bring your own LiteLLM proxy with NetBird identity stamped on every request",
		DefaultHost:        "",
		AuthHeaderName:     "Authorization",
		AuthHeaderTemplate: "Bearer ${API_KEY}",
		DefaultContentType: "application/json",
		BrandColor:         "#0EA5E9",
		ParserID:           "openai",
		// IdentityInjection requires a LiteLLM virtual key minted with
		// metadata.allow_client_tags=true; the master key silently drops
		// caller tags. Tags go out via both the x-litellm-tags header and
		// body metadata.tags: LiteLLM enforces budgets from the body only,
		// so the header is the spend-tracking fallback when body injection
		// can't run. See the Agent Network provider docs for key setup.
		IdentityInjection: &IdentityInjection{
			HeaderPair: &HeaderPairInjection{
				EndUserIDHeader: "x-litellm-end-user-id",
				TagsHeader:      "x-litellm-tags",
				TagsInBody:      true,
				EndUserIDInBody: true,
			},
		},
		Models: []Model{},
	},
	{
		ID:          "portkey",
		Kind:        KindGateway,
		Name:        "Portkey AI Gateway",
		Description: "Portkey AI Gateway with NetBird identity stamped via x-portkey-metadata",
		DefaultHost: "api.portkey.ai",
		// Portkey hosted requires x-portkey-api-key (account key)
		// plus a routing decision per request. The simplest routing
		// path is a saved Portkey config id stamped via
		// x-portkey-config — operators paste the pc-... id once and
		// Portkey resolves the upstream provider + virtual key from
		// it. ExtraHeaders below surfaces the input. Alternative:
		// callers author "@org/model" in the body; both flows
		// coexist (per-request authoring still works without a
		// configured value).
		AuthHeaderName:     "x-portkey-api-key",
		AuthHeaderTemplate: "${API_KEY}",
		DefaultContentType: "application/json",
		BrandColor:         "#FF5C00",
		ParserID:           "openai",
		IdentityInjection: &IdentityInjection{
			JSONMetadata: &JSONMetadataInjection{
				Header:         "x-portkey-metadata",
				UserKey:        "_user",
				GroupsKey:      "groups",
				MaxValueLength: 128,
			},
		},
		ExtraHeaders: []ExtraHeader{
			{Name: "x-portkey-config"},
		},
		Models: []Model{},
	},
	{
		ID:                 "bifrost",
		Kind:               KindGateway,
		Name:               "Bifrost",
		Description:        "Maxim AI's Bifrost gateway. Point upstream URL at /openai/v1 or /anthropic/v1 on your Bifrost host depending on which body shape your apps use.",
		DefaultHost:        "",
		AuthHeaderName:     "Authorization",
		AuthHeaderTemplate: "Bearer ${API_KEY}",
		DefaultContentType: "application/json",
		BrandColor:         "#7C3AED",
		// ParserID empty: the proxy's request parser sniffs the URL
		// path. Bifrost's /openai/v1/... contains "/v1/chat/completions"
		// (matches OpenAIParser.DetectFromURL); /anthropic/v1/messages
		// contains "/v1/messages" (matches AnthropicParser). Operators
		// who paste a different prefix get no usage parsing and the
		// cost meter skips with skipMissingProvider — degraded but
		// non-fatal.
		ParserID: "",
		// Identity-injection headers are operator-customisable. The
		// HeaderPair values below are PLACEHOLDERS surfaced by the
		// dashboard; the actual values stamped on the wire come from
		// the provider record's IdentityHeaderUserID /
		// IdentityHeaderGroups fields. An empty operator value
		// disables stamping for that dimension (the inject middleware
		// already no-ops on empty header names). Defaulting to the
		// x-bf-dim- family so the values land in Bifrost's
		// Prometheus/OTEL pipelines when the operator declares the
		// label names in their client.prometheus_labels config — see
		// docs.getbifrost.ai/features/telemetry. Operators who use
		// the always-on x-bf-lh- log-metadata family (no Bifrost-side
		// declaration required) just edit the inputs.
		//
		// Bifrost virtual keys (sk-bf-*) ride Authorization: Bearer.
		// Operators provision the VK on their Bifrost (UI /
		// config.json / POST /api/governance/virtual-keys) and paste
		// the returned sk-bf-... as ${API_KEY}. Pin v1.4+ to avoid
		// the v1.3.0 x-bf-vk regression (maximhq/bifrost#632).
		IdentityInjection: &IdentityInjection{
			HeaderPair: &HeaderPairInjection{
				EndUserIDHeader: "x-bf-dim-netbird_user_id",
				TagsHeader:      "x-bf-dim-netbird_groups",
				Customizable:    true,
			},
		},
		Models: []Model{},
	},
	{
		ID:                 "cloudflare_ai_gateway",
		Kind:               KindGateway,
		Name:               "Cloudflare AI Gateway",
		Description:        "Cloudflare AI Gateway. Operator pastes the gateway URL (with the upstream provider slug like /openai or /anthropic so the URL sniffer dispatches to the right parser) and a per-gateway authentication token. Recommended setup is BYOK / Stored Keys: Cloudflare manages the upstream provider credential and the gateway token is the only secret NetBird needs.",
		DefaultHost:        "",
		AuthHeaderName:     "cf-aig-authorization",
		AuthHeaderTemplate: "Bearer ${API_KEY}",
		DefaultContentType: "application/json",
		BrandColor:         "#F38020",
		// ParserID empty: like Bifrost, the proxy's parser-detect
		// sniffs the URL path. /openai/... contains the OpenAI hint
		// substrings; /anthropic/v1/messages contains /v1/messages
		// (matches AnthropicParser). The /compat universal endpoint
		// also speaks OpenAI shape so OpenAIParser handles it.
		// Operators who paste a different prefix degrade to no-cost
		// (skipMissingProvider) but the request still flows.
		ParserID: "",
		// cf-aig-metadata is a single header carrying a JSON object;
		// up to five string/number/boolean values per request. NetBird
		// occupies two slots (user id + groups CSV) and leaves three
		// for operator-added context. JSON keys are operator-
		// customisable so Cloudflare-side log filters can use the
		// operator's existing label conventions instead of NetBird's
		// defaults — hence Customizable=true. The dashboard surfaces
		// the catalog values as placeholders; only the values stored
		// on the provider record's IdentityHeader* fields land on the
		// wire (empty operator value = key is omitted from the JSON,
		// since applyJSONMetadata already skips empty keys).
		IdentityInjection: &IdentityInjection{
			JSONMetadata: &JSONMetadataInjection{
				Header:       "cf-aig-metadata",
				UserKey:      "netbird_user_id",
				GroupsKey:    "netbird_groups",
				Customizable: true,
				// Cloudflare's docs don't specify a per-value cap;
				// leaving 0 disables the truncate path. Header-level
				// constraint is "5 entries max" rather than length.
				MaxValueLength: 0,
			},
		},
		Models: []Model{},
	},
	{
		ID:                 "vercel_ai_gateway",
		Kind:               KindGateway,
		Name:               "Vercel AI Gateway",
		Description:        "Vercel's unified API for hundreds of models. Single endpoint, OpenAI-compatible body, model dispatch via prefix (openai/..., anthropic/..., google/..., xai/...). Per-user / per-tag attribution lands in Vercel's Custom Reporting API and observability dashboard.",
		DefaultHost:        "",
		AuthHeaderName:     "Authorization",
		AuthHeaderTemplate: "Bearer ${API_KEY}",
		DefaultContentType: "application/json",
		BrandColor:         "#000000",
		// Vercel always speaks OpenAI shape on /v1/chat/completions —
		// the model prefix in the body picks the upstream provider.
		// No URL sniffing needed; pin the parser directly.
		ParserID: "openai",
		// HeaderPair shape with fixed wire names dictated by Vercel's
		// Custom Reporting API contract. Customizable=false because
		// renaming the headers makes Vercel silently stop attributing
		// — the gateway's reporting endpoint only matches its own
		// header names. Same fixed-protocol position as LiteLLM.
		//
		// Caveats operators should know:
		//   - up to 10 tags total per request (deduped); 11+ → HTTP 400
		//   - each tag must be 1-64 chars
		//   - user up to 256 chars (NetBird user emails fit)
		//   - $0.075 per 1k unique user/tag values written
		// We don't enforce the caps in the inject middleware today;
		// operators in groups beyond the 10-tag limit will see Vercel
		// 400s and need to re-scope their group memberships.
		IdentityInjection: &IdentityInjection{
			HeaderPair: &HeaderPairInjection{
				EndUserIDHeader: "ai-reporting-user",
				TagsHeader:      "ai-reporting-tags",
			},
		},
		Models: []Model{},
	},
	{
		ID:                 "openrouter",
		Kind:               KindGateway,
		Name:               "OpenRouter",
		Description:        "OpenRouter's unified API for hundreds of models. Single endpoint at openrouter.ai/api/v1, OpenAI-compatible body, model dispatch via prefix (anthropic/claude-..., openai/gpt-..., google/gemini-..., etc.). Per-user attribution lands in OpenRouter's analytics via the OpenAI-standard `user` body field; OpenRouter has no groups / tags dimension at request time.",
		DefaultHost:        "openrouter.ai/api/v1",
		AuthHeaderName:     "Authorization",
		AuthHeaderTemplate: "Bearer ${API_KEY}",
		DefaultContentType: "application/json",
		BrandColor:         "#6F4FF2",
		// OpenRouter is single-endpoint OpenAI-shape on /api/v1/chat/completions —
		// model prefix in the body picks the upstream provider.
		// Pinning the parser saves URL sniffing.
		ParserID: "openai",
		// HeaderPair shape with EndUserIDInBody as the only active
		// dimension. OpenRouter's per-user attribution is the
		// OpenAI-standard `user` body field, not a header — and
		// OpenRouter offers no per-request groups / tags dimension at
		// all. Customizable=false because the field name is locked by
		// OpenAI's spec; renaming would just defeat the inject.
		IdentityInjection: &IdentityInjection{
			HeaderPair: &HeaderPairInjection{
				EndUserIDInBody: true,
			},
		},
		// HTTP-Referer + X-OpenRouter-Title surface in OpenRouter's
		// app rankings and per-app analytics. Operators paste their
		// own app URL + display name on the provider record so their
		// requests show under their brand instead of "no app". Both
		// are static per-deployment, not per-request, hence the
		// ExtraHeaders mechanism (operator-typed value, stamped on
		// every request to this provider). Skip X-OpenRouter-Categories
		// for now — the marketplace-categories dimension is
		// niche-enough that we'd add it on demand.
		ExtraHeaders: []ExtraHeader{
			{Name: "HTTP-Referer"},
			{Name: "X-OpenRouter-Title"},
		},
		Models: []Model{},
	},
	{
		// vLLM is an OpenAI-compatible self-hosted server. It behaves like
		// the generic custom entry; it gets its own catalog id purely so it
		// surfaces as a named "vLLM" choice in the provider picker.
		ID:                 "vllm",
		Kind:               KindCustom,
		Name:               "vLLM",
		Description:        "Self-hosted vLLM (OpenAI-compatible)",
		DefaultHost:        "",
		AuthHeaderName:     "Authorization",
		AuthHeaderTemplate: "Bearer ${API_KEY}",
		DefaultContentType: "application/json",
		BrandColor:         "#30A2FF",
		Models:             []Model{},
	},
	{
		ID:                 "custom",
		Kind:               KindCustom,
		Name:               "Custom / Self-hosted",
		Description:        "OpenAI-compatible endpoint (vLLM, Ollama, …)",
		DefaultHost:        "",
		AuthHeaderName:     "Authorization",
		AuthHeaderTemplate: "Bearer ${API_KEY}",
		DefaultContentType: "application/json",
		BrandColor:         "#9CA3AF",
		Models:             []Model{},
	},
}

// All returns a copy of the full catalog.
func All() []Provider {
	out := make([]Provider, len(providers))
	copy(out, providers)
	return out
}

// Lookup returns the catalog entry with the given id, if any.
func Lookup(id string) (Provider, bool) {
	for _, p := range providers {
		if p.ID == id {
			return p, true
		}
	}
	return Provider{}, false
}

// IsKnown reports whether the given id refers to a catalog entry.
func IsKnown(id string) bool {
	_, ok := Lookup(id)
	return ok
}

// IsVertexPathStyle reports whether a provider uses the Google Vertex AI
// request shape — the model is carried in the URL path
// (/v1/projects/{p}/locations/{r}/publishers/{pub}/models/{model}:{action})
// rather than the body, so the proxy routes it by path instead of by model.
func IsVertexPathStyle(providerID string) bool {
	return providerID == "vertex_ai_api"
}

// IsBedrockPathStyle reports whether a provider uses the AWS Bedrock request
// shape — the model is carried in the URL path (/model/{modelId}/{action},
// action being invoke, invoke-with-response-stream, converse, or
// converse-stream) rather than the body, so the proxy routes it by path.
func IsBedrockPathStyle(providerID string) bool {
	return providerID == "bedrock_api"
}

// ToAPIResponse renders a catalog provider as the API representation.
func (p Provider) ToAPIResponse() api.AgentNetworkCatalogProvider {
	models := make([]api.AgentNetworkCatalogModel, 0, len(p.Models))
	for _, m := range p.Models {
		models = append(models, api.AgentNetworkCatalogModel{
			Id:            m.ID,
			Label:         m.Label,
			InputPer1k:    m.InputPer1k,
			OutputPer1k:   m.OutputPer1k,
			ContextWindow: m.ContextWindow,
		})
	}
	kind := api.AgentNetworkCatalogProviderKindProvider
	switch p.Kind {
	case KindGateway:
		kind = api.AgentNetworkCatalogProviderKindGateway
	case KindCustom:
		kind = api.AgentNetworkCatalogProviderKindCustom
	}
	resp := api.AgentNetworkCatalogProvider{
		Id:                 p.ID,
		Name:               p.Name,
		Description:        p.Description,
		DefaultHost:        p.DefaultHost,
		Kind:               kind,
		AuthHeaderTemplate: p.AuthHeaderTemplate,
		DefaultContentType: p.DefaultContentType,
		BrandColor:         p.BrandColor,
		Models:             models,
	}
	if len(p.ExtraHeaders) > 0 {
		extras := make([]api.AgentNetworkCatalogExtraHeader, 0, len(p.ExtraHeaders))
		for _, h := range p.ExtraHeaders {
			extras = append(extras, api.AgentNetworkCatalogExtraHeader{
				Name: h.Name,
			})
		}
		resp.ExtraHeaders = &extras
	}
	// Surface IdentityInjection so the dashboard can decide whether
	// to render editable inputs vs. a read-only mappings strip per
	// shape's customizable flag. HeaderPair (Bifrost) and
	// JSONMetadata (Cloudflare, Portkey) are mutually exclusive on a
	// given catalog entry; emit whichever shape is set.
	if p.IdentityInjection != nil {
		injection := &api.AgentNetworkCatalogIdentityInjection{}
		if hp := p.IdentityInjection.HeaderPair; hp != nil {
			injection.HeaderPair = &api.AgentNetworkCatalogHeaderPairInjection{
				Customizable:    hp.Customizable,
				EndUserIdHeader: hp.EndUserIDHeader,
				TagsHeader:      hp.TagsHeader,
			}
		}
		if jm := p.IdentityInjection.JSONMetadata; jm != nil {
			injection.JsonMetadata = &api.AgentNetworkCatalogJSONMetadataInjection{
				Customizable: jm.Customizable,
				Header:       jm.Header,
				UserKey:      jm.UserKey,
				GroupsKey:    jm.GroupsKey,
			}
		}
		if injection.HeaderPair != nil || injection.JsonMetadata != nil {
			resp.IdentityInjection = injection
		}
	}
	return resp
}
