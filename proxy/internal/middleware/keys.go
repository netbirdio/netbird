package middleware

// Metadata key namespace constants shared across the built-in
// middlewares. Each domain owns a prefix; middlewares declare their
// per-key allowlist drawn from these constants. Agents implementing
// the G2 middlewares import this file so the dashboard's expanded-row
// viewer and the access-log writer see a stable key surface.
//
// Key shape rules (enforced by the metadata accumulator):
//   - Lowercase ASCII letters, digits, dot, underscore, hyphen.
//   - At least one dot separating namespace from leaf.
//   - Max length: MaxMetadataKeyBytes.
const (
	// LLM request-side metadata (emitted by llm_request_parser).
	KeyLLMProvider         = "llm.provider"
	KeyLLMModel            = "llm.model"
	KeyLLMStream           = "llm.stream"
	KeyLLMRequestPromptRaw = "llm.request_prompt_raw"
	KeyLLMCaptureTruncated = "llm.capture_truncated"
	// KeyLLMSessionID groups requests of the same conversation / coding
	// session, read from the per-provider session marker in the request
	// body. Empty for clients that don't send one.
	KeyLLMSessionID = "llm.session_id"

	// LLM response-side metadata (emitted by llm_response_parser).
	//nolint:gosec // metadata key name, not a credential
	KeyLLMInputTokens = "llm.input_tokens"
	//nolint:gosec // metadata key name, not a credential
	KeyLLMOutputTokens = "llm.output_tokens"
	//nolint:gosec // metadata key name, not a credential
	KeyLLMTotalTokens = "llm.total_tokens"
	// LLM cached-input bucket. For OpenAI it's the SUBSET of input
	// tokens that hit the prompt cache (prompt_tokens_details.
	// cached_tokens) — billed at the cached_input_per_1k rate when
	// configured. For Anthropic it's cache_read_input_tokens, which
	// is ADDITIVE to llm.input_tokens — billed at cache_read_per_1k.
	// cost_meter switches formula on llm.provider.
	//nolint:gosec // metadata key name, not a credential
	KeyLLMCachedInputTokens = "llm.cached_input_tokens"
	// LLM cache-creation bucket (Anthropic only). ADDITIVE to
	// llm.input_tokens; billed at cache_creation_per_1k.
	//nolint:gosec // metadata key name, not a credential
	KeyLLMCacheCreationTokens = "llm.cache_creation_tokens"
	KeyLLMResponseCompletion  = "llm.response_completion"

	// Guardrail outcomes (emitted by llm_guardrail). The guardrail
	// also re-emits llm.request_prompt as a redacted variant of the
	// raw prompt and drops llm.request_prompt_raw from the bag.
	KeyLLMRequestPrompt  = "llm.request_prompt"
	KeyLLMPolicyDecision = "llm_policy.decision"
	KeyLLMPolicyReason   = "llm_policy.reason"

	// LLM router routing decision (emitted by llm_router). The router
	// stamps the resolved provider id so downstream middlewares and
	// the access-log emitter can attribute the request without
	// re-parsing the body.
	KeyLLMResolvedProviderID = "llm.resolved_provider_id"

	// LLM authorising groups for this request (emitted by llm_router
	// on the allow path). Carries the comma-separated intersection of
	// the caller's UserGroups with the resolved route's
	// AllowedGroupIDs — i.e. the groups that actually authorise this
	// specific request, NOT every group the peer happens to be in.
	// Identity-stamping middlewares use this for per-request tag
	// attribution so unrelated group memberships don't leak into
	// downstream gateways' spend logs.
	KeyLLMAuthorisingGroups = "llm.authorising_groups"

	// LLM policy attribution (emitted by llm_limit_check on the allow
	// path). Names the policy that paid for this request and the
	// dimension counters the post-flight llm_limit_record middleware
	// must tick. Empty when no applicable policy has any caps
	// configured (catch-all-allow attribution).
	KeyLLMSelectedPolicyID   = "llm.selected_policy_id"
	KeyLLMAttributionGroupID = "llm.attribution_group_id"
	KeyLLMAttributionWindowS = "llm.attribution_window_seconds"

	// Cost metering (emitted by cost_meter).
	KeyCostUSDTotal = "cost.usd_total"
	KeyCostSkipped  = "cost.skipped"

	// Framework-emitted error markers. Use the mw.<id>.* prefix to
	// distinguish framework-injected entries from middleware-emitted
	// metadata.
	KeyFrameworkErrorKindFmt = "mw.%s.error_kind"
)
