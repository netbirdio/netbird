// Package llm provides the shared LLM request and response parsing
// library consumed by proxy middleware. It is runtime agnostic: the same
// package is used by the native built-in executor now and will be reused
// by the WASM adapter later.
package llm

// Provider identifies an LLM API provider.
type Provider int

const (
	// ProviderUnknown signals that no parser matched the request.
	ProviderUnknown Provider = 0
	// ProviderOpenAI identifies the OpenAI API surface.
	ProviderOpenAI Provider = 1
	// ProviderAnthropic identifies the Anthropic Messages API surface.
	ProviderAnthropic Provider = 2
	// ProviderBedrock identifies the AWS Bedrock runtime surface.
	ProviderBedrock Provider = 3
)

// RequestFacts captures the subset of the LLM request body that the
// middleware annotates as metadata (model, streaming flag). Additional
// fields are added as parsers grow.
type RequestFacts struct {
	Model  string
	Stream bool
}

// Usage is the provider-agnostic token accounting emitted to metrics and
// access logs. Downstream consumers map InputTokens/OutputTokens to the
// plg.llm.* metadata allowlist entries.
//
// CachedInputTokens carries OpenAI's prompt_tokens_details.cached_tokens
// (a SUBSET of InputTokens) when the response is from OpenAI, or
// Anthropic's cache_read_input_tokens (ADDITIVE to InputTokens) when from
// Anthropic. The cost meter switches formula on KeyLLMProvider so the
// two shapes are billed correctly without double-counting.
//
// CacheCreationTokens carries Anthropic's cache_creation_input_tokens
// (ADDITIVE; not present in the OpenAI shape).
type Usage struct {
	InputTokens         int64
	OutputTokens        int64
	TotalTokens         int64
	CachedInputTokens   int64
	CacheCreationTokens int64
}

// Parser is the per-provider interface implemented in this package. The
// dispatcher selects a parser by calling DetectFromURL against the incoming
// request path; ties break by registration order (see Parsers).
type Parser interface {
	Provider() Provider
	ProviderName() string
	DetectFromURL(path string) bool
	ParseRequest(body []byte) (RequestFacts, error)
	ParseResponse(status int, contentType string, body []byte) (Usage, error)
	// ExtractPrompt returns the user-facing prompt text from a request body.
	// Different endpoint shapes (chat.completions, responses, messages) are
	// handled by the per-provider implementation. Returns "" when no prompt
	// can be extracted; never returns an error — extraction is best-effort
	// because callers use the result for observability, not authorization.
	ExtractPrompt(body []byte) string
	// ExtractCompletion returns the assistant-facing completion text from a
	// non-streaming response body. status and contentType match the
	// ParseResponse arguments so implementations can fast-fail uniformly.
	ExtractCompletion(status int, contentType string, body []byte) string
	// ExtractSessionID returns a stable identifier that groups requests of
	// the same conversation / coding session, read from the per-provider
	// location clients populate (e.g. OpenAI Codex's client_metadata.session_id,
	// Claude Code's metadata.user_id). Returns "" when the body carries no
	// recognised session marker; extraction is best-effort and never errors.
	ExtractSessionID(body []byte) string
}

// Parsers returns the built-in parser set in a stable order. The order is
// deterministic so that DetectFromURL ties produce consistent routing.
func Parsers() []Parser {
	return []Parser{
		OpenAIParser{},
		AnthropicParser{},
		BedrockParser{},
	}
}

// DetectParser returns the first parser whose DetectFromURL matches the given
// request path. ok=false means no parser claimed the path.
func DetectParser(path string) (Parser, bool) {
	for _, p := range Parsers() {
		if p.DetectFromURL(path) {
			return p, true
		}
	}
	return nil, false
}

// ParserByName returns the parser whose ProviderName matches id. Used by
// callers that already know which provider surface a request will hit
// (e.g. the agent-network middleware chain configured per synthesised
// service) so they can skip URL sniffing. ok=false when no parser is
// registered under that name.
func ParserByName(id string) (Parser, bool) {
	if id == "" {
		return nil, false
	}
	for _, p := range Parsers() {
		if p.ProviderName() == id {
			return p, true
		}
	}
	return nil, false
}
