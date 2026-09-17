package llm

import "errors"

// Sentinel errors returned by parsers and the pricing loader. Callers use
// errors.Is to branch on a condition without coupling to parser internals.
var (
	// ErrUnknownProvider indicates no parser claimed the request path.
	ErrUnknownProvider = errors.New("llmobs: unknown provider")

	// ErrUnsupportedModel indicates the response parsed successfully but the
	// model is absent from the pricing table. Token counts are still valid.
	ErrUnsupportedModel = errors.New("llmobs: unsupported model")

	// ErrNotLLMResponse indicates the response is not a JSON success body
	// that a non-streaming parser can consume (non-200 or wrong content type).
	ErrNotLLMResponse = errors.New("llmobs: not an LLM response")

	// ErrStreamingUnsupported indicates the caller passed an SSE response to
	// a non-streaming parser. Streaming is handled separately via the SSE
	// scanner.
	ErrStreamingUnsupported = errors.New("llmobs: streaming response requires SSE scanner")

	// ErrMalformedResponse indicates the response body could not be decoded
	// as the provider-specific JSON schema.
	ErrMalformedResponse = errors.New("llmobs: malformed response body")

	// ErrMalformedRequest indicates the request body could not be decoded as
	// the provider-specific JSON schema.
	ErrMalformedRequest = errors.New("llmobs: malformed request body")
)
