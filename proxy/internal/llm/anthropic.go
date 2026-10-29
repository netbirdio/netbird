package llm

import (
	"encoding/json"
	"fmt"
	"strings"
)

// AnthropicParser implements the Parser interface for the Anthropic Messages
// and Completions APIs. Detection is substring-based to tolerate upstream
// path rewrites.
type AnthropicParser struct{}

var anthropicPathHints = []string{
	"/v1/messages",
	"/v1/complete",
}

// Provider returns ProviderAnthropic.
func (AnthropicParser) Provider() Provider { return ProviderAnthropic }

// ProviderName returns the stable label used for metrics and metadata.
func (AnthropicParser) ProviderName() string { return "anthropic" }

// DetectFromURL reports whether the given request path looks like an
// Anthropic API endpoint. The match is case-insensitive and substring-based.
func (AnthropicParser) DetectFromURL(path string) bool {
	lower := strings.ToLower(path)
	for _, hint := range anthropicPathHints {
		if strings.Contains(lower, hint) {
			return true
		}
	}
	return false
}

type anthropicRequest struct {
	Model    string             `json:"model"`
	Stream   *bool              `json:"stream"`
	System   json.RawMessage    `json:"system"`
	Messages []anthropicMessage `json:"messages"`
	// Legacy /v1/complete endpoint.
	Prompt string `json:"prompt"`
}

type anthropicMessage struct {
	Role    string          `json:"role"`
	Content json.RawMessage `json:"content"`
}

// ParseRequest extracts the model name and streaming flag from an Anthropic
// request body. Unknown or missing fields leave the corresponding struct
// members zero-valued.
func (AnthropicParser) ParseRequest(body []byte) (RequestFacts, error) {
	var req anthropicRequest
	if err := json.Unmarshal(body, &req); err != nil {
		return RequestFacts{}, fmt.Errorf("decode anthropic request: %w: %v", ErrMalformedRequest, err)
	}
	return RequestFacts{
		Model:  req.Model,
		Stream: ptrDeref(req.Stream),
	}, nil
}

type anthropicResponse struct {
	Usage struct {
		InputTokens  int64 `json:"input_tokens"`
		OutputTokens int64 `json:"output_tokens"`
		// CacheReadInputTokens and CacheCreationInputTokens are
		// ADDITIVE to InputTokens (not subset), each billed at its
		// own rate by the cost meter. cache_read is the cheaper
		// read-from-cache rate, cache_creation is the more
		// expensive write-to-cache rate.
		CacheReadInputTokens     int64 `json:"cache_read_input_tokens"`
		CacheCreationInputTokens int64 `json:"cache_creation_input_tokens"`
	} `json:"usage"`
}

// ParseResponse decodes the non-streaming Anthropic response envelope. Status
// codes other than 200 are treated as non-LLM responses so the caller can
// skip cost accounting without aborting the request.
func (AnthropicParser) ParseResponse(status int, contentType string, body []byte) (Usage, error) {
	if status != 200 {
		return Usage{}, fmt.Errorf("anthropic status %d: %w", status, ErrNotLLMResponse)
	}
	if isEventStream(contentType) {
		return Usage{}, ErrStreamingUnsupported
	}
	if !isJSON(contentType) {
		return Usage{}, fmt.Errorf("anthropic content-type %q: %w", contentType, ErrNotLLMResponse)
	}

	var resp anthropicResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return Usage{}, fmt.Errorf("decode anthropic response: %w: %v", ErrMalformedResponse, err)
	}
	return Usage{
		InputTokens:         resp.Usage.InputTokens,
		OutputTokens:        resp.Usage.OutputTokens,
		TotalTokens:         resp.Usage.InputTokens + resp.Usage.OutputTokens + resp.Usage.CacheReadInputTokens + resp.Usage.CacheCreationInputTokens,
		CachedInputTokens:   resp.Usage.CacheReadInputTokens,
		CacheCreationTokens: resp.Usage.CacheCreationInputTokens,
	}, nil
}

// ExtractPrompt returns the user-visible prompt text from an Anthropic
// request body. Handles the Messages API (system + messages[]) and the
// legacy /v1/complete prompt string. Returns "" on any decode failure.
func (AnthropicParser) ExtractPrompt(body []byte) string {
	var req anthropicRequest
	if err := json.Unmarshal(body, &req); err != nil {
		return ""
	}
	var b strings.Builder
	if len(req.System) > 0 {
		if s := decodeStringOrJoin(req.System); s != "" {
			b.WriteString("system: ")
			b.WriteString(s)
		}
	}
	for _, m := range req.Messages {
		if b.Len() > 0 {
			b.WriteByte('\n')
		}
		if m.Role != "" {
			b.WriteString(m.Role)
			b.WriteString(": ")
		}
		b.WriteString(decodeStringOrJoin(m.Content))
	}
	if b.Len() == 0 && req.Prompt != "" {
		b.WriteString(req.Prompt)
	}
	return b.String()
}

// ExtractSessionID is the body-side fallback for Anthropic. Claude Code's
// authoritative session marker is the X-Claude-Code-Session-Id request
// header (handled by the request-parser middleware); this only mines the
// optional metadata.user_id for an embedded "...session_<uuid>" marker.
// metadata.user_id on its own is a USER identifier, not a session, so the
// whole value is deliberately NOT used — returning it would mislabel every
// request from a user as one session. Returns "" when no session marker is
// present.
func (AnthropicParser) ExtractSessionID(body []byte) string {
	var req struct {
		Metadata struct {
			UserID string `json:"user_id"`
		} `json:"metadata"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		return ""
	}
	if idx := strings.LastIndex(req.Metadata.UserID, "session_"); idx >= 0 {
		if session := req.Metadata.UserID[idx+len("session_"):]; session != "" {
			return session
		}
	}
	return ""
}

type anthropicMessageResponse struct {
	Content []struct {
		Type string `json:"type"`
		Text string `json:"text"`
	} `json:"content"`
	// Legacy /v1/complete response.
	Completion string `json:"completion"`
}

// ExtractCompletion returns the assistant text from a non-streaming Anthropic
// Messages or Completions response. Returns "" when status/content-type
// indicate the body is not parseable or no text part is present.
func (AnthropicParser) ExtractCompletion(status int, contentType string, body []byte) string {
	if status != 200 || isEventStream(contentType) || !isJSON(contentType) {
		return ""
	}
	var resp anthropicMessageResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return ""
	}
	var b strings.Builder
	for _, part := range resp.Content {
		if part.Text == "" {
			continue
		}
		if b.Len() > 0 {
			b.WriteByte('\n')
		}
		b.WriteString(part.Text)
	}
	if b.Len() == 0 {
		return resp.Completion
	}
	return b.String()
}
