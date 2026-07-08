package llm

import (
	"encoding/json"
	"fmt"
	"strings"
)

// OpenAIParser implements the Parser interface for OpenAI-compatible APIs.
// It recognizes chat.completions, completions, embeddings, and the newer
// responses endpoint; any proxy path-prefix stripping is tolerated by the
// substring match in DetectFromURL.
type OpenAIParser struct{}

// openAIPathHints are substring patterns that mark a request as
// OpenAI-shaped. The bare `/chat/completions` is listed alongside
// `/v1/chat/completions` because gateways like Cloudflare AI
// Gateway place their own version segment before the provider
// slug (gateway/v1/{account}/{gateway}/openai/chat/completions) —
// the canonical `/v1/` ends up nowhere near `/chat/completions`,
// so the `/v1/chat/completions` hint misses. `/chat/completions`
// is OpenAI's API contract: any service accepting OpenAI bodies
// serves at this path, so false-positive risk is negligible.
// `/completions` (legacy), `/embeddings`, and `/responses` are
// kept on the canonical-only path because their bare forms are
// too generic to be safe substrings.
var openAIPathHints = []string{
	"/v1/chat/completions",
	"/v1/completions",
	"/v1/embeddings",
	"/v1/responses",
	"/chat/completions",
}

// Provider returns ProviderOpenAI.
func (OpenAIParser) Provider() Provider { return ProviderOpenAI }

// ProviderName returns the stable label used for metrics and metadata.
func (OpenAIParser) ProviderName() string { return "openai" }

// DetectFromURL reports whether the given request path looks like an OpenAI
// API endpoint. The match is case-insensitive and substring-based so that a
// reverse proxy prefix strip or rewrite does not defeat detection.
func (OpenAIParser) DetectFromURL(path string) bool {
	lower := strings.ToLower(path)
	for _, hint := range openAIPathHints {
		if strings.Contains(lower, hint) {
			return true
		}
	}
	return false
}

type openAIRequest struct {
	Model         string `json:"model"`
	Stream        *bool  `json:"stream"`
	StreamOptions *struct {
		IncludeUsage *bool `json:"include_usage"`
	} `json:"stream_options"`
	// Chat Completions / Completions: messages[].content (string or array of
	// content parts). Responses API: input is either a string or an array of
	// items with content parts. We use json.RawMessage to defer parsing each
	// shape independently.
	Messages []openAIMessage `json:"messages"`
	Prompt   json.RawMessage `json:"prompt"`
	Input    json.RawMessage `json:"input"`
}

type openAIMessage struct {
	Role    string          `json:"role"`
	Content json.RawMessage `json:"content"`
}

// ParseRequest extracts the model name and streaming flag from an OpenAI
// request body. Unknown or missing fields leave the corresponding struct
// members zero-valued.
func (OpenAIParser) ParseRequest(body []byte) (RequestFacts, error) {
	var req openAIRequest
	if err := json.Unmarshal(body, &req); err != nil {
		return RequestFacts{}, fmt.Errorf("decode openai request: %w: %v", ErrMalformedRequest, err)
	}
	return RequestFacts{
		Model:  req.Model,
		Stream: ptrDeref(req.Stream),
	}, nil
}

// openAIResponse accepts both naming conventions in a single struct because
// OpenAI's older Chat Completions API uses prompt_tokens/completion_tokens
// while the newer Responses API (/v1/responses) uses input_tokens/output_tokens
// (aligned with Anthropic). Pointer fields let us tell "absent" from "zero".
//
// PromptTokensDetails.CachedTokens (Chat Completions) and
// InputTokensDetails.CachedTokens (Responses API) carry the SUBSET of
// prompt/input tokens that hit the prompt cache. Cost-meter applies the
// discount rate to that subset and the regular rate to the remainder so
// we never double-bill the cached portion.
type openAIResponse struct {
	Usage struct {
		PromptTokens        *int64 `json:"prompt_tokens"`
		CompletionTokens    *int64 `json:"completion_tokens"`
		InputTokens         *int64 `json:"input_tokens"`
		OutputTokens        *int64 `json:"output_tokens"`
		TotalTokens         *int64 `json:"total_tokens"`
		PromptTokensDetails *struct {
			CachedTokens *int64 `json:"cached_tokens"`
		} `json:"prompt_tokens_details"`
		InputTokensDetails *struct {
			CachedTokens *int64 `json:"cached_tokens"`
		} `json:"input_tokens_details"`
	} `json:"usage"`
}

// ParseResponse decodes the non-streaming OpenAI response envelope. Status
// codes other than 200 are treated as non-LLM responses so the caller can
// skip cost accounting without aborting the request.
func (OpenAIParser) ParseResponse(status int, contentType string, body []byte) (Usage, error) {
	if status != 200 {
		return Usage{}, fmt.Errorf("openai status %d: %w", status, ErrNotLLMResponse)
	}
	if isEventStream(contentType) {
		return Usage{}, ErrStreamingUnsupported
	}
	if !isJSON(contentType) {
		return Usage{}, fmt.Errorf("openai content-type %q: %w", contentType, ErrNotLLMResponse)
	}

	var resp openAIResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return Usage{}, fmt.Errorf("decode openai response: %w: %v", ErrMalformedResponse, err)
	}

	// Responses-API names take precedence when present; fall back to the older
	// Chat Completions names. This handles both endpoints transparently
	// without forcing a per-route configuration.
	u := Usage{
		InputTokens:       pickInt64(resp.Usage.InputTokens, resp.Usage.PromptTokens),
		OutputTokens:      pickInt64(resp.Usage.OutputTokens, resp.Usage.CompletionTokens),
		TotalTokens:       derefInt64(resp.Usage.TotalTokens),
		CachedInputTokens: openAICachedTokens(resp),
	}
	if u.TotalTokens == 0 && (u.InputTokens > 0 || u.OutputTokens > 0) {
		u.TotalTokens = u.InputTokens + u.OutputTokens
	}
	return u, nil
}

// openAICachedTokens returns the cached-prompt subset reported by
// either the Responses-API (input_tokens_details.cached_tokens) or
// the Chat-Completions API (prompt_tokens_details.cached_tokens).
// Responses-API takes precedence when both are populated.
func openAICachedTokens(resp openAIResponse) int64 {
	// Responses-API details are authoritative when present: an explicit
	// cached_tokens of 0 must be honored, not treated as missing and
	// overridden by the Chat-Completions field (which would overstate cache).
	if resp.Usage.InputTokensDetails != nil && resp.Usage.InputTokensDetails.CachedTokens != nil {
		return derefInt64(resp.Usage.InputTokensDetails.CachedTokens)
	}
	if resp.Usage.PromptTokensDetails != nil {
		return derefInt64(resp.Usage.PromptTokensDetails.CachedTokens)
	}
	return 0
}

// ExtractPrompt returns the user-visible prompt text from an OpenAI request.
// Handles chat.completions (messages[].content), legacy completions (prompt
// string), and the Responses API (input as string or content-part array).
// Returns "" when nothing extractable is found.
func (OpenAIParser) ExtractPrompt(body []byte) string {
	var req openAIRequest
	if err := json.Unmarshal(body, &req); err != nil {
		return ""
	}
	if len(req.Messages) > 0 {
		return joinMessages(req.Messages)
	}
	if len(req.Input) > 0 {
		return extractResponsesInput(req.Input)
	}
	if len(req.Prompt) > 0 {
		return decodeStringOrJoin(req.Prompt)
	}
	return ""
}

// extractResponsesInput handles the Responses API `input` field. It is one
// of three shapes: a plain string, an array of message items
// ({role, content: string | [parts]}) as sent by Codex and the Responses
// SDK, or a flat array of content parts ({type, text/input_text}). Message
// items are flattened to "role: text" lines; items without extractable text
// (reasoning blocks, tool calls) are skipped.
func extractResponsesInput(raw json.RawMessage) string {
	if s, ok := tryDecodeString(raw); ok {
		return s
	}
	var items []struct {
		Role      string          `json:"role"`
		Content   json.RawMessage `json:"content"`
		Text      string          `json:"text"`
		InputText string          `json:"input_text"`
	}
	if err := json.Unmarshal(raw, &items); err != nil {
		return extractContentParts(raw)
	}
	var b strings.Builder
	for _, it := range items {
		var text string
		switch {
		case len(it.Content) > 0:
			text = decodeStringOrJoin(it.Content)
		case it.Text != "":
			text = it.Text
		case it.InputText != "":
			text = it.InputText
		}
		if text == "" {
			continue
		}
		if b.Len() > 0 {
			b.WriteByte('\n')
		}
		if it.Role != "" {
			b.WriteString(it.Role)
			b.WriteString(": ")
		}
		b.WriteString(text)
	}
	return b.String()
}

// ExtractSessionID reads the OpenAI session marker. Codex (the Responses
// API client) stamps client_metadata.session_id on every request body;
// plain chat.completions traffic carries no session id and yields "".
func (OpenAIParser) ExtractSessionID(body []byte) string {
	var req struct {
		ClientMetadata struct {
			SessionID string `json:"session_id"`
		} `json:"client_metadata"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		return ""
	}
	return req.ClientMetadata.SessionID
}

type openAIChatChoice struct {
	Message struct {
		Role    string          `json:"role"`
		Content json.RawMessage `json:"content"`
	} `json:"message"`
	Text string `json:"text"`
}

type openAIChatResponse struct {
	Choices []openAIChatChoice `json:"choices"`
	// Responses API: output[].content[].text
	Output []struct {
		Type    string          `json:"type"`
		Content json.RawMessage `json:"content"`
		Text    string          `json:"text"`
	} `json:"output"`
	OutputText string `json:"output_text"`
}

// ExtractCompletion returns the assistant text from a non-streaming OpenAI
// response. Handles chat.completions (choices[].message.content), legacy
// completions (choices[].text), and Responses API (output[].content[].text
// or the convenience output_text field).
func (OpenAIParser) ExtractCompletion(status int, contentType string, body []byte) string {
	if status != 200 || isEventStream(contentType) || !isJSON(contentType) {
		return ""
	}
	var resp openAIChatResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return ""
	}
	if resp.OutputText != "" {
		return resp.OutputText
	}
	for _, c := range resp.Choices {
		if len(c.Message.Content) > 0 {
			if s := decodeStringOrJoin(c.Message.Content); s != "" {
				return s
			}
		}
		if c.Text != "" {
			return c.Text
		}
	}
	for _, o := range resp.Output {
		if o.Text != "" {
			return o.Text
		}
		if len(o.Content) > 0 {
			if s := extractContentParts(o.Content); s != "" {
				return s
			}
		}
	}
	return ""
}

// joinMessages flattens a chat.completions messages array into a single
// "role: content" string per message, separated by newlines. Roles surface
// system/user/assistant context which is useful for log review.
func joinMessages(msgs []openAIMessage) string {
	var b strings.Builder
	for i, m := range msgs {
		if i > 0 {
			b.WriteByte('\n')
		}
		if m.Role != "" {
			b.WriteString(m.Role)
			b.WriteString(": ")
		}
		b.WriteString(decodeStringOrJoin(m.Content))
	}
	return b.String()
}

// extractContentParts handles the Responses-API content shape, which is
// either a single string or an array of {type, text} parts. text and
// input_text both carry user-facing content.
func extractContentParts(raw json.RawMessage) string {
	if s, ok := tryDecodeString(raw); ok {
		return s
	}
	var parts []struct {
		Type      string `json:"type"`
		Text      string `json:"text"`
		InputText string `json:"input_text"`
	}
	if err := json.Unmarshal(raw, &parts); err != nil {
		// Last-ditch: array of strings.
		var arr []string
		if json.Unmarshal(raw, &arr) == nil {
			return strings.Join(arr, "\n")
		}
		return ""
	}
	var b strings.Builder
	for _, p := range parts {
		var text string
		switch {
		case p.Text != "":
			text = p.Text
		case p.InputText != "":
			text = p.InputText
		}
		if text == "" {
			continue
		}
		if b.Len() > 0 {
			b.WriteByte('\n')
		}
		b.WriteString(text)
	}
	return b.String()
}

// decodeStringOrJoin accepts either a JSON string or a content-parts array
// (chat.completions multimodal) and returns a flat string. Multimodal parts
// are separated by newlines; non-text parts are skipped.
func decodeStringOrJoin(raw json.RawMessage) string {
	if s, ok := tryDecodeString(raw); ok {
		return s
	}
	return extractContentParts(raw)
}

func tryDecodeString(raw json.RawMessage) (string, bool) {
	if len(raw) == 0 {
		return "", false
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return s, true
	}
	return "", false
}

// pickInt64 returns the first non-nil pointer's value. Used to prefer one
// naming convention while transparently falling back to another.
func pickInt64(preferred, fallback *int64) int64 {
	if preferred != nil {
		return *preferred
	}
	return derefInt64(fallback)
}

func derefInt64(v *int64) int64 {
	if v == nil {
		return 0
	}
	return *v
}

func ptrDeref(b *bool) bool {
	if b == nil {
		return false
	}
	return *b
}

func isEventStream(contentType string) bool {
	return strings.Contains(strings.ToLower(contentType), "text/event-stream")
}

func isJSON(contentType string) bool {
	lower := strings.ToLower(contentType)
	return strings.Contains(lower, "application/json") || strings.Contains(lower, "+json")
}
