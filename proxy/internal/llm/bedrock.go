package llm

import (
	"encoding/json"
	"fmt"
	"strings"
)

// ProviderNameBedrock is the stable label for the AWS Bedrock parser, used as
// the llm.provider metadata value and the cost-meter formula selector.
const ProviderNameBedrock = "bedrock"

// BedrockParser implements the Parser interface for the AWS Bedrock runtime.
// Bedrock carries the model in the URL path (/model/{id}/{action}); the request
// middleware extracts it there, so this parser focuses on the response shapes:
// the vendor-native InvokeModel body (e.g. Anthropic's snake_case usage) and the
// unified Converse body (camelCase usage).
type BedrockParser struct{}

var bedrockPathHints = []string{"/invoke", "/converse"}

// Provider returns ProviderBedrock.
func (BedrockParser) Provider() Provider { return ProviderBedrock }

// ProviderName returns the stable label used for metrics and metadata.
func (BedrockParser) ProviderName() string { return ProviderNameBedrock }

// DetectFromURL reports whether the path is a Bedrock runtime model endpoint.
func (BedrockParser) DetectFromURL(path string) bool {
	lower := strings.ToLower(path)
	if !strings.HasPrefix(lower, "/model/") {
		return false
	}
	for _, hint := range bedrockPathHints {
		if strings.Contains(lower, hint) {
			return true
		}
	}
	return false
}

// ParseRequest is a no-op for Bedrock: the model lives in the URL path, not the
// body, and the streaming flag is derived from the path action. The request
// middleware handles both via parseBedrockPath, so this returns empty facts.
func (BedrockParser) ParseRequest([]byte) (RequestFacts, error) {
	return RequestFacts{}, nil
}

// bedrockResponse captures token usage from both Bedrock response shapes:
// InvokeModel (vendor-native; Anthropic uses snake_case + additive cache
// buckets) and Converse (camelCase, with a precomputed total).
type bedrockResponse struct {
	Usage struct {
		// InvokeModel (Anthropic-on-Bedrock) — snake_case.
		InputTokens              int64 `json:"input_tokens"`
		OutputTokens             int64 `json:"output_tokens"`
		CacheReadInputTokens     int64 `json:"cache_read_input_tokens"`
		CacheCreationInputTokens int64 `json:"cache_creation_input_tokens"`
		// Converse — camelCase.
		InputTokensCamel  int64 `json:"inputTokens"`
		OutputTokensCamel int64 `json:"outputTokens"`
		TotalTokensCamel  int64 `json:"totalTokens"`
	} `json:"usage"`
}

// ParseResponse decodes the non-streaming Bedrock response envelope, handling
// both the InvokeModel and Converse usage shapes. Non-200 / non-JSON bodies are
// treated as non-LLM responses so the caller skips cost accounting.
func (BedrockParser) ParseResponse(status int, contentType string, body []byte) (Usage, error) {
	if status != 200 {
		return Usage{}, fmt.Errorf("bedrock status %d: %w", status, ErrNotLLMResponse)
	}
	if isAWSEventStream(contentType) || isEventStream(contentType) {
		return Usage{}, ErrStreamingUnsupported
	}
	if !isJSON(contentType) {
		return Usage{}, fmt.Errorf("bedrock content-type %q: %w", contentType, ErrNotLLMResponse)
	}

	var resp bedrockResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return Usage{}, fmt.Errorf("decode bedrock response: %w: %v", ErrMalformedResponse, err)
	}
	inTok := firstNonZero(resp.Usage.InputTokens, resp.Usage.InputTokensCamel)
	outTok := firstNonZero(resp.Usage.OutputTokens, resp.Usage.OutputTokensCamel)
	total := resp.Usage.TotalTokensCamel
	if total == 0 {
		total = inTok + outTok + resp.Usage.CacheReadInputTokens + resp.Usage.CacheCreationInputTokens
	}
	return Usage{
		InputTokens:         inTok,
		OutputTokens:        outTok,
		TotalTokens:         total,
		CachedInputTokens:   resp.Usage.CacheReadInputTokens,
		CacheCreationTokens: resp.Usage.CacheCreationInputTokens,
	}, nil
}

// ExtractPrompt returns the user-visible prompt from a Bedrock request body,
// handling both the InvokeModel (Anthropic Messages: system + messages[]) and
// Converse (messages[].content[].text) shapes. Returns "" on decode failure.
func (BedrockParser) ExtractPrompt(body []byte) string {
	var req struct {
		System   json.RawMessage `json:"system"`
		Messages []struct {
			Role    string          `json:"role"`
			Content json.RawMessage `json:"content"`
		} `json:"messages"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		return ""
	}
	var b strings.Builder
	if s := decodeStringOrJoin(req.System); s != "" {
		b.WriteString("system: ")
		b.WriteString(s)
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
	return b.String()
}

// ExtractCompletion returns the assistant text from a non-streaming Bedrock
// response, handling InvokeModel (Anthropic content[].text) and Converse
// (output.message.content[].text).
func (BedrockParser) ExtractCompletion(status int, contentType string, body []byte) string {
	if status != 200 || isAWSEventStream(contentType) || !isJSON(contentType) {
		return ""
	}
	var resp struct {
		Content []struct {
			Text string `json:"text"`
		} `json:"content"`
		Output struct {
			Message struct {
				Content []struct {
					Text string `json:"text"`
				} `json:"content"`
			} `json:"message"`
		} `json:"output"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return ""
	}
	var b strings.Builder
	appendText := func(text string) {
		if text == "" {
			return
		}
		if b.Len() > 0 {
			b.WriteByte('\n')
		}
		b.WriteString(text)
	}
	for _, p := range resp.Content {
		appendText(p.Text)
	}
	for _, p := range resp.Output.Message.Content {
		appendText(p.Text)
	}
	return b.String()
}

// ExtractSessionID has no Bedrock-native marker; session grouping relies on the
// request headers handled by the middleware. Returns "".
func (BedrockParser) ExtractSessionID([]byte) string { return "" }

// firstNonZero returns a when non-zero, else b. Folds the snake_case and
// camelCase usage variants into a single value.
func firstNonZero(a, b int64) int64 {
	if a != 0 {
		return a
	}
	return b
}

// isAWSEventStream reports whether contentType is the AWS binary event-stream
// framing used by Bedrock's streaming endpoints.
func isAWSEventStream(contentType string) bool {
	return strings.Contains(strings.ToLower(contentType), "application/vnd.amazon.eventstream")
}
