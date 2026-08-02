package llm_response_parser

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strings"

	"github.com/netbirdio/netbird/proxy/internal/llm"
)

// openAIDoneSentinel is the OpenAI end-of-stream marker. The scanner
// stops once this data frame is observed.
const openAIDoneSentinel = "[DONE]"

// accumulateStream walks the SSE byte slice, dispatches per provider,
// and returns the running token-usage and concatenated completion text.
// Errors from the scanner short-circuit accumulation but never panic
// — partial results are returned for truncated bodies.
func accumulateStream(provider string, body []byte) (llm.Usage, string) {
	switch provider {
	case "openai":
		return accumulateOpenAIStream(body)
	case "anthropic":
		return accumulateAnthropicStream(body)
	case llm.ProviderNameBedrock:
		return accumulateBedrockStream(body)
	default:
		return llm.Usage{}, ""
	}
}

// openAIStreamUsage is the usage block shared by both OpenAI streaming
// envelopes. Pointer fields tell "absent" from zero; the chat.completions
// (prompt_/completion_) and Responses-API (input_/output_) names are both
// accepted so a single decode covers either endpoint.
type openAIStreamUsage struct {
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
}

// openAIStreamChunk matches both OpenAI streaming envelopes. The
// chat.completions chunk carries text in choices[].delta.content and a
// trailing top-level usage block. The Responses API (/v1/responses) emits
// typed events instead: completion text rides response.output_text.delta
// (top-level "delta" string) and the final usage rides response.completed
// under response.usage. Only fields used for accumulation are declared.
type openAIStreamChunk struct {
	Choices []struct {
		Delta struct {
			Content string `json:"content"`
		} `json:"delta"`
	} `json:"choices"`
	Usage *openAIStreamUsage `json:"usage"`

	Type     string          `json:"type"`
	Delta    json.RawMessage `json:"delta"`
	Response *struct {
		Usage *openAIStreamUsage `json:"usage"`
	} `json:"response"`
}

// accumulateOpenAIStream sums per-chunk content deltas and lifts the usage
// block off the final frame, handling both the chat.completions and the
// Responses-API event shapes. Clients without stream_options.include_usage
// (chat.completions) and any provider that omits the final usage simply
// leave tokens at zero; the caller chooses what to emit.
func accumulateOpenAIStream(body []byte) (llm.Usage, string) {
	var (
		usage      llm.Usage
		completion strings.Builder
	)
	scanner := llm.NewScanner(bytes.NewReader(body))
	for {
		ev, err := scanner.Next()
		if err != nil {
			break
		}
		if ev.Data == openAIDoneSentinel {
			break
		}
		if ev.Data == "" {
			continue
		}

		var chunk openAIStreamChunk
		if err := json.Unmarshal([]byte(ev.Data), &chunk); err != nil {
			continue
		}
		for _, c := range chunk.Choices {
			completion.WriteString(c.Delta.Content)
		}
		if chunk.Type == "response.output_text.delta" {
			if s, ok := decodeJSONString(chunk.Delta); ok {
				completion.WriteString(s)
			}
		}

		u := chunk.Usage
		if u == nil && chunk.Response != nil {
			u = chunk.Response.Usage
		}
		applyOpenAIStreamUsage(u, &usage)
	}
	return usage, completion.String()
}

// applyOpenAIStreamUsage lifts the token counts off a final-frame usage
// block into the running usage, normalising the chat.completions
// (prompt_/completion_) and Responses-API (input_/output_) names and
// backfilling total tokens when the provider omits them.
func applyOpenAIStreamUsage(u *openAIStreamUsage, usage *llm.Usage) {
	if u == nil {
		return
	}
	usage.InputTokens = pickInt64(u.InputTokens, u.PromptTokens)
	usage.OutputTokens = pickInt64(u.OutputTokens, u.CompletionTokens)
	usage.TotalTokens = derefInt64(u.TotalTokens)
	if u.InputTokensDetails != nil {
		if v := derefInt64(u.InputTokensDetails.CachedTokens); v > 0 {
			usage.CachedInputTokens = v
		}
	}
	if usage.CachedInputTokens == 0 && u.PromptTokensDetails != nil {
		usage.CachedInputTokens = derefInt64(u.PromptTokensDetails.CachedTokens)
	}
	if usage.TotalTokens == 0 && (usage.InputTokens > 0 || usage.OutputTokens > 0) {
		usage.TotalTokens = usage.InputTokens + usage.OutputTokens
	}
}

// decodeJSONString unmarshals a JSON-encoded string value, returning
// ok=false when the raw message is empty or not a string.
func decodeJSONString(raw json.RawMessage) (string, bool) {
	if len(raw) == 0 {
		return "", false
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return "", false
	}
	return s, true
}

// anthropicStreamEvent captures the union of Messages-API stream event
// payloads we care about. Each named event on the wire fills only its
// shape's fields; unknown keys are ignored.
type anthropicStreamUsage struct {
	InputTokens              *int64 `json:"input_tokens"`
	OutputTokens             *int64 `json:"output_tokens"`
	CacheReadInputTokens     *int64 `json:"cache_read_input_tokens"`
	CacheCreationInputTokens *int64 `json:"cache_creation_input_tokens"`
}

type anthropicStreamEvent struct {
	Type    string `json:"type"`
	Message *struct {
		Usage *anthropicStreamUsage `json:"usage"`
	} `json:"message"`
	Delta *struct {
		Type string `json:"type"`
		Text string `json:"text"`
	} `json:"delta"`
	Usage *anthropicStreamUsage `json:"usage"`
}

// accumulateAnthropicStream tracks input_tokens from message_start,
// output_tokens from message_delta, and concatenates text_delta payloads
// from content_block_delta events. Final usage prefers message_delta
// values which carry the post-completion totals.
func accumulateAnthropicStream(body []byte) (llm.Usage, string) {
	var (
		usage      llm.Usage
		completion strings.Builder
	)
	scanner := llm.NewScanner(bytes.NewReader(body))
	for {
		ev, err := scanner.Next()
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			break
		}
		if ev.Data == "" {
			continue
		}

		var payload anthropicStreamEvent
		if err := json.Unmarshal([]byte(ev.Data), &payload); err != nil {
			continue
		}

		eventType := ev.Type
		if eventType == "" {
			eventType = payload.Type
		}
		applyAnthropicStreamEvent(eventType, payload, &usage, &completion)
	}
	if usage.InputTokens > 0 || usage.OutputTokens > 0 {
		usage.TotalTokens = usage.InputTokens + usage.OutputTokens + usage.CachedInputTokens + usage.CacheCreationTokens
	}
	return usage, completion.String()
}

// applyAnthropicStreamEvent folds one parsed Anthropic Messages stream event
// into the running usage/completion. Shared by the SSE accumulator and the
// Bedrock InvokeModel event-stream, whose chunks wrap the same event JSON.
func applyAnthropicStreamEvent(eventType string, payload anthropicStreamEvent, usage *llm.Usage, completion *strings.Builder) {
	switch eventType {
	case "message_start":
		if payload.Message != nil {
			applyAnthropicStreamUsage(payload.Message.Usage, usage)
		}
	case "content_block_delta":
		if payload.Delta != nil && payload.Delta.Type == "text_delta" {
			completion.WriteString(payload.Delta.Text)
		}
	case "message_delta":
		applyAnthropicStreamUsage(payload.Usage, usage)
	case "message_stop":
		// No-op; Anthropic does not emit usage here.
	}
}

// applyAnthropicStreamUsage folds a non-nil Anthropic usage block into the
// running totals. Each field overwrites only when present and positive, so
// message_delta's post-completion counts supersede the message_start seed
// without zeroing dimensions a later event omits.
func applyAnthropicStreamUsage(u *anthropicStreamUsage, usage *llm.Usage) {
	if u == nil {
		return
	}
	if v := derefInt64(u.InputTokens); v > 0 {
		usage.InputTokens = v
	}
	if v := derefInt64(u.OutputTokens); v > 0 {
		usage.OutputTokens = v
	}
	if v := derefInt64(u.CacheReadInputTokens); v > 0 {
		usage.CachedInputTokens = v
	}
	if v := derefInt64(u.CacheCreationInputTokens); v > 0 {
		usage.CacheCreationTokens = v
	}
}

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
