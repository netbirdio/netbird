package llm_response_parser

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/proxy/internal/middleware"
)

// TestInvoke_OpenAIResponsesStreaming is the regression guard for the live
// bug where Codex hits /v1/responses (the OpenAI Responses API), whose SSE
// shape differs from chat.completions: completion text rides
// response.output_text.delta and usage rides response.completed under
// response.usage. The old parser only knew the chat.completions shape, so
// resp_meta came back empty (no tokens, no cost).
func TestInvoke_OpenAIResponsesStreaming(t *testing.T) {
	m := newTestMiddleware(t)
	body := loadFixture(t, "openai_responses_stream.txt")

	in := &middleware.Input{
		Slot:        middleware.SlotOnResponse,
		Status:      200,
		RespHeaders: []middleware.KV{{Key: "Content-Type", Value: "text/event-stream; charset=utf-8"}},
		RespBody:    body,
		Metadata: []middleware.KV{
			{Key: middleware.KeyLLMProvider, Value: "openai"},
			{Key: middleware.KeyLLMModel, Value: "gpt-5.5"},
		},
	}

	out, err := m.Invoke(context.Background(), in)
	require.NoError(t, err, "Invoke must not error on a Responses-API streaming body")

	inTok, ok := metaValue(out.Metadata, middleware.KeyLLMInputTokens)
	require.True(t, ok, "input tokens must be emitted from a Responses-API stream")
	assert.Equal(t, "123", inTok, "input_tokens must come from response.completed usage")

	outTok, _ := metaValue(out.Metadata, middleware.KeyLLMOutputTokens)
	assert.Equal(t, "45", outTok, "output_tokens must come from response.completed usage")

	totTok, _ := metaValue(out.Metadata, middleware.KeyLLMTotalTokens)
	assert.Equal(t, "168", totTok, "total_tokens must come from response.completed usage")

	cached, ok := metaValue(out.Metadata, middleware.KeyLLMCachedInputTokens)
	require.True(t, ok, "cached input tokens must surface from input_tokens_details")
	assert.Equal(t, "40", cached, "cached_tokens subset must surface for cost discounting")

	completion, ok := metaValue(out.Metadata, middleware.KeyLLMResponseCompletion)
	require.True(t, ok, "completion must be emitted for Responses-API streams")
	assert.Equal(t, "Hello, world!", completion, "output_text.delta events must concatenate")
}

// TestAccumulateOpenAIStream_ResponsesNoUsage confirms that a Responses-API
// stream with text but no terminal usage frame still yields the completion
// and leaves tokens at zero rather than erroring.
func TestAccumulateOpenAIStream_ResponsesNoUsage(t *testing.T) {
	body := []byte(`event: response.output_text.delta
data: {"type":"response.output_text.delta","delta":"partial"}

`)

	usage, completion := accumulateOpenAIStream(body)
	assert.Equal(t, int64(0), usage.InputTokens, "no usage frame leaves input tokens at zero")
	assert.Equal(t, int64(0), usage.OutputTokens, "no usage frame leaves output tokens at zero")
	assert.Equal(t, "partial", completion, "output_text deltas accumulate even without a usage frame")
}
