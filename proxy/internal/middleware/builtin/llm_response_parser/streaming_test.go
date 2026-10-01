package llm_response_parser

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/proxy/internal/middleware"
)

func TestInvoke_OpenAIStreamingWithUsage(t *testing.T) {
	m := newTestMiddleware(t)
	body := loadFixture(t, "openai_stream.txt")

	in := &middleware.Input{
		Slot:        middleware.SlotOnResponse,
		Status:      200,
		RespHeaders: []middleware.KV{{Key: "Content-Type", Value: "text/event-stream"}},
		RespBody:    body,
		Metadata: []middleware.KV{
			{Key: middleware.KeyLLMProvider, Value: "openai"},
			{Key: middleware.KeyLLMModel, Value: "gpt-4o-mini"},
		},
	}

	out, err := m.Invoke(context.Background(), in)
	require.NoError(t, err, "Invoke must not error on streaming OpenAI body")

	in123, _ := metaValue(out.Metadata, middleware.KeyLLMInputTokens)
	assert.Equal(t, "123", in123, "input tokens must come from final-chunk usage block")

	outTok, _ := metaValue(out.Metadata, middleware.KeyLLMOutputTokens)
	assert.Equal(t, "45", outTok, "output tokens must come from final-chunk usage block")

	totTok, _ := metaValue(out.Metadata, middleware.KeyLLMTotalTokens)
	assert.Equal(t, "168", totTok, "total tokens must come from final-chunk usage block")

	completion, ok := metaValue(out.Metadata, middleware.KeyLLMResponseCompletion)
	require.True(t, ok, "completion must be emitted for streaming responses")
	assert.Equal(t, "Hello, world!", completion, "deltas must concatenate into the buffered fixture's text")
}

func TestInvoke_OpenAIStreamingWithoutUsage(t *testing.T) {
	body := []byte(`data: {"choices":[{"delta":{"content":"Hi"}}]}

data: {"choices":[{"delta":{"content":" there"}}]}

data: [DONE]

`)

	usage, completion := accumulateOpenAIStream(body)
	assert.Equal(t, int64(0), usage.InputTokens, "input tokens must stay zero without a usage frame")
	assert.Equal(t, int64(0), usage.OutputTokens, "output tokens must stay zero without a usage frame")
	assert.Equal(t, int64(0), usage.TotalTokens, "total tokens must stay zero without a usage frame")
	assert.Equal(t, "Hi there", completion, "deltas must still accumulate when usage is absent")
}

func TestInvoke_OpenAIStreamingNoUsage_OmitsUsageMetadata(t *testing.T) {
	m := newTestMiddleware(t)
	body := []byte(`data: {"choices":[{"delta":{"content":"Hello"}}]}

data: [DONE]

`)
	in := &middleware.Input{
		Slot:        middleware.SlotOnResponse,
		Status:      200,
		RespHeaders: []middleware.KV{{Key: "Content-Type", Value: "text/event-stream"}},
		RespBody:    body,
		Metadata:    []middleware.KV{{Key: middleware.KeyLLMProvider, Value: "openai"}},
	}
	out, err := m.Invoke(context.Background(), in)
	require.NoError(t, err, "Invoke must not error on usage-less streams")

	_, hasIn := metaValue(out.Metadata, middleware.KeyLLMInputTokens)
	_, hasOut := metaValue(out.Metadata, middleware.KeyLLMOutputTokens)
	_, hasTot := metaValue(out.Metadata, middleware.KeyLLMTotalTokens)
	assert.False(t, hasIn, "input tokens omitted when no usage frame")
	assert.False(t, hasOut, "output tokens omitted when no usage frame")
	assert.False(t, hasTot, "total tokens omitted when no usage frame")

	completion, ok := metaValue(out.Metadata, middleware.KeyLLMResponseCompletion)
	require.True(t, ok, "completion must still be emitted from deltas")
	assert.Equal(t, "Hello", completion, "completion must come from delta accumulation")
}

func TestInvoke_AnthropicStreaming(t *testing.T) {
	m := newTestMiddleware(t)
	body := loadFixture(t, "anthropic_stream.txt")

	in := &middleware.Input{
		Slot:        middleware.SlotOnResponse,
		Status:      200,
		RespHeaders: []middleware.KV{{Key: "Content-Type", Value: "text/event-stream"}},
		RespBody:    body,
		Metadata: []middleware.KV{
			{Key: middleware.KeyLLMProvider, Value: "anthropic"},
			{Key: middleware.KeyLLMModel, Value: "claude-sonnet-4-5"},
		},
	}

	out, err := m.Invoke(context.Background(), in)
	require.NoError(t, err, "Invoke must not error on streaming Anthropic body")

	in123, _ := metaValue(out.Metadata, middleware.KeyLLMInputTokens)
	assert.Equal(t, "123", in123, "input tokens must come from message_start usage")

	outTok, _ := metaValue(out.Metadata, middleware.KeyLLMOutputTokens)
	assert.Equal(t, "45", outTok, "output tokens must come from message_delta usage")

	totTok, _ := metaValue(out.Metadata, middleware.KeyLLMTotalTokens)
	assert.Equal(t, "168", totTok, "total tokens must be input+output for anthropic streaming")

	completion, ok := metaValue(out.Metadata, middleware.KeyLLMResponseCompletion)
	require.True(t, ok, "completion must be emitted from text_delta accumulation")
	assert.Equal(t, "Hello, world!", completion, "anthropic streaming text must accumulate across content_block_delta events")
}

func TestInvoke_StreamingTruncatedBody_BestEffort(t *testing.T) {
	m := newTestMiddleware(t)
	full := loadFixture(t, "anthropic_stream.txt")
	cut := len(full) / 2
	truncated := full[:cut]

	in := &middleware.Input{
		Slot:              middleware.SlotOnResponse,
		Status:            200,
		RespHeaders:       []middleware.KV{{Key: "Content-Type", Value: "text/event-stream"}},
		RespBody:          truncated,
		RespBodyTruncated: true,
		Metadata:          []middleware.KV{{Key: middleware.KeyLLMProvider, Value: "anthropic"}},
	}

	require.NotPanics(t, func() {
		_, err := m.Invoke(context.Background(), in)
		require.NoError(t, err, "truncated streaming body must not surface as error")
	}, "Invoke must never panic on a truncated SSE body")
}

func TestInvoke_StreamingEmptyBody(t *testing.T) {
	m := newTestMiddleware(t)
	in := &middleware.Input{
		Slot:        middleware.SlotOnResponse,
		Status:      200,
		RespHeaders: []middleware.KV{{Key: "Content-Type", Value: "text/event-stream"}},
		RespBody:    nil,
		Metadata:    []middleware.KV{{Key: middleware.KeyLLMProvider, Value: "openai"}},
	}
	out, err := m.Invoke(context.Background(), in)
	require.NoError(t, err, "empty SSE body must not surface as error")
	assert.Empty(t, out.Metadata, "no metadata for empty SSE body")
}

func TestAccumulateAnthropicStream_PartialUsage(t *testing.T) {
	body := []byte(`event: message_start
data: {"type":"message_start","message":{"usage":{"input_tokens":10}}}

event: content_block_delta
data: {"type":"content_block_delta","delta":{"type":"text_delta","text":"hi"}}

`)
	usage, completion := accumulateAnthropicStream(body)
	assert.Equal(t, int64(10), usage.InputTokens, "partial input_tokens must survive truncated stream")
	assert.Equal(t, int64(0), usage.OutputTokens, "output_tokens stays zero without message_delta")
	assert.Equal(t, "hi", completion, "completion must come from observed text_delta events")
}
