package llm

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestBedrockParser_ParseResponse_Invoke(t *testing.T) {
	body := []byte(`{"usage":{"input_tokens":13,"output_tokens":5,"cache_read_input_tokens":2,"cache_creation_input_tokens":4}}`)
	u, err := BedrockParser{}.ParseResponse(200, "application/json", body)
	require.NoError(t, err)
	require.Equal(t, int64(13), u.InputTokens, "invoke input tokens")
	require.Equal(t, int64(5), u.OutputTokens, "invoke output tokens")
	require.Equal(t, int64(2), u.CachedInputTokens, "invoke cache-read tokens")
	require.Equal(t, int64(4), u.CacheCreationTokens, "invoke cache-creation tokens")
	require.Equal(t, int64(13+5+2+4), u.TotalTokens, "invoke total is additive")
}

func TestBedrockParser_ParseResponse_Converse(t *testing.T) {
	body := []byte(`{"output":{"message":{"content":[{"text":"pong"}]}},"usage":{"inputTokens":11,"outputTokens":3,"totalTokens":14}}`)
	u, err := BedrockParser{}.ParseResponse(200, "application/json", body)
	require.NoError(t, err)
	require.Equal(t, int64(11), u.InputTokens, "converse camelCase input tokens")
	require.Equal(t, int64(3), u.OutputTokens, "converse camelCase output tokens")
	require.Equal(t, int64(14), u.TotalTokens, "converse uses provider total")
}

func TestBedrockParser_ParseResponse_StreamingUnsupported(t *testing.T) {
	_, err := BedrockParser{}.ParseResponse(200, "application/vnd.amazon.eventstream", []byte("binary"))
	require.ErrorIs(t, err, ErrStreamingUnsupported, "event-stream must route to the streaming accumulator")
}

func TestBedrockParser_ParseResponse_NonSuccess(t *testing.T) {
	_, err := BedrockParser{}.ParseResponse(404, "application/json", []byte(`{"message":"gated"}`))
	require.ErrorIs(t, err, ErrNotLLMResponse, "non-200 is not an LLM response")
}

func TestBedrockParser_ExtractCompletion(t *testing.T) {
	invoke := BedrockParser{}.ExtractCompletion(200, "application/json", []byte(`{"content":[{"text":"a"},{"text":"b"}]}`))
	require.Equal(t, "a\nb", invoke, "invoke completion joins content parts")

	converse := BedrockParser{}.ExtractCompletion(200, "application/json", []byte(`{"output":{"message":{"content":[{"text":"x"}]}}}`))
	require.Equal(t, "x", converse, "converse completion reads output.message.content")
}

func TestBedrockParser_ExtractPrompt(t *testing.T) {
	invoke := BedrockParser{}.ExtractPrompt([]byte(`{"messages":[{"role":"user","content":"hi"}]}`))
	require.Equal(t, "user: hi", invoke, "invoke prompt reads anthropic content string")

	converse := BedrockParser{}.ExtractPrompt([]byte(`{"messages":[{"role":"user","content":[{"text":"hello"}]}]}`))
	require.Equal(t, "user: hello", converse, "converse prompt reads content parts")
}

func TestBedrockParser_DetectFromURL(t *testing.T) {
	require.True(t, BedrockParser{}.DetectFromURL("/model/eu.anthropic.claude/invoke"), "invoke path")
	require.True(t, BedrockParser{}.DetectFromURL("/model/x/converse-stream"), "converse-stream path")
	require.False(t, BedrockParser{}.DetectFromURL("/v1/chat/completions"), "openai path is not bedrock")
}

func TestBedrockParser_RegisteredByName(t *testing.T) {
	p, ok := ParserByName(ProviderNameBedrock)
	require.True(t, ok, "bedrock parser is registered")
	require.Equal(t, ProviderNameBedrock, p.ProviderName())
}
