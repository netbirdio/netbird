package llm

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAnthropicDetectFromURL(t *testing.T) {
	p := AnthropicParser{}

	cases := map[string]bool{
		"/v1/messages":         true,
		"/v1/complete":         true,
		"/V1/Messages":         true,
		"/proxy/v1/messages?x": true,
		"/v1/chat/completions": false,
		"":                     false,
	}
	for path, want := range cases {
		assert.Equal(t, want, p.DetectFromURL(path), "DetectFromURL(%q)", path)
	}
}

func TestAnthropicParseRequest(t *testing.T) {
	p := AnthropicParser{}

	t.Run("stream true", func(t *testing.T) {
		facts, err := p.ParseRequest([]byte(`{"model":"claude-sonnet-4-5","stream":true}`))
		require.NoError(t, err)
		assert.Equal(t, "claude-sonnet-4-5", facts.Model, "model extracted")
		assert.True(t, facts.Stream, "stream flag honoured")
	})

	t.Run("stream default", func(t *testing.T) {
		facts, err := p.ParseRequest([]byte(`{"model":"claude-sonnet-4-5"}`))
		require.NoError(t, err)
		assert.False(t, facts.Stream, "missing stream flag defaults to false")
	})

	t.Run("malformed", func(t *testing.T) {
		_, err := p.ParseRequest([]byte(`{"model":`))
		require.Error(t, err)
		assert.True(t, errors.Is(err, ErrMalformedRequest), "sentinel wrapped")
	})
}

func TestAnthropicParseResponse(t *testing.T) {
	p := AnthropicParser{}

	t.Run("happy fixture", func(t *testing.T) {
		body, err := os.ReadFile(filepath.Join("fixtures", "anthropic_messages.json"))
		require.NoError(t, err, "fixture must be readable")

		usage, err := p.ParseResponse(200, "application/json", body)
		require.NoError(t, err)
		assert.Equal(t, int64(123), usage.InputTokens, "input tokens extracted")
		assert.Equal(t, int64(45), usage.OutputTokens, "output tokens extracted")
		assert.Equal(t, int64(168), usage.TotalTokens, "total computed as sum")
	})

	t.Run("streaming rejected", func(t *testing.T) {
		_, err := p.ParseResponse(200, "text/event-stream", []byte(""))
		require.ErrorIs(t, err, ErrStreamingUnsupported, "SSE responses must use the scanner")
	})

	t.Run("non-200", func(t *testing.T) {
		_, err := p.ParseResponse(429, "application/json", []byte(`{}`))
		require.ErrorIs(t, err, ErrNotLLMResponse, "non-200 rejected as non-LLM")
	})

	t.Run("non-json content type", func(t *testing.T) {
		_, err := p.ParseResponse(200, "text/html", []byte(`{}`))
		require.ErrorIs(t, err, ErrNotLLMResponse, "text/html treated as non-LLM")
	})

	t.Run("malformed body", func(t *testing.T) {
		_, err := p.ParseResponse(200, "application/json", []byte(`{`))
		require.ErrorIs(t, err, ErrMalformedResponse, "bad JSON yields malformed error")
	})

	// Anthropic's two cache fields are ADDITIVE to input_tokens (not
	// subset). The parser must surface them so the cost meter can
	// bill each bucket at its own configured rate. Total includes
	// every bucket so downstream attribution sees the full token
	// volume the request consumed.
	t.Run("cache_read_input_tokens surfaces as CachedInputTokens (additive)", func(t *testing.T) {
		body := []byte(`{"usage":{"input_tokens":256,"output_tokens":200,"cache_read_input_tokens":768}}`)
		usage, err := p.ParseResponse(200, "application/json", body)
		require.NoError(t, err)
		assert.Equal(t, int64(256), usage.InputTokens, "regular input remains separate from cache buckets")
		assert.Equal(t, int64(768), usage.CachedInputTokens, "cache_read maps onto CachedInputTokens — same field carries OpenAI cached subset and Anthropic cache reads")
		assert.Zero(t, usage.CacheCreationTokens)
		assert.Equal(t, int64(256+200+768), usage.TotalTokens, "total includes every input bucket plus output — cache reads are billable tokens")
	})

	t.Run("cache_creation_input_tokens surfaces as CacheCreationTokens (additive)", func(t *testing.T) {
		body := []byte(`{"usage":{"input_tokens":256,"output_tokens":200,"cache_creation_input_tokens":512}}`)
		usage, err := p.ParseResponse(200, "application/json", body)
		require.NoError(t, err)
		assert.Equal(t, int64(256), usage.InputTokens)
		assert.Zero(t, usage.CachedInputTokens)
		assert.Equal(t, int64(512), usage.CacheCreationTokens, "cache_creation surfaces — meter applies the write-rate multiplier")
		assert.Equal(t, int64(256+200+512), usage.TotalTokens)
	})

	t.Run("both cache buckets present", func(t *testing.T) {
		body := []byte(`{"usage":{"input_tokens":256,"output_tokens":200,"cache_read_input_tokens":768,"cache_creation_input_tokens":512}}`)
		usage, err := p.ParseResponse(200, "application/json", body)
		require.NoError(t, err)
		assert.Equal(t, int64(768), usage.CachedInputTokens)
		assert.Equal(t, int64(512), usage.CacheCreationTokens)
		assert.Equal(t, int64(256+200+768+512), usage.TotalTokens, "all four buckets sum into total")
	})

	t.Run("absent cache fields leave counts at zero", func(t *testing.T) {
		body := []byte(`{"usage":{"input_tokens":100,"output_tokens":50}}`)
		usage, err := p.ParseResponse(200, "application/json", body)
		require.NoError(t, err)
		assert.Zero(t, usage.CachedInputTokens, "no cache_read field = no cached count")
		assert.Zero(t, usage.CacheCreationTokens, "no cache_creation field = no creation count")
		assert.Equal(t, int64(150), usage.TotalTokens, "back to the simple in+out total when no cache buckets present")
	})
}

func TestAnthropicExtractPrompt_Messages(t *testing.T) {
	body := []byte(`{"model":"claude-sonnet-4-7","system":"be brief","messages":[{"role":"user","content":"hi"},{"role":"assistant","content":"yes"}]}`)
	got := AnthropicParser{}.ExtractPrompt(body)
	require.Contains(t, got, "system: be brief", "system surfaces with role label")
	require.Contains(t, got, "user: hi", "user message surfaces")
	require.Contains(t, got, "assistant: yes", "assistant message surfaces")
}

func TestAnthropicExtractPrompt_LegacyComplete(t *testing.T) {
	body := []byte(`{"model":"claude-2","prompt":"\n\nHuman: hi\n\nAssistant:"}`)
	got := AnthropicParser{}.ExtractPrompt(body)
	require.Contains(t, got, "Human: hi", "legacy prompt string surfaces")
}

func TestAnthropicExtractSessionID(t *testing.T) {
	t.Run("claude code session suffix", func(t *testing.T) {
		body := []byte(`{"model":"claude-opus-4-8","metadata":{"user_id":"user_abc123_account_def456_session_9f8e7d6c"},"messages":[]}`)
		assert.Equal(t, "9f8e7d6c", AnthropicParser{}.ExtractSessionID(body), "session_<id> suffix must be extracted from metadata.user_id")
	})
	t.Run("plain user_id is not treated as a session", func(t *testing.T) {
		body := []byte(`{"model":"claude-opus-4-8","metadata":{"user_id":"acme-team"},"messages":[]}`)
		assert.Equal(t, "", AnthropicParser{}.ExtractSessionID(body), "a user identifier without a session marker must NOT be used as a session id")
	})
	t.Run("no metadata yields empty", func(t *testing.T) {
		body := []byte(`{"model":"claude-opus-4-8","messages":[{"role":"user","content":"hi"}]}`)
		assert.Equal(t, "", AnthropicParser{}.ExtractSessionID(body), "absent metadata.user_id yields no session id")
	})
}

func TestAnthropicExtractCompletion_Messages(t *testing.T) {
	body, err := os.ReadFile(filepath.Join("fixtures", "anthropic_messages.json"))
	require.NoError(t, err)
	got := AnthropicParser{}.ExtractCompletion(200, "application/json", body)
	require.NotEmpty(t, got, "anthropic fixture has assistant text")
}

func TestAnthropicExtractCompletion_Streaming(t *testing.T) {
	got := AnthropicParser{}.ExtractCompletion(200, "text/event-stream", []byte(""))
	require.Empty(t, got, "streaming responses are skipped")
}
