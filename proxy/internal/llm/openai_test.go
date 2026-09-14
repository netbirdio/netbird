package llm

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestOpenAIDetectFromURL(t *testing.T) {
	p := OpenAIParser{}

	cases := map[string]bool{
		"/v1/chat/completions":                  true,
		"/v1/completions":                       true,
		"/v1/embeddings":                        true,
		"/v1/responses":                         true,
		"/API/V1/Chat/Completions":              true,
		"/upstream/v1/chat/completions?trace=1": true,
		// Cloudflare AI Gateway puts its own /v1/{account}/{gateway}
		// segment between the canonical /v1/ and the provider slug,
		// so the /v1/chat/completions substring no longer appears
		// adjacent in the path. The bare /chat/completions hint
		// catches Cloudflare's OpenAI direct path
		// (/v1/{account}/{gateway}/openai/chat/completions) and
		// compat path (/v1/{account}/{gateway}/compat/chat/completions).
		"/v1/{account}/{gateway}/openai/chat/completions":  true,
		"/v1/{account}/{gateway}/compat/chat/completions":  true,
		"/chat/completions":                                true,
		"/v1/messages":                                     false,
		"/healthz":                                         false,
		"":                                                 false,
	}
	for path, want := range cases {
		assert.Equal(t, want, p.DetectFromURL(path), "DetectFromURL(%q)", path)
	}
}

func TestOpenAIParseRequest(t *testing.T) {
	p := OpenAIParser{}

	t.Run("stream true", func(t *testing.T) {
		facts, err := p.ParseRequest([]byte(`{"model":"gpt-4o","stream":true,"stream_options":{"include_usage":true}}`))
		require.NoError(t, err)
		assert.Equal(t, "gpt-4o", facts.Model, "request model extracted")
		assert.True(t, facts.Stream, "request marked as streaming")
	})

	t.Run("stream default", func(t *testing.T) {
		facts, err := p.ParseRequest([]byte(`{"model":"gpt-4o-mini"}`))
		require.NoError(t, err)
		assert.Equal(t, "gpt-4o-mini", facts.Model, "request model extracted")
		assert.False(t, facts.Stream, "missing stream flag defaults to false")
	})

	t.Run("malformed", func(t *testing.T) {
		_, err := p.ParseRequest([]byte(`{not json}`))
		require.Error(t, err)
		assert.True(t, errors.Is(err, ErrMalformedRequest), "sentinel error wrapped")
	})
}

func TestOpenAIParseResponse(t *testing.T) {
	p := OpenAIParser{}

	t.Run("happy fixture", func(t *testing.T) {
		body, err := os.ReadFile(filepath.Join("fixtures", "openai_chat_completion.json"))
		require.NoError(t, err, "fixture must be readable")

		usage, err := p.ParseResponse(200, "application/json", body)
		require.NoError(t, err)
		assert.Equal(t, int64(123), usage.InputTokens, "prompt tokens become input")
		assert.Equal(t, int64(45), usage.OutputTokens, "completion tokens become output")
		assert.Equal(t, int64(168), usage.TotalTokens, "total_tokens carried through")
	})

	t.Run("total computed when missing", func(t *testing.T) {
		body := []byte(`{"usage":{"prompt_tokens":10,"completion_tokens":5}}`)
		usage, err := p.ParseResponse(200, "application/json", body)
		require.NoError(t, err)
		assert.Equal(t, int64(15), usage.TotalTokens, "total computed from in+out")
	})

	t.Run("streaming rejected", func(t *testing.T) {
		_, err := p.ParseResponse(200, "text/event-stream", []byte(""))
		require.ErrorIs(t, err, ErrStreamingUnsupported, "SSE responses must use the scanner")
	})

	t.Run("non-200", func(t *testing.T) {
		_, err := p.ParseResponse(500, "application/json", []byte(`{"error":"x"}`))
		require.ErrorIs(t, err, ErrNotLLMResponse, "non-200 rejected as non-LLM")
	})

	t.Run("non-json content type", func(t *testing.T) {
		_, err := p.ParseResponse(200, "text/plain", []byte(`{}`))
		require.ErrorIs(t, err, ErrNotLLMResponse, "text/plain treated as non-LLM")
	})

	t.Run("malformed body", func(t *testing.T) {
		_, err := p.ParseResponse(200, "application/json", []byte(`{not json`))
		require.ErrorIs(t, err, ErrMalformedResponse, "bad JSON yields malformed error")
	})

	// Responses-API fixture: /v1/responses returns input_tokens/output_tokens
	// (Anthropic-style) instead of prompt_tokens/completion_tokens. The parser
	// must accept both.
	t.Run("responses api fixture", func(t *testing.T) {
		body, err := os.ReadFile(filepath.Join("fixtures", "openai_responses.json"))
		require.NoError(t, err, "fixture must be readable")

		usage, err := p.ParseResponse(200, "application/json", body)
		require.NoError(t, err)
		assert.Equal(t, int64(15), usage.InputTokens, "input_tokens should map directly")
		assert.Equal(t, int64(414), usage.OutputTokens, "output_tokens should map directly")
		assert.Equal(t, int64(429), usage.TotalTokens, "total_tokens carried through")
	})

	t.Run("responses api naming preferred over chat-completions when both present", func(t *testing.T) {
		body := []byte(`{"usage":{"prompt_tokens":1,"completion_tokens":2,"input_tokens":15,"output_tokens":414,"total_tokens":429}}`)
		usage, err := p.ParseResponse(200, "application/json", body)
		require.NoError(t, err)
		assert.Equal(t, int64(15), usage.InputTokens, "responses-api names take precedence")
		assert.Equal(t, int64(414), usage.OutputTokens, "responses-api names take precedence")
	})

	t.Run("chat-completions naming still works alone", func(t *testing.T) {
		body := []byte(`{"usage":{"prompt_tokens":15,"completion_tokens":414,"total_tokens":429}}`)
		usage, err := p.ParseResponse(200, "application/json", body)
		require.NoError(t, err)
		assert.Equal(t, int64(15), usage.InputTokens, "prompt_tokens fallback")
		assert.Equal(t, int64(414), usage.OutputTokens, "completion_tokens fallback")
	})

	// Cached-prompt accounting. cached_tokens is a SUBSET of
	// prompt_tokens — input_tokens carries the full prompt count and
	// the cached subset is reported separately so the cost meter can
	// apply the discount rate to that portion.
	t.Run("chat-completions cached_tokens subset surfaces", func(t *testing.T) {
		body := []byte(`{"usage":{"prompt_tokens":1024,"completion_tokens":200,"total_tokens":1224,"prompt_tokens_details":{"cached_tokens":768}}}`)
		usage, err := p.ParseResponse(200, "application/json", body)
		require.NoError(t, err)
		assert.Equal(t, int64(1024), usage.InputTokens, "input remains the full prompt count — cached is a subset, not a separate bucket")
		assert.Equal(t, int64(768), usage.CachedInputTokens, "cached_tokens must surface so cost meter can discount the cached subset")
		assert.Zero(t, usage.CacheCreationTokens, "OpenAI has no cache_creation analogue")
	})

	t.Run("responses-api input_tokens_details.cached_tokens surfaces", func(t *testing.T) {
		body := []byte(`{"usage":{"input_tokens":2048,"output_tokens":100,"total_tokens":2148,"input_tokens_details":{"cached_tokens":1500}}}`)
		usage, err := p.ParseResponse(200, "application/json", body)
		require.NoError(t, err)
		assert.Equal(t, int64(2048), usage.InputTokens)
		assert.Equal(t, int64(1500), usage.CachedInputTokens, "Responses-API input_tokens_details.cached_tokens path must surface too")
	})

	t.Run("responses-api cached takes precedence over chat-completions when both present", func(t *testing.T) {
		body := []byte(`{"usage":{"prompt_tokens":1,"input_tokens":2,"output_tokens":3,"prompt_tokens_details":{"cached_tokens":50},"input_tokens_details":{"cached_tokens":99}}}`)
		usage, err := p.ParseResponse(200, "application/json", body)
		require.NoError(t, err)
		assert.Equal(t, int64(99), usage.CachedInputTokens, "Responses-API field wins when both naming conventions are present")
	})

	t.Run("absent cached_tokens leaves cached counts at zero", func(t *testing.T) {
		body := []byte(`{"usage":{"prompt_tokens":15,"completion_tokens":414,"total_tokens":429}}`)
		usage, err := p.ParseResponse(200, "application/json", body)
		require.NoError(t, err)
		assert.Zero(t, usage.CachedInputTokens, "no prompt_tokens_details = no cached subset")
	})
}

func TestOpenAIExtractPrompt_ChatCompletions(t *testing.T) {
	body := []byte(`{"model":"gpt-4o-mini","messages":[{"role":"system","content":"be brief"},{"role":"user","content":"ping"}]}`)
	got := OpenAIParser{}.ExtractPrompt(body)
	require.NotEmpty(t, got, "messages array must extract")
	require.Contains(t, got, "system: be brief", "system role and content surface")
	require.Contains(t, got, "user: ping", "user role and content surface")
}

func TestOpenAIExtractPrompt_ResponsesAPIStringInput(t *testing.T) {
	body := []byte(`{"model":"gpt-5.4","input":"Hello there"}`)
	got := OpenAIParser{}.ExtractPrompt(body)
	require.Equal(t, "Hello there", got, "string input field should pass through")
}

func TestOpenAIExtractPrompt_ResponsesAPIInputParts(t *testing.T) {
	body := []byte(`{"model":"gpt-5.4","input":[{"type":"input_text","input_text":"first"},{"type":"input_text","input_text":"second"}]}`)
	got := OpenAIParser{}.ExtractPrompt(body)
	require.Contains(t, got, "first", "first content part surfaces")
	require.Contains(t, got, "second", "second content part surfaces")
}

// TestOpenAIExtractPrompt_ResponsesAPIMessageItems guards the live Codex
// shape: input is an array of message items whose text is nested under
// content[].text, not flat content parts. The old code fed the outer array
// to the content-part decoder and extracted nothing, so the stored prompt
// was empty.
func TestOpenAIExtractPrompt_ResponsesAPIMessageItems(t *testing.T) {
	body := []byte(`{"model":"gpt-5.5","input":[` +
		`{"type":"message","role":"developer","content":[{"type":"input_text","text":"system rules"}]},` +
		`{"type":"message","role":"user","content":[{"type":"input_text","text":"hello there"}]},` +
		`{"type":"reasoning","encrypted_content":"opaque","summary":[]},` +
		`{"type":"message","role":"assistant","content":[{"type":"output_text","text":"prior reply"}]}` +
		`]}`)
	got := OpenAIParser{}.ExtractPrompt(body)
	require.Contains(t, got, "system rules", "developer message content must surface")
	require.Contains(t, got, "hello there", "user message content must surface")
	require.Contains(t, got, "developer:", "role labels must prefix each message")
	require.NotContains(t, got, "opaque", "reasoning items without text must be skipped")
}

func TestOpenAIExtractPrompt_LegacyCompletion(t *testing.T) {
	body := []byte(`{"model":"text-davinci-003","prompt":"once upon a time"}`)
	got := OpenAIParser{}.ExtractPrompt(body)
	require.Equal(t, "once upon a time", got, "string prompt field should pass through")
}

func TestOpenAIExtractSessionID(t *testing.T) {
	t.Run("codex client_metadata.session_id", func(t *testing.T) {
		body := []byte(`{"model":"gpt-5.5","client_metadata":{"session_id":"019eeb72-ab7c-7cd2","thread_id":"t1"},"input":[]}`)
		assert.Equal(t, "019eeb72-ab7c-7cd2", OpenAIParser{}.ExtractSessionID(body), "Codex session id must come from client_metadata.session_id")
	})
	t.Run("plain chat has no session", func(t *testing.T) {
		body := []byte(`{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}]}`)
		assert.Equal(t, "", OpenAIParser{}.ExtractSessionID(body), "plain chat.completions carries no session id")
	})
	t.Run("non-JSON yields empty", func(t *testing.T) {
		assert.Equal(t, "", OpenAIParser{}.ExtractSessionID([]byte("not json")), "malformed body must not error")
	})
}

func TestOpenAIExtractCompletion_ChatCompletions(t *testing.T) {
	body, err := os.ReadFile(filepath.Join("fixtures", "openai_chat_completion.json"))
	require.NoError(t, err)
	got := OpenAIParser{}.ExtractCompletion(200, "application/json", body)
	require.NotEmpty(t, got, "fixture has assistant content")
}

func TestOpenAIExtractCompletion_ResponsesAPI(t *testing.T) {
	body, err := os.ReadFile(filepath.Join("fixtures", "openai_responses.json"))
	require.NoError(t, err)
	got := OpenAIParser{}.ExtractCompletion(200, "application/json", body)
	require.NotEmpty(t, got, "responses-api fixture has output content")
}

func TestOpenAIExtractCompletion_Streaming(t *testing.T) {
	got := OpenAIParser{}.ExtractCompletion(200, "text/event-stream", []byte(""))
	require.Empty(t, got, "streaming responses are skipped")
}

func TestOpenAIExtractCompletion_NonOK(t *testing.T) {
	got := OpenAIParser{}.ExtractCompletion(500, "application/json", []byte(`{"choices":[{"message":{"content":"x"}}]}`))
	require.Empty(t, got, "non-200 returns empty")
}
