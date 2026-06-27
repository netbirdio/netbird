package llm_request_parser

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/proxy/internal/middleware"
)

func metaValue(t *testing.T, kvs []middleware.KV, key string) (string, bool) {
	t.Helper()
	for _, kv := range kvs {
		if kv.Key == key {
			return kv.Value, true
		}
	}
	return "", false
}

func newMiddleware(t *testing.T) middleware.Middleware {
	t.Helper()
	mw, err := Factory{}.New(nil)
	require.NoError(t, err, "factory must accept nil config")
	return mw
}

func TestMiddleware_StaticSurface(t *testing.T) {
	mw := newMiddleware(t)
	assert.Equal(t, ID, mw.ID(), "ID must match the registered constant")
	assert.Equal(t, Version, mw.Version(), "Version must match the constant")
	assert.Equal(t, middleware.SlotOnRequest, mw.Slot(), "must run in the request slot")
	assert.Equal(t, []string{"application/json"}, mw.AcceptedContentTypes(), "only JSON bodies are needed")
	assert.False(t, mw.MutationsSupported(), "request parser never mutates")
	assert.NoError(t, mw.Close(), "Close on stateless middleware is a no-op")

	keys := mw.MetadataKeys()
	expected := []string{
		middleware.KeyLLMProvider,
		middleware.KeyLLMModel,
		middleware.KeyLLMStream,
		middleware.KeyLLMRequestPromptRaw,
		middleware.KeyLLMCaptureTruncated,
		middleware.KeyLLMSessionID,
	}
	assert.Equal(t, expected, keys, "metadata key allowlist must match the spec")
}

func TestFactory_AcceptsEmptyAndJSONConfig(t *testing.T) {
	cases := [][]byte{nil, {}, []byte("null"), []byte("{}"), []byte("   ")}
	for _, raw := range cases {
		mw, err := Factory{}.New(raw)
		require.NoError(t, err, "empty/null/object config must be accepted")
		require.NotNil(t, mw, "factory must return a middleware instance")
	}
}

func TestFactory_RejectsMalformedConfig(t *testing.T) {
	mw, err := Factory{}.New([]byte("{not json"))
	require.Error(t, err, "malformed config must surface at construction")
	assert.Nil(t, mw, "no instance is returned on error")
}

func TestInvoke_OpenAIBufferedChatCompletion(t *testing.T) {
	mw := newMiddleware(t)
	body := []byte(`{"model":"gpt-4o-mini","stream":false,"messages":[{"role":"user","content":"Hello, world!"}]}`)

	out, err := mw.Invoke(context.Background(), &middleware.Input{
		URL:  "/v1/chat/completions",
		Body: body,
	})
	require.NoError(t, err)
	require.NotNil(t, out, "output must be returned")
	assert.Equal(t, middleware.DecisionAllow, out.Decision, "request parser always allows")

	provider, ok := metaValue(t, out.Metadata, middleware.KeyLLMProvider)
	require.True(t, ok, "provider metadata must be set")
	assert.Equal(t, "openai", provider, "OpenAI provider detected from path")

	model, ok := metaValue(t, out.Metadata, middleware.KeyLLMModel)
	require.True(t, ok, "model metadata must be set")
	assert.Equal(t, "gpt-4o-mini", model, "model echoed from request body")

	stream, ok := metaValue(t, out.Metadata, middleware.KeyLLMStream)
	require.True(t, ok, "stream metadata must be set")
	assert.Equal(t, "false", stream, "buffered request reports stream=false")

	prompt, ok := metaValue(t, out.Metadata, middleware.KeyLLMRequestPromptRaw)
	require.True(t, ok, "prompt metadata must be set when extractable")
	assert.Contains(t, prompt, "Hello, world!", "extracted prompt carries the user message")

	truncated, ok := metaValue(t, out.Metadata, middleware.KeyLLMCaptureTruncated)
	require.True(t, ok, "capture_truncated must always be emitted on success")
	assert.Equal(t, "false", truncated, "no truncation on a small body")
}

func TestInvoke_EmitsSessionID(t *testing.T) {
	mw := newMiddleware(t)

	t.Run("codex session from client_metadata", func(t *testing.T) {
		body := []byte(`{"model":"gpt-5.5","client_metadata":{"session_id":"sess-codex-1"},"input":[]}`)
		out, err := mw.Invoke(context.Background(), &middleware.Input{URL: "/v1/responses", Body: body})
		require.NoError(t, err)
		sid, ok := metaValue(t, out.Metadata, middleware.KeyLLMSessionID)
		require.True(t, ok, "session id must be emitted for Codex requests")
		assert.Equal(t, "sess-codex-1", sid, "session id must come from client_metadata.session_id")
	})

	t.Run("no session id key when absent", func(t *testing.T) {
		body := []byte(`{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}]}`)
		out, err := mw.Invoke(context.Background(), &middleware.Input{URL: "/v1/chat/completions", Body: body})
		require.NoError(t, err)
		_, ok := metaValue(t, out.Metadata, middleware.KeyLLMSessionID)
		assert.False(t, ok, "no session id key emitted when the request carries none")
	})

	t.Run("claude code session header", func(t *testing.T) {
		body := []byte(`{"model":"claude-opus-4-8","messages":[{"role":"user","content":"hi"}]}`)
		out, err := mw.Invoke(context.Background(), &middleware.Input{
			URL:     "/v1/messages",
			Body:    body,
			Headers: []middleware.KV{{Key: "X-Claude-Code-Session-Id", Value: "cc-sess-1"}},
		})
		require.NoError(t, err)
		sid, ok := metaValue(t, out.Metadata, middleware.KeyLLMSessionID)
		require.True(t, ok, "Claude Code session id must be read from X-Claude-Code-Session-Id")
		assert.Equal(t, "cc-sess-1", sid, "session id must come from the Claude Code session header")
	})

	t.Run("codex Session-Id header", func(t *testing.T) {
		// Codex sends the session as the canonical header "Session-Id".
		body := []byte(`{"model":"gpt-5.5","input":[]}`)
		out, err := mw.Invoke(context.Background(), &middleware.Input{
			URL:     "/v1/responses",
			Body:    body,
			Headers: []middleware.KV{{Key: "Session-Id", Value: "sess-hdr-1"}},
		})
		require.NoError(t, err)
		sid, ok := metaValue(t, out.Metadata, middleware.KeyLLMSessionID)
		require.True(t, ok, "session id must be read from the Session-Id header")
		assert.Equal(t, "sess-hdr-1", sid, "session id must come from the Codex Session-Id header")
	})

	t.Run("header wins over body and survives bypassed body", func(t *testing.T) {
		// Oversized request: body was bypassed to a routing stub with no
		// client_metadata, but the header still carries the session.
		out, err := mw.Invoke(context.Background(), &middleware.Input{
			URL:     "/v1/responses",
			Body:    []byte(`{"model":"gpt-5.5","stream":true}`),
			Headers: []middleware.KV{{Key: "X-Session-Id", Value: "sess-hdr-2"}},
		})
		require.NoError(t, err)
		sid, _ := metaValue(t, out.Metadata, middleware.KeyLLMSessionID)
		assert.Equal(t, "sess-hdr-2", sid, "x-session-id header must be honoured when the body carries no marker")
	})
}

func TestInvoke_OpenAIStreamingChatCompletion(t *testing.T) {
	mw := newMiddleware(t)
	body := []byte(`{"model":"gpt-4o-mini","stream":true,"messages":[{"role":"user","content":"hi"}]}`)

	out, err := mw.Invoke(context.Background(), &middleware.Input{
		URL:  "/v1/chat/completions",
		Body: body,
	})
	require.NoError(t, err)

	stream, ok := metaValue(t, out.Metadata, middleware.KeyLLMStream)
	require.True(t, ok, "stream metadata must be set")
	assert.Equal(t, "true", stream, "stream flag echoed for SSE-bound request")
}

func TestInvoke_AnthropicMessages(t *testing.T) {
	mw := newMiddleware(t)
	body := []byte(`{"model":"claude-sonnet-4-5","stream":false,"messages":[{"role":"user","content":"What is the weather?"}]}`)

	out, err := mw.Invoke(context.Background(), &middleware.Input{
		URL:  "/v1/messages",
		Body: body,
	})
	require.NoError(t, err)

	provider, ok := metaValue(t, out.Metadata, middleware.KeyLLMProvider)
	require.True(t, ok, "provider metadata must be set")
	assert.Equal(t, "anthropic", provider, "Anthropic provider detected from path")

	model, _ := metaValue(t, out.Metadata, middleware.KeyLLMModel)
	assert.Equal(t, "claude-sonnet-4-5", model, "anthropic model echoed")

	prompt, ok := metaValue(t, out.Metadata, middleware.KeyLLMRequestPromptRaw)
	require.True(t, ok, "prompt metadata must be set")
	assert.Contains(t, prompt, "What is the weather?", "anthropic message text extracted")
}

func TestInvoke_UnknownURLNoMetadata(t *testing.T) {
	mw := newMiddleware(t)
	out, err := mw.Invoke(context.Background(), &middleware.Input{
		URL:  "/healthz",
		Body: []byte(`{"model":"x"}`),
	})
	require.NoError(t, err)
	require.NotNil(t, out)
	assert.Equal(t, middleware.DecisionAllow, out.Decision, "unknown paths still allow")
	assert.Empty(t, out.Metadata, "no metadata is emitted when no parser matches")
}

func TestInvoke_ProviderIDConfigBypassesURLSniff(t *testing.T) {
	mw, err := Factory{}.New([]byte(`{"provider_id":"openai"}`))
	require.NoError(t, err, "factory must accept provider_id config")

	// URL doesn't match any of the OpenAI path hints — the provider_id
	// config is the only signal the middleware has.
	out, err := mw.Invoke(context.Background(), &middleware.Input{
		URL:  "/custom/gateway/foo/bar",
		Body: []byte(`{"model":"gpt-4o-mini","messages":[{"role":"user","content":"Hi"}]}`),
	})
	require.NoError(t, err)
	require.NotNil(t, out)
	assert.Equal(t, middleware.DecisionAllow, out.Decision)

	provider, ok := metaValue(t, out.Metadata, middleware.KeyLLMProvider)
	require.True(t, ok, "provider must be emitted when provider_id is configured even on unknown URLs")
	assert.Equal(t, "openai", provider, "provider_id config selects the OpenAI parser")

	model, ok := metaValue(t, out.Metadata, middleware.KeyLLMModel)
	require.True(t, ok, "model still extracted from the body")
	assert.Equal(t, "gpt-4o-mini", model)
}

func TestInvoke_UnknownProviderIDFallsBackToURL(t *testing.T) {
	mw, err := Factory{}.New([]byte(`{"provider_id":"not-a-real-parser"}`))
	require.NoError(t, err, "factory must accept any provider_id string")

	// URL hits the OpenAI surface, so URL sniffing should still resolve
	// even though the configured provider_id doesn't match a parser.
	out, err := mw.Invoke(context.Background(), &middleware.Input{
		URL:  "/v1/chat/completions",
		Body: []byte(`{"model":"gpt-4o-mini"}`),
	})
	require.NoError(t, err)
	require.NotNil(t, out)

	provider, ok := metaValue(t, out.Metadata, middleware.KeyLLMProvider)
	require.True(t, ok, "fallback URL sniffing must populate the provider")
	assert.Equal(t, "openai", provider)
}

func TestInvoke_MalformedBodyAllowsWithProvider(t *testing.T) {
	mw := newMiddleware(t)
	out, err := mw.Invoke(context.Background(), &middleware.Input{
		URL:  "/v1/chat/completions",
		Body: []byte(`{not json`),
	})
	require.NoError(t, err, "malformed body must not error")
	require.NotNil(t, out)
	assert.Equal(t, middleware.DecisionAllow, out.Decision, "decision is always allow")

	provider, ok := metaValue(t, out.Metadata, middleware.KeyLLMProvider)
	require.True(t, ok, "provider metadata is emitted before body parse")
	assert.Equal(t, "openai", provider, "provider stays even when body parse fails")

	_, hasModel := metaValue(t, out.Metadata, middleware.KeyLLMModel)
	assert.False(t, hasModel, "no model metadata when parse fails")

	truncated, ok := metaValue(t, out.Metadata, middleware.KeyLLMCaptureTruncated)
	require.True(t, ok, "capture_truncated is emitted on parse error path")
	assert.Equal(t, "false", truncated, "no truncation marker without truncated body or prompt")
}

func TestInvoke_TruncatesLongPrompt(t *testing.T) {
	mw := newMiddleware(t)
	long := strings.Repeat("x", maxPromptBytes*2)
	body := []byte(`{"model":"gpt-4o-mini","messages":[{"role":"user","content":"` + long + `"}]}`)

	out, err := mw.Invoke(context.Background(), &middleware.Input{
		URL:  "/v1/chat/completions",
		Body: body,
	})
	require.NoError(t, err)

	prompt, ok := metaValue(t, out.Metadata, middleware.KeyLLMRequestPromptRaw)
	require.True(t, ok, "prompt metadata must be set")
	assert.LessOrEqual(t, len(prompt), maxPromptBytes, "prompt must respect the byte budget")

	truncated, ok := metaValue(t, out.Metadata, middleware.KeyLLMCaptureTruncated)
	require.True(t, ok, "capture_truncated must be set")
	assert.Equal(t, "true", truncated, "truncation marker raised when prompt is clipped")
}

func TestInvoke_TruncatesOnRuneBoundary(t *testing.T) {
	mw := newMiddleware(t)
	// Each ☃ is 3 bytes in UTF-8; build a string whose byte length exceeds
	// maxPromptBytes with snowmen straddling the cut point.
	rune3 := "☃"
	repeats := (maxPromptBytes / len(rune3)) + 5
	long := strings.Repeat(rune3, repeats)
	body := []byte(`{"model":"gpt-4o-mini","messages":[{"role":"user","content":"` + long + `"}]}`)

	out, err := mw.Invoke(context.Background(), &middleware.Input{
		URL:  "/v1/chat/completions",
		Body: body,
	})
	require.NoError(t, err)

	prompt, ok := metaValue(t, out.Metadata, middleware.KeyLLMRequestPromptRaw)
	require.True(t, ok, "prompt metadata must be set")
	assert.LessOrEqual(t, len(prompt), maxPromptBytes, "prompt must respect the byte budget")
	assert.True(t, strings.HasSuffix(prompt, rune3) || !strings.ContainsRune(prompt[len(prompt)-1:], 0xFFFD),
		"truncation must not split a multi-byte rune")
}

func TestInvoke_BodyTruncatedRaisesCaptureTruncated(t *testing.T) {
	mw := newMiddleware(t)
	body := []byte(`{"model":"gpt-4o-mini","messages":[{"role":"user","content":"hi"}]}`)

	out, err := mw.Invoke(context.Background(), &middleware.Input{
		URL:           "/v1/chat/completions",
		Body:          body,
		BodyTruncated: true,
	})
	require.NoError(t, err)

	truncated, ok := metaValue(t, out.Metadata, middleware.KeyLLMCaptureTruncated)
	require.True(t, ok, "capture_truncated must be set")
	assert.Equal(t, "true", truncated, "BodyTruncated input flips the marker even when prompt fits")
}

// TestInvoke_RedactPii_RedactsBeforeEmittingRawPrompt covers the GC contract:
// when the synthesiser sets redact_pii=true on the parser config, the value
// emitted as llm.request_prompt_raw must already be redacted, so the
// access-log row never carries raw emails / SSNs / phones — even though the
// downstream llm_guardrail middleware also runs.
func TestInvoke_RedactPii_RedactsBeforeEmittingRawPrompt(t *testing.T) {
	mw, err := Factory{}.New([]byte(`{"redact_pii":true}`))
	require.NoError(t, err)

	body := []byte(`{"model":"gpt-4o-mini","stream":false,"messages":[{"role":"user","content":"contact alice.johnson@example.com SSN 123-45-6789 phone (202) 555-0147 and bob 202/555/0108"}]}`)
	out, err := mw.Invoke(context.Background(), &middleware.Input{URL: "/v1/chat/completions", Body: body})
	require.NoError(t, err)
	require.NotNil(t, out)

	raw, ok := metaValue(t, out.Metadata, middleware.KeyLLMRequestPromptRaw)
	require.True(t, ok, "raw prompt key must still be emitted")
	assert.Contains(t, raw, "[REDACTED:email]", "email must be redacted before emit")
	assert.Contains(t, raw, "[REDACTED:ssn]", "ssn must be redacted before emit")
	assert.Contains(t, raw, "[REDACTED:phone]", "phone must be redacted before emit")
	assert.NotContains(t, raw, "alice.johnson@example.com", "raw email must not survive")
	assert.NotContains(t, raw, "123-45-6789", "raw SSN must not survive")
	assert.NotContains(t, raw, "(202) 555-0147", "parenthesised phone must not survive")
	assert.NotContains(t, raw, "202/555/0108", "slash-separated phone must not survive")
}

// TestInvoke_CapturePromptOff_DoesNotEmitRawPrompt covers the contract for
// the account-level enable_prompt_collection toggle: when the synthesiser sets
// capture_prompt=false (operator hasn't opted in to prompt content), the
// parser MUST NOT emit llm.request_prompt_raw at all — otherwise the access
// log carries the user's input even though log collection is meant to be
// metadata-only (provider, model, tokens, cost). The other facts the parser
// emits (provider, model, stream, capture_truncated) stay.
func TestInvoke_CapturePromptOff_DoesNotEmitRawPrompt(t *testing.T) {
	mw, err := Factory{}.New([]byte(`{"capture_prompt":false}`))
	require.NoError(t, err)
	body := []byte(`{"model":"gpt-4o","messages":[{"role":"user","content":"contact alice@example.com SSN 123-45-6789"}]}`)
	out, err := mw.Invoke(context.Background(), &middleware.Input{URL: "/v1/chat/completions", Body: body})
	require.NoError(t, err)
	require.NotNil(t, out)

	_, ok := metaValue(t, out.Metadata, middleware.KeyLLMRequestPromptRaw)
	assert.False(t, ok, "llm.request_prompt_raw must NOT be emitted when capture_prompt is false")
	// Non-content facts must still flow.
	_, ok = metaValue(t, out.Metadata, middleware.KeyLLMModel)
	assert.True(t, ok, "model fact must still be emitted")
	_, ok = metaValue(t, out.Metadata, middleware.KeyLLMProvider)
	assert.True(t, ok, "provider fact must still be emitted")
}

// TestInvoke_CapturePromptUnset_PreservesLegacyEmission documents the default
// behavior: an empty / legacy config (no capture_prompt field) keeps the
// existing emission, so non-agent-network callers and pre-toggle tests don't
// suddenly lose data.
func TestInvoke_CapturePromptUnset_PreservesLegacyEmission(t *testing.T) {
	mw, err := Factory{}.New([]byte(`{}`))
	require.NoError(t, err)
	body := []byte(`{"model":"gpt-4o","messages":[{"role":"user","content":"hello"}]}`)
	out, err := mw.Invoke(context.Background(), &middleware.Input{URL: "/v1/chat/completions", Body: body})
	require.NoError(t, err)
	_, ok := metaValue(t, out.Metadata, middleware.KeyLLMRequestPromptRaw)
	assert.True(t, ok, "absent capture_prompt must preserve emission (backwards-compatible default)")
}

// TestInvoke_RedactPii_OffShipsRawPrompt is the inverse: when redact_pii is
// false (default) the operator opted out and the raw prompt is shipped
// verbatim, so audit / debugging consumers still get the full body.
func TestInvoke_RedactPii_OffShipsRawPrompt(t *testing.T) {
	mw, err := Factory{}.New([]byte(`{}`))
	require.NoError(t, err)

	body := []byte(`{"model":"gpt-4o-mini","messages":[{"role":"user","content":"alice.johnson@example.com"}]}`)
	out, err := mw.Invoke(context.Background(), &middleware.Input{URL: "/v1/chat/completions", Body: body})
	require.NoError(t, err)

	raw, ok := metaValue(t, out.Metadata, middleware.KeyLLMRequestPromptRaw)
	require.True(t, ok)
	assert.Contains(t, raw, "alice.johnson@example.com", "redact off → raw email passes through")
	assert.NotContains(t, raw, "[REDACTED:", "redact off → no markers")
}

func TestInvoke_NilInputAllows(t *testing.T) {
	mw := newMiddleware(t)
	out, err := mw.Invoke(context.Background(), nil)
	require.NoError(t, err, "nil input must not panic or error")
	require.NotNil(t, out)
	assert.Equal(t, middleware.DecisionAllow, out.Decision, "nil input still allows")
	assert.Empty(t, out.Metadata, "nil input emits no metadata")
}
