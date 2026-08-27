package llm_response_parser

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/proxy/internal/middleware"
)

func loadFixture(t *testing.T, name string) []byte {
	t.Helper()
	root, err := os.Getwd()
	require.NoError(t, err, "must resolve cwd to locate fixture")

	dir := root
	for i := 0; i < 8; i++ {
		candidate := filepath.Join(dir, "proxy", "internal", "llm", "fixtures", name)
		if data, err := os.ReadFile(candidate); err == nil {
			return data
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	t.Fatalf("fixture %q not found relative to %q", name, root)
	return nil
}

func metaValue(kvs []middleware.KV, key string) (string, bool) {
	for _, kv := range kvs {
		if kv.Key == key {
			return kv.Value, true
		}
	}
	return "", false
}

func newTestMiddleware(t *testing.T) *Middleware {
	t.Helper()
	mw, err := Factory{}.New(nil)
	require.NoError(t, err, "factory must accept empty config")
	concrete, ok := mw.(*Middleware)
	require.True(t, ok, "factory must return *Middleware")
	return concrete
}

func TestMiddleware_StaticSurface(t *testing.T) {
	m := newTestMiddleware(t)
	assert.Equal(t, ID, m.ID(), "ID must match registry constant")
	assert.Equal(t, "1.0.0", m.Version(), "Version must be 1.0.0")
	assert.Equal(t, middleware.SlotOnResponse, m.Slot(), "Slot must be SlotOnResponse")
	assert.False(t, m.MutationsSupported(), "response parser does not mutate")
	assert.ElementsMatch(t,
		[]string{"application/json", "text/event-stream"},
		m.AcceptedContentTypes(),
		"AcceptedContentTypes must list JSON and SSE",
	)
	assert.ElementsMatch(t,
		[]string{
			middleware.KeyLLMInputTokens,
			middleware.KeyLLMOutputTokens,
			middleware.KeyLLMTotalTokens,
			middleware.KeyLLMCachedInputTokens,
			middleware.KeyLLMCacheCreationTokens,
			middleware.KeyLLMResponseCompletion,
		},
		m.MetadataKeys(),
		"MetadataKeys must be the documented response-side keys, including the optional cache buckets emitted only when nonzero",
	)
	require.NoError(t, m.Close(), "Close must be a no-op")
}

func TestFactory_AcceptsEmptyAndNullConfig(t *testing.T) {
	for name, raw := range map[string][]byte{
		"nil":   nil,
		"empty": {},
		"null":  []byte("null"),
		"obj":   []byte("{}"),
		"ws":    []byte("   "),
	} {
		t.Run(name, func(t *testing.T) {
			mw, err := Factory{}.New(raw)
			require.NoError(t, err, "factory must accept %s config", name)
			require.NotNil(t, mw, "factory must return middleware for %s", name)
		})
	}
}

func TestFactory_RejectsMalformedJSON(t *testing.T) {
	_, err := Factory{}.New([]byte("not-json"))
	require.Error(t, err, "malformed config must surface a decode error")
}

func TestInvoke_OpenAIBuffered(t *testing.T) {
	m := newTestMiddleware(t)
	body := loadFixture(t, "openai_chat_completion.json")

	in := &middleware.Input{
		Slot:        middleware.SlotOnResponse,
		Status:      200,
		RespHeaders: []middleware.KV{{Key: "Content-Type", Value: "application/json"}},
		RespBody:    body,
		Metadata: []middleware.KV{
			{Key: middleware.KeyLLMProvider, Value: "openai"},
			{Key: middleware.KeyLLMModel, Value: "gpt-4o-mini"},
		},
	}

	out, err := m.Invoke(context.Background(), in)
	require.NoError(t, err, "Invoke must not error on a valid buffered response")
	require.Equal(t, middleware.DecisionAllow, out.Decision, "decision must be Allow")

	in123, ok := metaValue(out.Metadata, middleware.KeyLLMInputTokens)
	require.True(t, ok, "input tokens must be emitted")
	assert.Equal(t, "123", in123, "input tokens must match fixture prompt_tokens")

	outTok, ok := metaValue(out.Metadata, middleware.KeyLLMOutputTokens)
	require.True(t, ok, "output tokens must be emitted")
	assert.Equal(t, "45", outTok, "output tokens must match fixture completion_tokens")

	totTok, ok := metaValue(out.Metadata, middleware.KeyLLMTotalTokens)
	require.True(t, ok, "total tokens must be emitted")
	assert.Equal(t, "168", totTok, "total tokens must match fixture")

	completion, ok := metaValue(out.Metadata, middleware.KeyLLMResponseCompletion)
	require.True(t, ok, "completion must be emitted")
	assert.Equal(t, "Hello, world!", completion, "completion text must match fixture")
}

func TestInvoke_AnthropicBuffered(t *testing.T) {
	m := newTestMiddleware(t)
	body := loadFixture(t, "anthropic_messages.json")

	in := &middleware.Input{
		Slot:        middleware.SlotOnResponse,
		Status:      200,
		RespHeaders: []middleware.KV{{Key: "Content-Type", Value: "application/json"}},
		RespBody:    body,
		Metadata: []middleware.KV{
			{Key: middleware.KeyLLMProvider, Value: "anthropic"},
			{Key: middleware.KeyLLMModel, Value: "claude-sonnet-4-5"},
		},
	}

	out, err := m.Invoke(context.Background(), in)
	require.NoError(t, err, "Invoke must not error on a valid buffered response")
	require.Equal(t, middleware.DecisionAllow, out.Decision, "decision must be Allow")

	in123, _ := metaValue(out.Metadata, middleware.KeyLLMInputTokens)
	assert.Equal(t, "123", in123, "input tokens must match anthropic fixture")

	outTok, _ := metaValue(out.Metadata, middleware.KeyLLMOutputTokens)
	assert.Equal(t, "45", outTok, "output tokens must match anthropic fixture")

	totTok, _ := metaValue(out.Metadata, middleware.KeyLLMTotalTokens)
	assert.Equal(t, "168", totTok, "total tokens must be input+output for anthropic")

	completion, ok := metaValue(out.Metadata, middleware.KeyLLMResponseCompletion)
	require.True(t, ok, "completion must be emitted for anthropic")
	assert.Equal(t, "Hello, world!", completion, "completion text must match fixture")
}

// TestInvoke_OpenAICachedTokensSurfaceOnMetadata covers the
// end-to-end path from the JSON usage block to the
// llm.cached_input_tokens metadata key the cost meter consumes.
// llm.cache_creation_tokens is NOT emitted for OpenAI because
// OpenAI has no cache_creation analogue.
func TestInvoke_OpenAICachedTokensSurfaceOnMetadata(t *testing.T) {
	m := newTestMiddleware(t)
	body := []byte(`{"usage":{"prompt_tokens":1024,"completion_tokens":200,"total_tokens":1224,"prompt_tokens_details":{"cached_tokens":768}}}`)

	in := &middleware.Input{
		Slot:        middleware.SlotOnResponse,
		Status:      200,
		RespHeaders: []middleware.KV{{Key: "Content-Type", Value: "application/json"}},
		RespBody:    body,
		Metadata: []middleware.KV{
			{Key: middleware.KeyLLMProvider, Value: "openai"},
			{Key: middleware.KeyLLMModel, Value: "gpt-4o"},
		},
	}

	out, err := m.Invoke(context.Background(), in)
	require.NoError(t, err)
	cached, ok := metaValue(out.Metadata, middleware.KeyLLMCachedInputTokens)
	require.True(t, ok, "cached_input_tokens must land on the bag when the OpenAI response carries cached_tokens")
	assert.Equal(t, "768", cached)

	_, hasCreation := metaValue(out.Metadata, middleware.KeyLLMCacheCreationTokens)
	assert.False(t, hasCreation, "cache_creation_tokens must NOT be emitted for OpenAI — no analogue in the OpenAI shape")
}

// TestInvoke_AnthropicCacheBucketsSurfaceOnMetadata covers the
// Anthropic shape: both cache_read and cache_creation values flow
// onto the metadata bag so the cost meter can apply per-bucket
// rates.
func TestInvoke_AnthropicCacheBucketsSurfaceOnMetadata(t *testing.T) {
	m := newTestMiddleware(t)
	body := []byte(`{"usage":{"input_tokens":256,"output_tokens":200,"cache_read_input_tokens":768,"cache_creation_input_tokens":512}}`)

	in := &middleware.Input{
		Slot:        middleware.SlotOnResponse,
		Status:      200,
		RespHeaders: []middleware.KV{{Key: "Content-Type", Value: "application/json"}},
		RespBody:    body,
		Metadata: []middleware.KV{
			{Key: middleware.KeyLLMProvider, Value: "anthropic"},
			{Key: middleware.KeyLLMModel, Value: "claude-sonnet-4-5"},
		},
	}

	out, err := m.Invoke(context.Background(), in)
	require.NoError(t, err)

	cached, ok := metaValue(out.Metadata, middleware.KeyLLMCachedInputTokens)
	require.True(t, ok, "cache_read_input_tokens lands under cached_input_tokens — same key carries OpenAI cached subset and Anthropic cache reads, meter switches formula on provider")
	assert.Equal(t, "768", cached)

	creation, ok := metaValue(out.Metadata, middleware.KeyLLMCacheCreationTokens)
	require.True(t, ok, "cache_creation_input_tokens lands under cache_creation_tokens for Anthropic")
	assert.Equal(t, "512", creation)
}

func TestInvoke_NoProviderMetadata_NoOp(t *testing.T) {
	m := newTestMiddleware(t)
	in := &middleware.Input{
		Slot:        middleware.SlotOnResponse,
		Status:      200,
		RespHeaders: []middleware.KV{{Key: "Content-Type", Value: "application/json"}},
		RespBody:    loadFixture(t, "openai_chat_completion.json"),
	}
	out, err := m.Invoke(context.Background(), in)
	require.NoError(t, err, "missing provider metadata is not an error")
	assert.Equal(t, middleware.DecisionAllow, out.Decision, "decision must be Allow")
	assert.Empty(t, out.Metadata, "no metadata when provider context is missing")
}

func TestInvoke_UnknownProvider_NoOp(t *testing.T) {
	m := newTestMiddleware(t)
	in := &middleware.Input{
		Slot:        middleware.SlotOnResponse,
		Status:      200,
		RespHeaders: []middleware.KV{{Key: "Content-Type", Value: "application/json"}},
		RespBody:    loadFixture(t, "openai_chat_completion.json"),
		Metadata:    []middleware.KV{{Key: middleware.KeyLLMProvider, Value: "cohere"}},
	}
	out, err := m.Invoke(context.Background(), in)
	require.NoError(t, err, "unknown provider must not surface an error")
	assert.Empty(t, out.Metadata, "unknown providers emit no metadata")
}

func TestInvoke_ErrorStatus_NoUsageEmitted(t *testing.T) {
	m := newTestMiddleware(t)
	in := &middleware.Input{
		Slot:        middleware.SlotOnResponse,
		Status:      500,
		RespHeaders: []middleware.KV{{Key: "Content-Type", Value: "application/json"}},
		RespBody:    []byte(`{"error":{"message":"upstream blew up"}}`),
		Metadata:    []middleware.KV{{Key: middleware.KeyLLMProvider, Value: "openai"}},
	}
	out, err := m.Invoke(context.Background(), in)
	require.NoError(t, err, "error responses must not surface as middleware error")
	_, ok := metaValue(out.Metadata, middleware.KeyLLMInputTokens)
	assert.False(t, ok, "no usage metadata on >=400 responses")
}

func TestInvoke_NonInspectedContentType_NoOp(t *testing.T) {
	m := newTestMiddleware(t)
	in := &middleware.Input{
		Slot:        middleware.SlotOnResponse,
		Status:      200,
		RespHeaders: []middleware.KV{{Key: "Content-Type", Value: "text/plain"}},
		RespBody:    []byte("not json"),
		Metadata:    []middleware.KV{{Key: middleware.KeyLLMProvider, Value: "openai"}},
	}
	out, err := m.Invoke(context.Background(), in)
	require.NoError(t, err, "Invoke must tolerate non-inspected content types")
	assert.Empty(t, out.Metadata, "no metadata for non-JSON, non-SSE bodies")
}

func TestInvoke_NilInput(t *testing.T) {
	m := newTestMiddleware(t)
	out, err := m.Invoke(context.Background(), nil)
	require.NoError(t, err, "nil input must not error")
	require.Equal(t, middleware.DecisionAllow, out.Decision, "decision must be Allow even on nil input")
	assert.Empty(t, out.Metadata, "no metadata for nil input")
}

func TestInvoke_CompletionTruncatedAt3500Bytes(t *testing.T) {
	m := newTestMiddleware(t)
	long := strings.Repeat("x", 5000)
	body := []byte(`{"id":"x","choices":[{"message":{"role":"assistant","content":"` + long + `"}}],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}`)

	in := &middleware.Input{
		Slot:        middleware.SlotOnResponse,
		Status:      200,
		RespHeaders: []middleware.KV{{Key: "Content-Type", Value: "application/json"}},
		RespBody:    body,
		Metadata:    []middleware.KV{{Key: middleware.KeyLLMProvider, Value: "openai"}},
	}
	out, err := m.Invoke(context.Background(), in)
	require.NoError(t, err, "long-completion body must parse cleanly")

	completion, ok := metaValue(out.Metadata, middleware.KeyLLMResponseCompletion)
	require.True(t, ok, "completion must be emitted for long body")
	assert.LessOrEqual(t, len(completion), maxCompletionBytes, "completion must be truncated to <=3500 bytes")
	assert.Equal(t, maxCompletionBytes, len(completion), "completion must be truncated exactly at the cap when input is ASCII and longer")
}

// TestInvoke_RedactPii_RedactsCompletionBeforeEmit covers the GC contract on
// the response leg: when the synthesiser sets redact_pii=true, the value
// emitted as llm.response_completion must already be redacted, so the
// access-log row never carries raw emails / SSNs / phones the model generated.
// Without this, the response side leaked dozens of raw PII tokens per request.
func TestInvoke_RedactPii_RedactsCompletionBeforeEmit(t *testing.T) {
	mw, err := Factory{}.New([]byte(`{"redact_pii":true}`))
	require.NoError(t, err)

	piiCompletion := "Sample record: Alice Johnson, alice.johnson@example.com, SSN 123-45-6789, phone (202) 555-0147. Bob: 202/555/0108."
	body := []byte(`{"id":"x","choices":[{"message":{"role":"assistant","content":"` + piiCompletion + `"}}],"usage":{"prompt_tokens":10,"completion_tokens":50,"total_tokens":60}}`)

	in := &middleware.Input{
		Slot:        middleware.SlotOnResponse,
		Status:      200,
		RespHeaders: []middleware.KV{{Key: "Content-Type", Value: "application/json"}},
		RespBody:    body,
		Metadata:    []middleware.KV{{Key: middleware.KeyLLMProvider, Value: "openai"}},
	}
	out, err := mw.Invoke(context.Background(), in)
	require.NoError(t, err)
	require.NotNil(t, out)

	completion, ok := metaValue(out.Metadata, middleware.KeyLLMResponseCompletion)
	require.True(t, ok, "completion key must be emitted")
	assert.Contains(t, completion, "[REDACTED:email]", "email must be redacted before emit")
	assert.Contains(t, completion, "[REDACTED:ssn]", "ssn must be redacted before emit")
	assert.Contains(t, completion, "[REDACTED:phone]", "phone must be redacted before emit")
	assert.NotContains(t, completion, "alice.johnson@example.com", "raw email must not survive")
	assert.NotContains(t, completion, "123-45-6789", "raw SSN must not survive")
	assert.NotContains(t, completion, "(202) 555-0147", "parens-phone must not survive")
	assert.NotContains(t, completion, "202/555/0108", "slash-phone must not survive")
}

// TestInvoke_CaptureCompletionOff_DoesNotEmitCompletion mirrors the request
// parser test: when capture_completion=false (operator has enable_prompt_
// collection off), llm.response_completion MUST NOT appear in the access log.
// The token / cost / usage facts the response parser also emits stay so
// operators still get billing data on log-only mode.
func TestInvoke_CaptureCompletionOff_DoesNotEmitCompletion(t *testing.T) {
	mw, err := Factory{}.New([]byte(`{"capture_completion":false}`))
	require.NoError(t, err)
	body := []byte(`{"id":"x","choices":[{"message":{"role":"assistant","content":"alice@example.com 123-45-6789"}}],"usage":{"prompt_tokens":10,"completion_tokens":20,"total_tokens":30}}`)
	in := &middleware.Input{
		Slot:        middleware.SlotOnResponse,
		Status:      200,
		RespHeaders: []middleware.KV{{Key: "Content-Type", Value: "application/json"}},
		RespBody:    body,
		Metadata:    []middleware.KV{{Key: middleware.KeyLLMProvider, Value: "openai"}},
	}
	out, err := mw.Invoke(context.Background(), in)
	require.NoError(t, err)

	_, ok := metaValue(out.Metadata, middleware.KeyLLMResponseCompletion)
	assert.False(t, ok, "llm.response_completion must NOT be emitted when capture_completion is false")

	// Token facts must still flow.
	_, ok = metaValue(out.Metadata, middleware.KeyLLMInputTokens)
	assert.True(t, ok, "input tokens fact must still be emitted")
	_, ok = metaValue(out.Metadata, middleware.KeyLLMOutputTokens)
	assert.True(t, ok, "output tokens fact must still be emitted")
}

// TestInvoke_CaptureCompletionUnset_PreservesLegacyEmission documents the
// default behavior: empty config keeps emitting completion, so callers
// without the toggle aren't broken.
func TestInvoke_CaptureCompletionUnset_PreservesLegacyEmission(t *testing.T) {
	mw, err := Factory{}.New([]byte(`{}`))
	require.NoError(t, err)
	body := []byte(`{"id":"x","choices":[{"message":{"role":"assistant","content":"hello"}}],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}`)
	in := &middleware.Input{
		Slot:        middleware.SlotOnResponse,
		Status:      200,
		RespHeaders: []middleware.KV{{Key: "Content-Type", Value: "application/json"}},
		RespBody:    body,
		Metadata:    []middleware.KV{{Key: middleware.KeyLLMProvider, Value: "openai"}},
	}
	out, err := mw.Invoke(context.Background(), in)
	require.NoError(t, err)
	_, ok := metaValue(out.Metadata, middleware.KeyLLMResponseCompletion)
	assert.True(t, ok, "absent capture_completion must preserve emission (backwards-compatible default)")
}

// TestInvoke_RedactPii_OffShipsRawCompletion covers the inverse: with
// redact_pii=false (default) the model output is shipped verbatim.
func TestInvoke_RedactPii_OffShipsRawCompletion(t *testing.T) {
	mw, err := Factory{}.New(nil)
	require.NoError(t, err)

	body := []byte(`{"id":"x","choices":[{"message":{"role":"assistant","content":"alice@example.com 123-45-6789"}}],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}`)
	in := &middleware.Input{
		Slot:        middleware.SlotOnResponse,
		Status:      200,
		RespHeaders: []middleware.KV{{Key: "Content-Type", Value: "application/json"}},
		RespBody:    body,
		Metadata:    []middleware.KV{{Key: middleware.KeyLLMProvider, Value: "openai"}},
	}
	out, err := mw.Invoke(context.Background(), in)
	require.NoError(t, err)

	completion, ok := metaValue(out.Metadata, middleware.KeyLLMResponseCompletion)
	require.True(t, ok)
	assert.Contains(t, completion, "alice@example.com", "redact off → raw email passes through")
	assert.Contains(t, completion, "123-45-6789", "redact off → raw SSN passes through")
	assert.NotContains(t, completion, "[REDACTED:", "redact off → no markers")
}

func TestInvoke_CompletionTruncationRuneSafe(t *testing.T) {
	rune4 := "\xf0\x9f\x98\x80" // 4-byte emoji
	body := strings.Repeat("a", maxCompletionBytes-1) + rune4
	require.Greater(t, len(body), maxCompletionBytes, "test setup must exceed the cap")

	got := truncateCompletion(body)
	assert.True(t, len(got) < maxCompletionBytes, "truncated bytes must drop the partial rune entirely")
	assert.NotContains(t, got, "\x80", "truncated text must not end on a continuation byte")
}
