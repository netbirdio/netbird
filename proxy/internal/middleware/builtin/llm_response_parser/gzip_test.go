package llm_response_parser

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/proxy/internal/middleware"
)

// gzipBytes returns data gzip-compressed — the wire shape Anthropic
// returns when the client (Claude Code) negotiated Accept-Encoding: gzip.
func gzipBytes(t *testing.T, data []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)
	_, err := w.Write(data)
	require.NoError(t, err, "gzip write must succeed")
	require.NoError(t, w.Close(), "gzip close must succeed")
	return buf.Bytes()
}

// TestInvoke_AnthropicStreaming_Gzip is the regression guard for the live
// bug: Claude Code negotiates gzip, Anthropic gzips the SSE stream, the
// proxy captures the compressed bytes, and the parser must decompress
// before accumulating — otherwise token usage is silently dropped and
// cost_meter skips with missing_tokens.
func TestInvoke_AnthropicStreaming_Gzip(t *testing.T) {
	m := newTestMiddleware(t)
	body := gzipBytes(t, loadFixture(t, "anthropic_stream.txt"))

	in := &middleware.Input{
		Slot:   middleware.SlotOnResponse,
		Status: 200,
		RespHeaders: []middleware.KV{
			{Key: "Content-Type", Value: "text/event-stream; charset=utf-8"},
			{Key: "Content-Encoding", Value: "gzip"},
		},
		RespBody: body,
		Metadata: []middleware.KV{
			{Key: middleware.KeyLLMProvider, Value: "anthropic"},
			{Key: middleware.KeyLLMModel, Value: "claude-opus-4-8"},
		},
	}

	out, err := m.Invoke(context.Background(), in)
	require.NoError(t, err, "Invoke must not error on a gzip-encoded streaming body")

	in123, ok := metaValue(out.Metadata, middleware.KeyLLMInputTokens)
	require.True(t, ok, "input tokens must be emitted from a gzip SSE stream")
	assert.Equal(t, "123", in123, "input tokens must survive gzip decompression")

	outTok, _ := metaValue(out.Metadata, middleware.KeyLLMOutputTokens)
	assert.Equal(t, "45", outTok, "output tokens must survive gzip decompression")

	totTok, _ := metaValue(out.Metadata, middleware.KeyLLMTotalTokens)
	assert.Equal(t, "168", totTok, "total tokens must survive gzip decompression")
}

// TestInvoke_AnthropicBuffered_Gzip covers the non-streaming JSON path
// under gzip — the same decode must happen before ParseResponse.
func TestInvoke_AnthropicBuffered_Gzip(t *testing.T) {
	m := newTestMiddleware(t)
	body := gzipBytes(t, loadFixture(t, "anthropic_messages.json"))

	in := &middleware.Input{
		Slot:   middleware.SlotOnResponse,
		Status: 200,
		RespHeaders: []middleware.KV{
			{Key: "Content-Type", Value: "application/json"},
			{Key: "Content-Encoding", Value: "gzip"},
		},
		RespBody: body,
		Metadata: []middleware.KV{
			{Key: middleware.KeyLLMProvider, Value: "anthropic"},
			{Key: middleware.KeyLLMModel, Value: "claude-opus-4-8"},
		},
	}

	out, err := m.Invoke(context.Background(), in)
	require.NoError(t, err, "Invoke must not error on a gzip-encoded buffered body")

	_, ok := metaValue(out.Metadata, middleware.KeyLLMInputTokens)
	require.True(t, ok, "input tokens must be emitted from a gzip JSON body")
}

// TestDecodeResponseBody covers the encoding matrix directly.
func TestDecodeResponseBody(t *testing.T) {
	plain := []byte(`{"hello":"world"}`)

	t.Run("identity passthrough", func(t *testing.T) {
		assert.Equal(t, plain, decodeResponseBody(plain, ""))
		assert.Equal(t, plain, decodeResponseBody(plain, "identity"))
	})

	t.Run("gzip", func(t *testing.T) {
		assert.Equal(t, plain, decodeResponseBody(gzipBytes(t, plain), "gzip"))
	})

	t.Run("gzip with multi-coding header takes outermost", func(t *testing.T) {
		assert.Equal(t, plain, decodeResponseBody(gzipBytes(t, plain), "identity, gzip"))
	})

	t.Run("deflate zlib-wrapped", func(t *testing.T) {
		var buf bytes.Buffer
		zw := zlib.NewWriter(&buf)
		_, _ = zw.Write(plain)
		_ = zw.Close()
		assert.Equal(t, plain, decodeResponseBody(buf.Bytes(), "deflate"))
	})

	t.Run("deflate raw flate fallback", func(t *testing.T) {
		var buf bytes.Buffer
		fw, _ := flate.NewWriter(&buf, flate.DefaultCompression)
		_, _ = fw.Write(plain)
		_ = fw.Close()
		assert.Equal(t, plain, decodeResponseBody(buf.Bytes(), "deflate"))
	})

	t.Run("gzip header but not actually gzip falls back to raw", func(t *testing.T) {
		assert.Equal(t, plain, decodeResponseBody(plain, "gzip"))
	})

	t.Run("unknown encoding (br) returns raw", func(t *testing.T) {
		assert.Equal(t, plain, decodeResponseBody(plain, "br"))
	})
}
