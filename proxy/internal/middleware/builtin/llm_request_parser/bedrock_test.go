package llm_request_parser

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/proxy/internal/middleware"
)

func TestParseBedrockPath(t *testing.T) {
	tests := []struct {
		path   string
		model  string
		stream bool
		ok     bool
	}{
		{"/model/eu.anthropic.claude-sonnet-4-5-20250929-v1:0/invoke", "anthropic.claude-sonnet-4-5", false, true},
		{"/model/eu.anthropic.claude-sonnet-4-5-20250929-v1:0/invoke-with-response-stream", "anthropic.claude-sonnet-4-5", true, true},
		{"/model/eu.anthropic.claude-sonnet-4-5-20250929-v1:0/converse", "anthropic.claude-sonnet-4-5", false, true},
		{"/model/eu.anthropic.claude-sonnet-4-5-20250929-v1:0/converse-stream", "anthropic.claude-sonnet-4-5", true, true},
		// URL-encoded colon in the version suffix.
		{"/model/eu.anthropic.claude-sonnet-4-5-20250929-v1%3A0/invoke", "anthropic.claude-sonnet-4-5", false, true},
		// Optional "/bedrock" gateway-namespace prefix.
		{"/bedrock/model/eu.anthropic.claude-sonnet-4-5-20250929-v1:0/invoke-with-response-stream", "anthropic.claude-sonnet-4-5", true, true},
		{"/bedrock/model/anthropic.claude-sonnet-4-5-20250929-v1:0/converse", "anthropic.claude-sonnet-4-5", false, true},
		{"/v1/chat/completions", "", false, false},
		{"/model/foo", "", false, false},
		{"/model//invoke", "", false, false},
		{"/model/x/unknown-action", "", false, false},
	}
	for _, tt := range tests {
		br, ok := parseBedrockPath(tt.path)
		require.Equal(t, tt.ok, ok, "ok for %q", tt.path)
		if tt.ok {
			require.Equal(t, tt.model, br.model, "model for %q", tt.path)
			require.Equal(t, tt.stream, br.stream, "stream for %q", tt.path)
		}
	}
}

// TestInvoke_BedrockCountTokens covers the dedicated token-counting
// endpoint. Denying it does not break the client, it just pushes context
// counting back onto the inference endpoint, which is billable.
func TestInvoke_BedrockCountTokens(t *testing.T) {
	mw := newMiddleware(t)

	out, err := mw.Invoke(context.Background(), &middleware.Input{
		URL:  "/model/us.anthropic.claude-sonnet-4-5-20250929-v1:0/count-tokens",
		Body: []byte(`{"input":{"converse":{"messages":[]}}}`),
	})
	require.NoError(t, err)
	require.NotNil(t, out)
	assert.Equal(t, middleware.DecisionAllow, out.Decision)

	model, ok := metaValue(t, out.Metadata, middleware.KeyLLMModel)
	require.True(t, ok, "count-tokens carries a model in the path and must emit it")
	assert.Equal(t, "anthropic.claude-sonnet-4-5", model, "model must be normalized like any other action")

	stream, _ := metaValue(t, out.Metadata, middleware.KeyLLMStream)
	assert.Equal(t, "false", stream, "count-tokens never streams")
}
