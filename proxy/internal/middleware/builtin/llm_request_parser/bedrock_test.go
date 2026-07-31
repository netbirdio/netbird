package llm_request_parser

import (
	"testing"

	"github.com/stretchr/testify/require"
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
