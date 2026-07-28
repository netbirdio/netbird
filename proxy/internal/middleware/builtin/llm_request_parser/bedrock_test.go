package llm_request_parser

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNormalizeBedrockModel(t *testing.T) {
	cases := map[string]string{
		"eu.anthropic.claude-sonnet-4-5-20250929-v1:0": "anthropic.claude-sonnet-4-5",
		"us.anthropic.claude-opus-4-8-20250101-v1:0":   "anthropic.claude-opus-4-8",
		"apac.anthropic.claude-haiku-4-5-v1:0":         "anthropic.claude-haiku-4-5",
		"anthropic.claude-sonnet-4-5-20250929-v1:0":    "anthropic.claude-sonnet-4-5",
		"meta.llama3-3-70b-instruct-v1:0":              "meta.llama3-3-70b-instruct",
		"amazon.nova-pro-v1:0":                         "amazon.nova-pro",
		"amazon.nova-2-lite-v1:0":                      "amazon.nova-2-lite",
		// Inference-profile ARN — model id lives in the last path segment.
		"arn:aws:bedrock:eu-central-1:123456789012:inference-profile/eu.anthropic.claude-sonnet-4-5-20250929-v1:0": "anthropic.claude-sonnet-4-5",
	}
	for in, want := range cases {
		require.Equal(t, want, normalizeBedrockModel(in), "normalize %q", in)
	}
}

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
