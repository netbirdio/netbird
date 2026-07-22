package llm

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNormalizeBedrockModel(t *testing.T) {
	cases := map[string]string{
		"eu.anthropic.claude-sonnet-4-5-20250929-v1:0": "anthropic.claude-sonnet-4-5",
		"us.anthropic.claude-haiku-4-5":                "anthropic.claude-haiku-4-5",
		"us.anthropic.claude-opus-4-8-20250101-v1:0":   "anthropic.claude-opus-4-8",
		"anthropic.claude-sonnet-4-5-20250929-v1:0":    "anthropic.claude-sonnet-4-5",
		"meta.llama3-3-70b-instruct-v1:0":              "meta.llama3-3-70b-instruct",
		"amazon.nova-pro-v1:0":                         "amazon.nova-pro",
		// Inference-profile ARN — model id lives in the last path segment.
		"arn:aws:bedrock:eu-central-1:123456789012:inference-profile/eu.anthropic.claude-sonnet-4-5-20250929-v1:0": "anthropic.claude-sonnet-4-5",
	}
	for in, want := range cases {
		require.Equal(t, want, NormalizeBedrockModel(in), "normalize %q", in)
	}
}
