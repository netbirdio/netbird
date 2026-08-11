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
		"apac.anthropic.claude-haiku-4-5-v1:0":         "anthropic.claude-haiku-4-5",
		"amazon.nova-2-lite-v1:0":                      "amazon.nova-2-lite",
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

func TestNormalizeVertexModel(t *testing.T) {
	cases := map[string]string{
		"claude-sonnet-4-5@20250929": "claude-sonnet-4-5",
		"claude-haiku-4-5":           "claude-haiku-4-5",
		"gpt-4o@2024-08-06":          "gpt-4o",
	}
	for in, want := range cases {
		require.Equal(t, want, NormalizeVertexModel(in), "normalize %q", in)
	}
}

func TestNormalizeAnthropicModel(t *testing.T) {
	cases := map[string]string{
		"claude-sonnet-4-5-20250929": "claude-sonnet-4-5",
		"claude-3-5-haiku-20241022":  "claude-3-5-haiku",
		"claude-sonnet-5":            "claude-sonnet-5",
		"claude-opus-4-8":            "claude-opus-4-8",
		// Other vendors' ids must survive untouched: none of them end in
		// eight consecutive digits.
		"gpt-4o":                     "gpt-4o",
		"gpt-4o-2024-08-06":          "gpt-4o-2024-08-06",
		"anthropic.claude-haiku-4-5": "anthropic.claude-haiku-4-5",
		"":                           "",
	}
	for in, want := range cases {
		require.Equal(t, want, NormalizeAnthropicModel(in), "normalize %q", in)
	}
}
