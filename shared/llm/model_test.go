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
		"claude-sonnet-4-5-20250929":            "claude-sonnet-4-5",
		"claude-3-5-haiku-20241022":             "claude-3-5-haiku",
		"claude-sonnet-5":                       "claude-sonnet-5",
		"claude-opus-4-8":                       "claude-opus-4-8",
		"anthropic.claude-haiku-4-5":            "anthropic.claude-haiku-4-5",
		"anthropic.claude-sonnet-4-5-20250929":  "anthropic.claude-sonnet-4-5",
		"us.anthropic.claude-opus-4-8-20250101": "us.anthropic.claude-opus-4-8",
		// Non-Claude ids must survive untouched even when they end in eight
		// consecutive digits: an operator can register a custom model under
		// any id, and pricing looks every one of them up through this helper.
		"gpt-4o":                  "gpt-4o",
		"gpt-4o-2024-08-06":       "gpt-4o-2024-08-06",
		"gpt-4o-20240806":         "gpt-4o-20240806",
		"internal-llm-20250101":   "internal-llm-20250101",
		"deepseek-r1-20250120":    "deepseek-r1-20250120",
		"Qwen/Qwen2.5-20250101":   "Qwen/Qwen2.5-20250101",
		"gemini-2-5-pro-20250101": "gemini-2-5-pro-20250101",
		"":                        "",
	}
	for in, want := range cases {
		require.Equal(t, want, NormalizeAnthropicModel(in), "normalize %q", in)
	}
}

// TestNormalizeBedrockModel_GeographiesBeyondTheOriginalFour covers the bug
// that made this vendor-anchored: the geography used to be matched against a
// list of four, so a profile issued anywhere else kept its prefix, missed the
// catalog key it was supposed to match, and reported the model unpriced.
func TestNormalizeBedrockModel_GeographiesBeyondTheOriginalFour(t *testing.T) {
	for _, geo := range []string{"us", "eu", "apac", "global", "jp", "au", "ca", "sa", "us-gov", "il", "mx"} {
		t.Run(geo, func(t *testing.T) {
			got := NormalizeBedrockModel(geo + ".anthropic.claude-sonnet-5-20260514-v1:0")
			require.Equal(t, "anthropic.claude-sonnet-5", got,
				"a cross-region profile must reduce to the catalog key whatever geography issued it")
		})
	}
}

// TestNormalizeBedrockModel_KeepsAVendorItCannotMistakeForAGeography pins the
// direction that must never break: a plain "<vendor>.<model>" id has no
// geography, and cutting its first segment would strip the vendor away and
// hand the id to whichever route claims the bare model name.
func TestNormalizeBedrockModel_KeepsAVendorItCannotMistakeForAGeography(t *testing.T) {
	cases := map[string]string{
		"amazon.nova-pro-v1:0":            "amazon.nova-pro",
		"anthropic.claude-sonnet-5-v1:0":  "anthropic.claude-sonnet-5",
		"meta.llama3-3-70b-instruct-v1:0": "meta.llama3-3-70b-instruct",
		"cohere.command-r-plus-v1:0":      "cohere.command-r-plus",
		// Unknown on both axes: neither the leading segment nor the one
		// after it is a name we hold, so the id is left exactly as it came.
		"xx.unknownvendor.some-model-v1:0": "xx.unknownvendor.some-model",
		"Qwen/Qwen2.5-0.5B-Instruct":       "Qwen/Qwen2.5-0.5B-Instruct",
	}
	for in, want := range cases {
		t.Run(in, func(t *testing.T) {
			require.Equal(t, want, NormalizeBedrockModel(in))
		})
	}
}

// TestNormalizeBedrockModel_RecognisesAnIdNewOnOneAxis covers what a live
// eu-central-1 listing returned days after the vendor list was written:
// "global.xai.grok-4.6", a vendor the list did not hold. Anchoring only on the
// vendor left the geography in the key, so the id matched no catalog entry and
// the model metered at zero. Each id below is unfamiliar on one axis and
// recognised through the other.
func TestNormalizeBedrockModel_RecognisesAnIdNewOnOneAxis(t *testing.T) {
	cases := map[string]string{
		// Known geography, vendor we had never seen (the live case).
		"global.xai.grok-4.6": "xai.grok-4.6",
		"eu.xai.grok-4.6":     "xai.grok-4.6",
		// Known vendor, geography outside the list.
		"il.anthropic.claude-sonnet-5-20260514-v1:0": "anthropic.claude-sonnet-5",
		"mx.amazon.nova-2-lite-v1:0":                 "amazon.nova-2-lite",
	}
	for in, want := range cases {
		t.Run(in, func(t *testing.T) {
			require.Equal(t, want, NormalizeBedrockModel(in))
		})
	}
}
