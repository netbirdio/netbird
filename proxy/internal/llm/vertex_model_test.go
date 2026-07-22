package llm

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNormalizeVertexModel(t *testing.T) {
	cases := map[string]string{
		"claude-sonnet-4-5@20250929": "claude-sonnet-4-5",
		"claude-opus-4-6@20250514":   "claude-opus-4-6",
		"claude-opus-4-6":            "claude-opus-4-6", // bare id passes through
		"text-embedding-005@001":     "text-embedding-005",
		"@cf/meta/llama-3-8b":        "", // leading "@" -> empty (treated as no model)
	}
	for in, want := range cases {
		require.Equal(t, want, NormalizeVertexModel(in), "normalize %q", in)
	}
}
