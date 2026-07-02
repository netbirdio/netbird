package pricing

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestDefaultTable_FirstPartyModelCoverage guards the embedded defaults against
// silent drift/gaps: every metered first-party model the management catalog
// enumerates must resolve to a price, and a few rates that previously drifted
// are pinned to their LiteLLM-validated values. Keep this list in step with the
// catalog (management/server/agentnetwork/catalog) when adding models.
func TestDefaultTable_FirstPartyModelCoverage(t *testing.T) {
	tbl := DefaultTable()
	require.NotNil(t, tbl, "embedded default pricing table must load")

	mustPrice := map[string][]string{
		// openai parser covers openai_api, azure_openai_api, and mistral_api.
		"openai": {
			"gpt-5.5", "gpt-5.5-pro", "gpt-5.4", "gpt-5.4-mini", "gpt-5.4-nano",
			"gpt-5.3-codex", "gpt-5.3-chat-latest", "o4-mini",
			"gpt-4.1", "gpt-4.1-mini", "gpt-4.1-nano", "gpt-4o", "gpt-4o-mini",
			"gpt-4-turbo", "gpt-3.5-turbo", "gpt-35-turbo",
			"text-embedding-3-large", "text-embedding-3-small",
			"mistral-large-latest", "mistral-medium-3-5", "codestral-2508",
			"ministral-8b-latest", "mistral-embed",
		},
		"anthropic": {
			"claude-fable-5", "claude-opus-4-8", "claude-opus-4-7", "claude-opus-4-6",
			"claude-opus-4-1", "claude-sonnet-4-6", "claude-sonnet-4-5", "claude-haiku-4-5",
		},
		// bedrock keys are the normalized ids the request parser emits.
		"bedrock": {
			"anthropic.claude-opus-4-8", "anthropic.claude-opus-4-7", "anthropic.claude-opus-4-6",
			"anthropic.claude-opus-4-1", "anthropic.claude-sonnet-4-6", "anthropic.claude-sonnet-4-5",
			"anthropic.claude-haiku-4-5", "meta.llama3-3-70b-instruct",
			"amazon.nova-pro", "amazon.nova-lite", "amazon.nova-micro", "amazon.nova-2-lite",
		},
	}
	for provider, models := range mustPrice {
		for _, m := range models {
			_, ok := tbl.Cost(provider, m, 1000, 1000, 0, 0)
			assert.True(t, ok, "%s/%s must be priced in the embedded defaults", provider, m)
		}
	}

	// Pin per-direction rates independently (input-only then output-only) so a
	// swap or skew of input<->output that preserves the combined total is still
	// caught — these are rates that previously drifted or are easy to mis-enter.
	in, ok := tbl.Cost("openai", "gpt-5.4", 1000, 0, 0, 0)
	require.True(t, ok)
	assert.InDelta(t, 0.0025, in, 1e-9, "gpt-5.4 input = 0.0025 per 1k")
	out, ok := tbl.Cost("openai", "gpt-5.4", 0, 1000, 0, 0)
	require.True(t, ok)
	assert.InDelta(t, 0.015, out, 1e-9, "gpt-5.4 output = 0.015 per 1k")

	in, ok = tbl.Cost("bedrock", "anthropic.claude-sonnet-4-5", 1000, 0, 0, 0)
	require.True(t, ok)
	assert.InDelta(t, 0.003, in, 1e-9, "bedrock sonnet-4-5 input = 0.003 per 1k")
	out, ok = tbl.Cost("bedrock", "anthropic.claude-sonnet-4-5", 0, 1000, 0, 0)
	require.True(t, ok)
	assert.InDelta(t, 0.015, out, 1e-9, "bedrock sonnet-4-5 output = 0.015 per 1k")
}
