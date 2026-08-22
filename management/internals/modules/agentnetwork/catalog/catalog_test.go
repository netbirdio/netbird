package catalog

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestClaudeLineupSelectable pins the models Claude Code resolves to by
// default. A model absent from the lineup can't be ticked on a provider
// record, so llm_router denies it as not-routable and the operator has no
// way to authorise the client's own default.
func TestClaudeLineupSelectable(t *testing.T) {
	for providerID, wanted := range map[string][]string{
		"anthropic_api": {"claude-opus-5", "claude-sonnet-5", "claude-haiku-4-5"},
		"bedrock_api":   {"anthropic.claude-opus-5", "anthropic.claude-sonnet-5", "anthropic.claude-haiku-4-5"},
		"vertex_ai_api": {"claude-opus-5", "claude-sonnet-5", "claude-haiku-4-5"},
	} {
		provider, ok := Lookup(providerID)
		require.True(t, ok, "catalog must define %s", providerID)

		selectable := make(map[string]Model, len(provider.Models))
		for _, m := range provider.Models {
			selectable[m.ID] = m
		}
		for _, id := range wanted {
			model, found := selectable[id]
			require.True(t, found, "%s must offer %s", providerID, id)
			assert.NotEmpty(t, model.Label, "%s/%s needs a label for the picker", providerID, id)
			assert.Positive(t, model.InputPer1k, "%s/%s needs an input rate", providerID, id)
			assert.Positive(t, model.OutputPer1k, "%s/%s needs an output rate", providerID, id)
			assert.Positive(t, model.ContextWindow, "%s/%s needs a context window", providerID, id)
		}
	}
}
