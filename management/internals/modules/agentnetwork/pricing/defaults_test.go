package pricing

import (
	"math"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/management/internals/modules/agentnetwork/catalog"
)

// TestDefaultTable_CoversEveryCatalogModel replaces the proxy's old
// hand-maintained coverage list: because the table is built FROM the
// catalog, drift is impossible by construction — this test guards the
// fold itself (every catalog model of every surfaced provider resolves,
// with exactly the catalog's rates).
func TestDefaultTable_CoversEveryCatalogModel(t *testing.T) {
	table := DefaultTable()
	for _, p := range catalog.All() {
		if len(p.PricingSurfaces) == 0 {
			assert.Empty(t, p.Models, "catalog entry %s declares models but no pricing surfaces — those models would never be priced", p.ID)
			continue
		}
		for _, surface := range p.PricingSurfaces {
			byModel, ok := table[surface]
			require.True(t, ok, "surface %q (provider %s) missing from default table", surface, p.ID)
			for _, m := range p.Models {
				e, ok := byModel[m.ID]
				require.True(t, ok, "%s/%s (provider %s) missing from default table", surface, m.ID, p.ID)
				assert.Equal(t, m.InputPer1k, e.InputPer1k, "%s/%s input rate", surface, m.ID)
				assert.Equal(t, m.OutputPer1k, e.OutputPer1k, "%s/%s output rate", surface, m.ID)
			}
		}
	}
}

// TestDefaultTable_NoConflictingContributions enforces the collision rule
// documented on catalog.Provider.PricingSurfaces: when two catalog
// providers contribute the same (surface, model) pair — azure/vertex
// mirroring openai/anthropic, kimi on both surfaces — their rates must be
// identical, because the surface-keyed table can only hold one entry.
// If a provider ever diverges (e.g. Azure reprices a model), this fails
// and the divergence must move to per-provider-record pricing.
func TestDefaultTable_NoConflictingContributions(t *testing.T) {
	type contribution struct {
		providerID string
		entry      Entry
	}
	seen := map[string]map[string]contribution{}
	for _, p := range catalog.All() {
		for _, surface := range p.PricingSurfaces {
			if seen[surface] == nil {
				seen[surface] = map[string]contribution{}
			}
			for _, m := range p.Models {
				e := entryFromCatalogModel(m)
				if prev, dup := seen[surface][m.ID]; dup {
					assert.Equal(t, prev.entry, e,
						"%s/%s: %s and %s contribute different rates", surface, m.ID, prev.providerID, p.ID)
					continue
				}
				seen[surface][m.ID] = contribution{providerID: p.ID, entry: e}
			}
		}
	}
	// Supplemental entries must never shadow a catalog-contributed model —
	// they exist precisely because the catalog does NOT list them.
	for surface, models := range supplementalDefaults {
		for id := range models {
			_, fromCatalog := seen[surface][id]
			assert.False(t, fromCatalog, "supplemental %s/%s is now in the catalog — delete the supplemental row", surface, id)
		}
	}
}

// TestDefaultTable_AllRatesFiniteNonNegative mirrors the proxy-side
// NewTable validation so a bad catalog edit is caught here, at unit-test
// time, rather than as a chain-build failure on every proxy.
func TestDefaultTable_AllRatesFiniteNonNegative(t *testing.T) {
	for surface, models := range DefaultTable() {
		for id, e := range models {
			for field, v := range map[string]float64{
				"input":          e.InputPer1k,
				"output":         e.OutputPer1k,
				"cached_input":   e.CachedInputPer1k,
				"cache_read":     e.CacheReadPer1k,
				"cache_creation": e.CacheCreationPer1k,
			} {
				assert.False(t, v < 0 || math.IsNaN(v) || math.IsInf(v, 0),
					"%s/%s: %s rate %v must be finite and non-negative", surface, id, field, v)
			}
		}
	}
}

// TestDefaultTable_PinnedRates pins rates that previously drifted or are
// easy to mis-enter (carried over from the proxy's retired
// defaults_coverage_test), plus the supplemental entries.
func TestDefaultTable_PinnedRates(t *testing.T) {
	table := DefaultTable()

	gpt54 := table["openai"]["gpt-5.4"]
	assert.InDelta(t, 0.0025, gpt54.InputPer1k, 1e-9, "gpt-5.4 input")
	assert.InDelta(t, 0.015, gpt54.OutputPer1k, 1e-9, "gpt-5.4 output")
	assert.InDelta(t, 0.00025, gpt54.CachedInputPer1k, 1e-9, "gpt-5.4 cached input")

	sonnet := table["bedrock"]["anthropic.claude-sonnet-4-5"]
	assert.InDelta(t, 0.003, sonnet.InputPer1k, 1e-9, "bedrock sonnet-4-5 input")
	assert.InDelta(t, 0.015, sonnet.OutputPer1k, 1e-9, "bedrock sonnet-4-5 output")
	assert.InDelta(t, 0.0003, sonnet.CacheReadPer1k, 1e-9, "bedrock sonnet-4-5 cache read")
	assert.InDelta(t, 0.00375, sonnet.CacheCreationPer1k, 1e-9, "bedrock sonnet-4-5 cache creation")

	// Vertex Claude prices under "anthropic" with the bare id.
	fable := table["anthropic"]["claude-fable-5"]
	assert.InDelta(t, 0.010, fable.InputPer1k, 1e-9, "claude-fable-5 input")
	assert.InDelta(t, 0.0125, fable.CacheCreationPer1k, 1e-9, "claude-fable-5 cache creation")

	// Every id below must stay priced whichever source provides it: the
	// catalog lineup for the current Claude 5 family, supplementalDefaults
	// for the ids the dashboard deliberately doesn't offer.
	for surface, ids := range map[string][]string{
		"openai":    {"gpt-5", "gpt-5-mini", "gpt-5-nano"},
		"anthropic": {"claude-opus-5", "claude-sonnet-5", "kimi-k3[1m]", "kimi-k3"},
		"bedrock":   {"anthropic.claude-opus-5", "anthropic.claude-sonnet-5"},
	} {
		for _, id := range ids {
			_, ok := table[surface][id]
			assert.True(t, ok, "%s/%s must be priced", surface, id)
		}
	}

	// Embeddings bill input-only — output stays zero.
	emb := table["openai"]["text-embedding-3-large"]
	assert.Zero(t, emb.OutputPer1k, "embedding output rate must be zero")
	assert.Positive(t, emb.InputPer1k, "embedding input rate must be set")
}

func TestLookupDefault_SurfaceOrder(t *testing.T) {
	// kimi-k3 exists on both surfaces; first surface in the slice wins.
	e, ok := LookupDefault([]string{"openai", "anthropic"}, "kimi-k3")
	require.True(t, ok)
	assert.InDelta(t, 0.003, e.InputPer1k, 1e-9)

	_, ok = LookupDefault([]string{"bedrock"}, "gpt-4o")
	assert.False(t, ok, "gpt-4o is not a bedrock model")

	_, ok = LookupDefault(nil, "gpt-4o")
	assert.False(t, ok, "no surfaces, no match")
}
