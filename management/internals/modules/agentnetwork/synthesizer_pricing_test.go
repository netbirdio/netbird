package agentnetwork

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/management/internals/modules/agentnetwork/types"
)

func fptr(v float64) *float64 { return &v }

func decodeCostMeterConfig(t *testing.T, raw []byte) costMeterConfig {
	t.Helper()
	var cfg costMeterConfig
	require.NoError(t, json.Unmarshal(raw, &cfg), "cost meter config must round-trip")
	require.NotNil(t, cfg.Pricing, "pricing wrapper must be present")
	return cfg
}

// TestBuildCostMeterConfig_BedrockModelNormalization: the operator may
// paste region-prefixed, versioned, or ARN-wrapped Bedrock ids; the
// per-record map must be keyed by the normalized id the request parser
// emits as llm.model, or the lookup never hits at billing time.
func TestBuildCostMeterConfig_BedrockModelNormalization(t *testing.T) {
	bedrock := &types.Provider{
		ID:         "prov-bedrock",
		ProviderID: "bedrock_api",
		Enabled:    true,
		Models: []types.ProviderModel{
			{ID: "eu.anthropic.claude-sonnet-4-5-20250929-v1:0", InputPer1k: 0.0033, OutputPer1k: 0.0165},
			// Post-normalization duplicate of the row above under a
			// different regional spelling — first occurrence wins.
			{ID: "us.anthropic.claude-sonnet-4-5-20250929-v1:0", InputPer1k: 9.9, OutputPer1k: 9.9},
		},
	}
	raw, err := buildCostMeterConfigJSON([]*types.Provider{bedrock}, map[string][]string{"prov-bedrock": {"grp"}})
	require.NoError(t, err)
	cfg := decodeCostMeterConfig(t, raw)

	models := cfg.Pricing.Providers["prov-bedrock"]
	require.Len(t, models, 1, "both spellings normalize to one model; first row wins")
	e, ok := models["anthropic.claude-sonnet-4-5"]
	require.True(t, ok, "key must be the normalized id the parser emits, not the operator's raw spelling")
	assert.InDelta(t, 0.0033, e.InputPer1k, 1e-9, "first row's rate wins the dedup")
	assert.InDelta(t, 0.0003, e.CacheReadPer1k, 1e-9, "cache read inherited from the bedrock default entry")
	assert.InDelta(t, 0.00375, e.CacheCreationPer1k, 1e-9, "cache creation inherited from the bedrock default entry")
}

// TestBuildCostMeterConfig_CacheRateNilVsZero pins the pointer semantics:
// nil inherits the default cache rate, explicit 0 clears it (that bucket
// bills at the input rate on the proxy).
func TestBuildCostMeterConfig_CacheRateNilVsZero(t *testing.T) {
	p := &types.Provider{
		ID:         "prov-oai",
		ProviderID: "openai_api",
		Enabled:    true,
		Models: []types.ProviderModel{
			{ID: "gpt-4o", InputPer1k: 0.002, OutputPer1k: 0.008},                                    // nil → inherit 0.00125
			{ID: "gpt-4o-mini", InputPer1k: 0.0001, OutputPer1k: 0.0005, CachedInputPer1k: fptr(0)},  // explicit 0 → no discount
			{ID: "my-custom-ft", InputPer1k: 0.01, OutputPer1k: 0.02, CachedInputPer1k: fptr(0.005)}, // unknown model, explicit rate
		},
	}
	raw, err := buildCostMeterConfigJSON([]*types.Provider{p}, map[string][]string{"prov-oai": {"grp"}})
	require.NoError(t, err)
	cfg := decodeCostMeterConfig(t, raw)
	models := cfg.Pricing.Providers["prov-oai"]

	assert.InDelta(t, 0.00125, models["gpt-4o"].CachedInputPer1k, 1e-9, "nil cache pointer inherits the default rate")
	assert.Zero(t, models["gpt-4o-mini"].CachedInputPer1k, "explicit 0 overrides the default (0.000075) — bucket bills at input rate")
	custom := models["my-custom-ft"]
	assert.InDelta(t, 0.005, custom.CachedInputPer1k, 1e-9, "unknown model keeps the operator's explicit cache rate")
	assert.Zero(t, custom.CacheReadPer1k, "no default to inherit for a model outside the catalog")
}

// TestBuildCostMeterConfig_OrphanAndGatewayProviders: an orphan (no
// authorising policy) is unreachable so its prices must not ship; a
// gateway with no model rows relies on the defaults table and gets no
// per-record entry.
func TestBuildCostMeterConfig_OrphanAndGatewayProviders(t *testing.T) {
	orphan := &types.Provider{
		ID:         "prov-orphan",
		ProviderID: "openai_api",
		Enabled:    true,
		Models:     []types.ProviderModel{{ID: "gpt-4o", InputPer1k: 1, OutputPer1k: 1}},
	}
	gateway := &types.Provider{
		ID:         "prov-litellm",
		ProviderID: "litellm_proxy",
		Enabled:    true,
		Models:     []types.ProviderModel{},
	}
	raw, err := buildCostMeterConfigJSON(
		[]*types.Provider{orphan, gateway},
		map[string][]string{"prov-litellm": {"grp"}}, // orphan has no policy
	)
	require.NoError(t, err)
	cfg := decodeCostMeterConfig(t, raw)

	assert.NotContains(t, cfg.Pricing.Providers, "prov-orphan", "orphan provider prices must not ship")
	assert.NotContains(t, cfg.Pricing.Providers, "prov-litellm", "empty-models gateway needs no per-record entry")
	assert.NotEmpty(t, cfg.Pricing.Defaults["openai"], "defaults still ship so the gateway's catalog-model traffic is priced")
}
