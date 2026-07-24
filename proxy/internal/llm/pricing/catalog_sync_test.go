package pricing

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/management/internals/modules/agentnetwork/catalog"
)

// catalogPricingProviders maps each metered catalog provider id to the
// pricing-table provider key(s) its requests are billed under (the
// llm.Parser surface the proxy meters that provider with). A catalog
// provider whose requests can hit more than one parser surface (Kimi
// serves both the OpenAI and Anthropic body shapes off one host) must
// carry matching entries in every listed table.
//
// Gateway/custom catalog entries (LiteLLM, Portkey, vLLM, …) publish no
// model list, so they never appear here.
var catalogPricingProviders = map[string][]string{
	"openai_api":       {"openai"},
	"azure_openai_api": {"openai"},
	"mistral_api":      {"openai"},
	"anthropic_api":    {"anthropic"},
	"vertex_ai_api":    {"anthropic"}, // Anthropic-on-Vertex: bare claude-* ids, anthropic parser
	"bedrock_api":      {"bedrock"},
	"kimi_api":         {"openai", "anthropic"},
}

// TestDefaultPricing_MatchesCatalog pins the management catalog (the prices
// the dashboard displays) to the proxy's embedded default pricing table (the
// prices the cost meter bills). A drift between the two makes correct costs
// look wrong — the dashboard advertises one rate while the proxy meters
// another — so every catalog model must resolve to a pricing entry with
// byte-identical input/output per-1k rates.
func TestDefaultPricing_MatchesCatalog(t *testing.T) {
	table := DefaultTable()

	for _, p := range catalog.All() {
		if len(p.Models) == 0 {
			continue // gateways / custom endpoints publish no models
		}
		keys, metered := catalogPricingProviders[p.ID]
		require.Truef(t, metered,
			"catalog provider %q publishes models but has no pricing-table mapping — add it to catalogPricingProviders and defaults_pricing.yaml",
			p.ID)

		for _, m := range p.Models {
			for _, key := range keys {
				entry, ok := table.entries[key][m.ID]
				require.Truef(t, ok,
					"catalog model %s/%s must have a %q pricing entry or the cost meter silently skips it (cost.skipped=unknown_model)",
					p.ID, m.ID, key)
				assert.Equalf(t, m.InputPer1k, entry.InputPer1K,
					"input rate drift for %s/%s: dashboard shows %v, proxy bills %v", p.ID, m.ID, m.InputPer1k, entry.InputPer1K)
				assert.Equalf(t, m.OutputPer1k, entry.OutputPer1K,
					"output rate drift for %s/%s: dashboard shows %v, proxy bills %v", p.ID, m.ID, m.OutputPer1k, entry.OutputPer1K)
			}
		}
	}
}
