package agentnetwork

import (
	"encoding/json"
	"fmt"

	"github.com/netbirdio/netbird/management/internals/modules/agentnetwork/catalog"
	"github.com/netbirdio/netbird/management/internals/modules/agentnetwork/pricing"
	"github.com/netbirdio/netbird/management/internals/modules/agentnetwork/types"
	sharedllm "github.com/netbirdio/netbird/shared/llm"
)

// costMeterConfig is the JSON shape the proxy-side cost_meter middleware
// expects (mirror-type pattern, same as routerConfig). The top-level
// "pricing" wrapper is the feature-detection signal: an old proxy's config
// struct ignores it as an unknown field, and a new proxy treats its
// absence as "old management" (skips every cost computation and warns).
type costMeterConfig struct {
	Pricing *costMeterPricing `json:"pricing,omitempty"`
}

// costMeterPricing carries the full pricing table:
//   - Defaults: surface ("openai"/"anthropic"/"bedrock") -> normalized
//     model id -> rates. The full default table ships to every account —
//     it is small (~10 KB) and keeps gateway-style providers (which
//     enumerate no models) priced for every catalog model.
//   - Providers: provider record id (matched against the
//     llm.resolved_provider_id metadata llm_router stamps) -> normalized
//     model id -> rates. Entries are fully materialized here at synth
//     time — default cache rates already folded in — so the proxy does
//     two map lookups and no merging.
type costMeterPricing struct {
	Defaults  map[string]map[string]pricing.Entry `json:"defaults,omitempty"`
	Providers map[string]map[string]pricing.Entry `json:"providers,omitempty"`
}

// buildCostMeterConfigJSON assembles the cost_meter middleware config
// from the default pricing table plus the operator's stored per-provider
// model prices. Same orphan rule as the router: a provider no enabled
// policy authorises is unreachable, so its prices are not shipped.
//
// Overlay semantics per model row:
//   - The row's model id is normalized exactly the way the proxy's
//     request parser normalizes the ids it meters (bedrock ARN/region/
//     version stripping, vertex "@version" stripping), so the per-record
//     lookup key compares equal to llm.model at billing time.
//   - The entry starts from the default entry for that model (when one
//     exists) to inherit cache rates the operator didn't state.
//   - Operator input/output overlay verbatim — including an explicit 0,
//     which prices the model as free (self-hosted / internal endpoints)
//     rather than silently reverting to list price.
//   - Cache-rate pointers overlay only when non-nil: nil means "inherit
//     the default", an explicit 0 means "no discount, bill this bucket
//     at the input rate".
func buildCostMeterConfigJSON(providers []*types.Provider, groupIndex map[string][]string) ([]byte, error) {
	cfg := costMeterConfig{Pricing: &costMeterPricing{
		Defaults: pricing.DefaultTable(),
	}}

	perRecord := make(map[string]map[string]pricing.Entry)
	for _, p := range providers {
		if _, hasPolicy := groupIndex[p.ID]; !hasPolicy {
			// Orphan: unreachable via the router, so unpriceable.
			continue
		}
		if len(p.Models) == 0 {
			// Gateway-style "claim every model" provider: the defaults
			// table is its price list.
			continue
		}
		entry, _ := catalog.Lookup(p.ProviderID)
		models := make(map[string]pricing.Entry, len(p.Models))
		for _, m := range p.Models {
			id := normalizePricingModelID(p.ProviderID, m.ID)
			if id == "" {
				continue
			}
			if _, dup := models[id]; dup {
				// First occurrence wins on post-normalization duplicates,
				// matching providerModelIDs' dedup order for routing.
				continue
			}
			models[id] = materializeEntry(entry.PricingSurfaces, id, m)
		}
		if len(models) > 0 {
			perRecord[p.ID] = models
		}
	}
	if len(perRecord) > 0 {
		cfg.Pricing.Providers = perRecord
	}

	out, err := json.Marshal(cfg)
	if err != nil {
		return nil, fmt.Errorf("marshal cost_meter middleware config: %w", err)
	}
	return out, nil
}

// normalizePricingModelID maps an operator-entered model id onto the
// normalized id the proxy's request parser emits as llm.model — the key
// the cost meter looks up at billing time.
func normalizePricingModelID(catalogProviderID, modelID string) string {
	switch {
	case catalog.IsBedrockPathStyle(catalogProviderID):
		return sharedllm.NormalizeBedrockModel(modelID)
	case catalog.IsVertexPathStyle(catalogProviderID):
		return sharedllm.NormalizeVertexModel(modelID)
	default:
		return modelID
	}
}

// materializeEntry folds the default entry for (surfaces, model) — when
// one exists — under the operator's stored prices, producing the fully
// materialized wire entry.
func materializeEntry(surfaces []string, normalizedID string, m types.ProviderModel) pricing.Entry {
	e, _ := pricing.LookupDefault(surfaces, normalizedID) // zero Entry on miss
	e.InputPer1k = m.InputPer1k
	e.OutputPer1k = m.OutputPer1k
	if m.CachedInputPer1k != nil {
		e.CachedInputPer1k = *m.CachedInputPer1k
	}
	if m.CacheReadPer1k != nil {
		e.CacheReadPer1k = *m.CacheReadPer1k
	}
	if m.CacheCreationPer1k != nil {
		e.CacheCreationPer1k = *m.CacheCreationPer1k
	}
	return e
}
