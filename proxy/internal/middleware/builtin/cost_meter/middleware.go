// Package cost_meter implements the SlotOnResponse middleware that
// converts token-usage metadata emitted by llm_response_parser into a
// per-request USD cost estimate. Pricing arrives from management inside
// the middleware config: a per-provider-record table (the operator's
// stored prices, matched via llm.resolved_provider_id) consulted first,
// then the surface-keyed defaults table.
package cost_meter

import (
	"context"
	"fmt"
	"strconv"

	"github.com/netbirdio/netbird/proxy/internal/llm"
	"github.com/netbirdio/netbird/proxy/internal/llm/pricing"
	"github.com/netbirdio/netbird/proxy/internal/middleware"
)

// ID is the registry identifier for this middleware.
const ID = "cost_meter"

// Version is the implementation version emitted via the spec merge.
// 1.1.0: pricing is config-delivered (defaults + per-provider-record
// entries) instead of proxy-embedded.
const Version = "1.1.0"

// Skip reasons emitted under KeyCostSkipped. The set is closed; the
// dashboard surfaces these verbatim.
const (
	skipMissingProvider = "missing_provider"
	skipMissingModel    = "missing_model"
	skipMissingTokens   = "missing_tokens"
	//nolint:gosec // skip-reason label, not a credential
	skipUnparseableTokens = "unparseable_tokens"
	skipZeroTokens        = "zero_tokens"
	skipUnknownModel      = "unknown_model"
)

var metadataKeys = []string{
	middleware.KeyCostUSDInput,
	middleware.KeyCostUSDCachedInput,
	middleware.KeyCostUSDCacheCreation,
	middleware.KeyCostUSDOutput,
	middleware.KeyCostUSDTotal,
	middleware.KeyCostUSDCache,
	middleware.KeyCostSkipped,
}

// Middleware computes a per-response cost estimate from the token
// counts emitted upstream by llm_response_parser. Both tables are
// immutable — a pricing change arrives as a mapping push that rebuilds
// the chain with a fresh instance.
type Middleware struct {
	// defaults is the surface-keyed table (llm.provider x llm.model).
	defaults *pricing.Table
	// perRecord is keyed by provider record id (llm.resolved_provider_id)
	// then normalized model id; entries arrive fully materialized from
	// management. Consulted before defaults. May be nil.
	perRecord map[string]map[string]pricing.Entry
}

// newMiddleware constructs a Middleware over the given pricing tables.
func newMiddleware(defaults *pricing.Table, perRecord map[string]map[string]pricing.Entry) *Middleware {
	return &Middleware{defaults: defaults, perRecord: perRecord}
}

// ID returns the registry identifier.
func (m *Middleware) ID() string { return ID }

// Version returns the implementation version.
func (m *Middleware) Version() string { return Version }

// Slot reports that the middleware runs after the upstream call.
func (m *Middleware) Slot() middleware.Slot { return middleware.SlotOnResponse }

// AcceptedContentTypes is empty: cost_meter never inspects bodies.
func (m *Middleware) AcceptedContentTypes() []string { return []string{} }

// MetadataKeys returns the closed allowlist of keys this middleware
// may emit.
func (m *Middleware) MetadataKeys() []string {
	return append([]string(nil), metadataKeys...)
}

// MutationsSupported reports that this middleware never mutates the
// response.
func (m *Middleware) MutationsSupported() bool { return false }

// Close releases resources owned by the middleware. Stateless — the
// pricing tables are plain maps owned by this instance.
func (m *Middleware) Close() error { return nil }

// Invoke reads provider, model, and token metadata, looks up pricing,
// and emits either KeyCostUSDTotal or KeyCostSkipped. The decision is
// always DecisionAllow; cost metering never denies or mutates.
func (m *Middleware) Invoke(_ context.Context, in *middleware.Input) (*middleware.Output, error) {
	out := &middleware.Output{Decision: middleware.DecisionAllow}
	if in == nil {
		return out, nil
	}

	provider := lookupKV(in.Metadata, middleware.KeyLLMProvider)
	if provider == "" {
		out.Metadata = skip(skipMissingProvider)
		return out, nil
	}

	model := lookupKV(in.Metadata, middleware.KeyLLMModel)
	if model == "" {
		out.Metadata = skip(skipMissingModel)
		return out, nil
	}

	inRaw, hasIn := lookupKVOK(in.Metadata, middleware.KeyLLMInputTokens)
	outRaw, hasOut := lookupKVOK(in.Metadata, middleware.KeyLLMOutputTokens)
	if !hasIn || !hasOut {
		out.Metadata = skip(skipMissingTokens)
		return out, nil
	}

	inTokens, err := strconv.ParseInt(inRaw, 10, 64)
	if err != nil || inTokens < 0 {
		// Unparseable or negative tokens are not a runtime error: the
		// upstream llm_response_parser emitted a non-numeric / invalid
		// value, so we surface that as cost.skipped and continue with
		// Allow rather than pricing a negative count.
		out.Metadata = skip(skipUnparseableTokens)
		return out, nil //nolint:nilerr // structured skip; not a runtime error
	}
	outTokens, err := strconv.ParseInt(outRaw, 10, 64)
	if err != nil || outTokens < 0 {
		out.Metadata = skip(skipUnparseableTokens)
		return out, nil //nolint:nilerr // structured skip; not a runtime error
	}

	// Cache buckets are optional and silently zeroed on a missing /
	// malformed value; they're a refinement on top of input cost,
	// not a precondition. A buggy value falls back to 0, never aborts.
	cachedTokens := parseOptionalInt64(in.Metadata, middleware.KeyLLMCachedInputTokens)
	cacheCreationTokens := parseOptionalInt64(in.Metadata, middleware.KeyLLMCacheCreationTokens)

	if inTokens == 0 && outTokens == 0 && cachedTokens == 0 && cacheCreationTokens == 0 {
		out.Metadata = skip(skipZeroTokens)
		return out, nil
	}

	costs, ok := m.lookupCosts(in.Metadata, provider, model, inTokens, outTokens, cachedTokens, cacheCreationTokens)
	if !ok {
		out.Metadata = skip(skipUnknownModel)
		return out, nil
	}

	// Per-bucket costs first: they're the base of the breakdown, and the two
	// aggregates that follow are derived from exactly these four values.
	out.Metadata = []middleware.KV{
		{Key: middleware.KeyCostUSDInput, Value: usd(costs.InputUSD)},
		{Key: middleware.KeyCostUSDCachedInput, Value: usd(costs.CachedInputUSD)},
		{Key: middleware.KeyCostUSDCacheCreation, Value: usd(costs.CacheCreationUSD)},
		{Key: middleware.KeyCostUSDOutput, Value: usd(costs.OutputUSD)},
		{Key: middleware.KeyCostUSDTotal, Value: usd(costs.TotalUSD)},
		{Key: middleware.KeyCostUSDCache, Value: usd(costs.CacheUSD)},
	}
	return out, nil
}

// lookupCosts resolves the price for this request and computes the cost
// split. Resolution order:
//
//  1. Per-provider-record entry: the operator's stored price for the
//     provider route that served the request, keyed by the
//     llm.resolved_provider_id metadata llm_router stamped on the allow
//     path. Absent metadata (e.g. no router in the chain) skips this tier.
//  2. Surface defaults: the catalog-derived table keyed by llm.provider.
//
// The surface always selects the cache formula — a per-record entry for an
// Anthropic route still bills its cache buckets additively.
func (m *Middleware) lookupCosts(md []middleware.KV, surface, model string, inTokens, outTokens, cachedTokens, cacheCreationTokens int64) (pricing.Costs, bool) {
	if recordID := lookupKV(md, middleware.KeyLLMResolvedProviderID); recordID != "" {
		if entry, ok := perRecordEntry(m.perRecord[recordID], model); ok {
			return pricing.EntryCosts(entry, surface, inTokens, outTokens, cachedTokens, cacheCreationTokens), true
		}
	}
	return m.defaults.Costs(surface, model, inTokens, outTokens, cachedTokens, cacheCreationTokens)
}

// perRecordEntry resolves the operator's stored price for a model on one
// provider record, falling back to the undated form of a dated Anthropic id
// so a client that pins a release date still bills at the registered rate.
func perRecordEntry(byModel map[string]pricing.Entry, model string) (pricing.Entry, bool) {
	if entry, ok := byModel[model]; ok {
		return entry, true
	}
	undated := llm.NormalizeAnthropicModel(model)
	if undated == model {
		return pricing.Entry{}, false
	}
	entry, ok := byModel[undated]
	return entry, ok
}

// usd renders a cost as the fixed-precision string every cost.usd_* key
// carries, so the per-bucket values and the aggregates round identically.
//
// 9 decimals, not 6: these values are summed downstream — per request, per
// session, and per usage bucket — so the rounding step is applied once per
// bucket per row and then accumulated. At 6 decimals a single row loses up to
// 2e-6 across its four buckets (enough to break a 1e-6 reconciliation against
// published rates), and a bucket smaller than half a microdollar quantises to
// zero outright: 16 cache-read tokens on a cheap model is 1.6e-9, so summing
// 10k such rows reports 0.02 instead of 0.016. Nano-dollar precision keeps the
// per-row error ~1000x below the smallest realistic bucket.
func usd(v float64) string { return fmt.Sprintf("%.9f", v) }

// skip returns a single-entry metadata slice carrying the given skip
// reason under KeyCostSkipped.
func skip(reason string) []middleware.KV {
	return []middleware.KV{{Key: middleware.KeyCostSkipped, Value: reason}}
}

// lookupKV returns the value associated with key, or the empty string
// when the key is absent.
func lookupKV(kvs []middleware.KV, key string) string {
	v, _ := lookupKVOK(kvs, key)
	return v
}

// lookupKVOK returns the value associated with key plus a presence
// flag so callers can distinguish absent from empty.
func lookupKVOK(kvs []middleware.KV, key string) (string, bool) {
	for _, kv := range kvs {
		if kv.Key == key {
			return kv.Value, true
		}
	}
	return "", false
}

// parseOptionalInt64 reads a metadata value and decodes it as int64.
// Absent or unparseable values yield 0 — the caller treats absence as
// "no cached tokens" rather than an error, since cache buckets are a
// refinement, not a precondition.
func parseOptionalInt64(kvs []middleware.KV, key string) int64 {
	raw, ok := lookupKVOK(kvs, key)
	if !ok {
		return 0
	}
	v, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || v < 0 {
		return 0
	}
	return v
}
