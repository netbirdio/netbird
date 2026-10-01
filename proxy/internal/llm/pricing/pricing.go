// Package pricing implements the pricing table and cost formula the
// cost_meter middleware uses to convert LLM token usage into a USD cost
// estimate. The table's content arrives from the management server inside
// cost_meter's middleware config (synthesized from the catalog plus the
// operator's stored per-provider prices) — the proxy carries no embedded
// price list. Price updates ride the ordinary mapping push: a chain
// rebuild constructs a fresh table, so there is nothing to reload.
package pricing

import (
	"fmt"
	"math"

	sharedllm "github.com/netbirdio/netbird/shared/llm"
)

// Entry is a single model's input and output pricing, expressed in USD per
// 1000 tokens.
//
// CachedInputPer1K applies to OpenAI's cached prompt tokens, which are a
// subset of input_tokens — when set, the cached portion is billed at this
// rate and the non-cached remainder at InputPer1K. Zero means "no discount
// configured", and cached tokens are billed at InputPer1K.
//
// CacheReadPer1K and CacheCreationPer1K apply to Anthropic's two prompt-
// cache fields, which are additive to input_tokens: cache_read is the
// cheaper read-from-cache rate, cache_creation is the more expensive
// write-to-cache rate. Zero means "no rate configured" and the
// corresponding token bucket is billed at InputPer1K.
type Entry struct {
	InputPer1K         float64
	OutputPer1K        float64
	CachedInputPer1K   float64
	CacheReadPer1K     float64
	CacheCreationPer1K float64
}

// EntryJSON is the wire shape of a pricing entry inside cost_meter's
// middleware config. Field names are the management→proxy contract; the
// management synthesizer marshals the same names (its pricing.Entry).
type EntryJSON struct {
	InputPer1K         float64 `json:"input_per_1k"`
	OutputPer1K        float64 `json:"output_per_1k"`
	CachedInputPer1K   float64 `json:"cached_input_per_1k"`
	CacheReadPer1K     float64 `json:"cache_read_per_1k"`
	CacheCreationPer1K float64 `json:"cache_creation_per_1k"`
}

// Table is a provider-surface-to-model pricing lookup. Instances are
// immutable once built; a mapping update builds a whole new middleware
// instance (and with it a new table) rather than mutating this one.
type Table struct {
	entries map[string]map[string]Entry
}

// NewEntries validates and converts a wire-shape map (surface-or-record ->
// model -> rates) into the internal representation. Every rate must be a
// finite, non-negative USD amount; a violation is returned as an error so
// a corrupt config fails the chain build loudly instead of mispricing.
// Management validates the same constraints at its API boundary, so this
// is defense-in-depth. Nil input yields an empty (never-matching) map.
func NewEntries(raw map[string]map[string]EntryJSON) (map[string]map[string]Entry, error) {
	out := make(map[string]map[string]Entry, len(raw))
	for outer, models := range raw {
		inner := make(map[string]Entry, len(models))
		for model, e := range models {
			for field, v := range map[string]float64{
				"input_per_1k":          e.InputPer1K,
				"output_per_1k":         e.OutputPer1K,
				"cached_input_per_1k":   e.CachedInputPer1K,
				"cache_read_per_1k":     e.CacheReadPer1K,
				"cache_creation_per_1k": e.CacheCreationPer1K,
			} {
				if v < 0 || math.IsNaN(v) || math.IsInf(v, 0) {
					return nil, fmt.Errorf("pricing %s/%s: %s must be a finite, non-negative rate, got %v", outer, model, field, v)
				}
			}
			// EntryJSON and Entry are field-identical (tags aside), so a
			// direct conversion carries all five rates.
			inner[model] = Entry(e)
		}
		out[outer] = inner
	}
	return out, nil
}

// NewTable builds an immutable Table from the wire-shape defaults map.
// See NewEntries for validation semantics.
func NewTable(raw map[string]map[string]EntryJSON) (*Table, error) {
	entries, err := NewEntries(raw)
	if err != nil {
		return nil, err
	}
	return &Table{entries: entries}, nil
}

// Lookup returns the entry for the given provider surface and model. A
// dated Anthropic id falls back to its undated form, so a client pinning
// "claude-sonnet-4-5-20250929" bills at the registered "claude-sonnet-4-5"
// rate instead of recording no cost at all.
func (t *Table) Lookup(provider, model string) (Entry, bool) {
	if t == nil {
		return Entry{}, false
	}
	byModel, ok := t.entries[provider]
	if !ok {
		return Entry{}, false
	}
	if e, found := byModel[model]; found {
		return e, true
	}
	undated := sharedllm.NormalizeAnthropicModel(model)
	if undated == model {
		return Entry{}, false
	}
	e, ok := byModel[undated]
	return e, ok
}

// Has reports whether the provider/model pair is present in the table.
func (t *Table) Has(provider, model string) bool {
	_, ok := t.Lookup(provider, model)
	return ok
}

// Cost returns the estimated USD cost for the given token counts. ok is
// false when the provider or model is not present in the table; the caller
// can still emit token metrics with a model=unknown label.
func (t *Table) Cost(provider, model string, inTokens, outTokens, cachedInput, cacheCreation int64) (float64, bool) {
	c, ok := t.Costs(provider, model, inTokens, outTokens, cachedInput, cacheCreation)
	return c.TotalUSD, ok
}

// Costs returns the estimated USD cost split for the given token counts.
// The provider surface selects the cache formula; see EntryCosts.
func (t *Table) Costs(provider, model string, inTokens, outTokens, cachedInput, cacheCreation int64) (Costs, bool) {
	entry, ok := t.Lookup(provider, model)
	if !ok {
		return Costs{}, false
	}
	return EntryCosts(entry, provider, inTokens, outTokens, cachedInput, cacheCreation), true
}

// Costs is a per-request cost split. The four per-bucket fields are the base
// of the breakdown — one per token bucket the provider bills separately — and
// the two aggregates are derived from them:
//
//	TotalUSD = InputUSD + CachedInputUSD + CacheCreationUSD + OutputUSD
//	CacheUSD = CachedInputUSD + CacheCreationUSD
//
// InputUSD is always the cost of the *non-cached* input bucket, for both
// provider shapes: on OpenAI the cached subset is carved out of inTokens and
// billed as CachedInputUSD, so the two never double-count. Buckets a provider
// doesn't bill are zero, which keeps the identities above true everywhere.
type Costs struct {
	InputUSD         float64
	CachedInputUSD   float64
	CacheCreationUSD float64
	OutputUSD        float64
	TotalUSD         float64
	CacheUSD         float64
}

// newCosts assembles a split from its per-bucket parts, deriving the two
// aggregates so TotalUSD and CacheUSD can never drift from the breakdown.
func newCosts(input, cachedInput, cacheCreation, output float64) Costs {
	return Costs{
		InputUSD:         input,
		CachedInputUSD:   cachedInput,
		CacheCreationUSD: cacheCreation,
		OutputUSD:        output,
		TotalUSD:         input + cachedInput + cacheCreation + output,
		CacheUSD:         cachedInput + cacheCreation,
	}
}

// EntryCosts computes the USD cost split for the given entry and token
// counts. The surface (the llm.provider value the request parser stamps)
// selects the cache formula; the entry may come from the surface-keyed
// defaults table or from a per-provider-record override — the math is
// identical either way.
//
// Provider-shape semantics for cached / cache-creation counts:
//
//   - "openai": cachedInput is a SUBSET of inTokens. The cached portion is
//     billed at CachedInputPer1K (or InputPer1K when no override), and the
//     non-cached remainder of inTokens at InputPer1K. cacheCreation is
//     ignored (OpenAI has no analogue).
//   - "anthropic", "bedrock": cachedInput (cache_read) and cacheCreation are
//     ADDITIVE to inTokens. The three buckets are billed at CacheReadPer1K,
//     CacheCreationPer1K, and InputPer1K respectively, each falling back
//     to InputPer1K when the corresponding rate is zero.
//   - Other surfaces: cached and cacheCreation are ignored; cost is
//     inTokens*InputPer1K + outTokens*OutputPer1K.
func EntryCosts(entry Entry, surface string, inTokens, outTokens, cachedInput, cacheCreation int64) Costs {
	// Clamp negatives to zero before any pricing math so a malformed
	// upstream count can never produce a negative cost.
	if inTokens < 0 {
		inTokens = 0
	}
	if outTokens < 0 {
		outTokens = 0
	}
	if cachedInput < 0 {
		cachedInput = 0
	}
	if cacheCreation < 0 {
		cacheCreation = 0
	}
	output := (float64(outTokens) / 1000.0) * entry.OutputPer1K
	switch surface {
	case "openai":
		// cachedInput is a subset of inTokens; clamp so a malformed
		// upstream (cached > total) can't produce a negative remainder.
		clamped := cachedInput
		if clamped > inTokens {
			clamped = inTokens
		}
		cachedRate := entry.CachedInputPer1K
		if cachedRate <= 0 {
			cachedRate = entry.InputPer1K
		}
		nonCached := float64(inTokens-clamped) / 1000.0 * entry.InputPer1K
		cached := float64(clamped) / 1000.0 * cachedRate
		return newCosts(nonCached, cached, 0, output)
	case "anthropic", "bedrock":
		// Bedrock-Anthropic returns the same additive cache buckets as
		// first-party Anthropic; non-Anthropic Bedrock models simply report
		// zero cache tokens, so this formula degrades to input + output.
		readRate := entry.CacheReadPer1K
		if readRate <= 0 {
			readRate = entry.InputPer1K
		}
		createRate := entry.CacheCreationPer1K
		if createRate <= 0 {
			createRate = entry.InputPer1K
		}
		input := float64(inTokens) / 1000.0 * entry.InputPer1K
		read := float64(cachedInput) / 1000.0 * readRate
		create := float64(cacheCreation) / 1000.0 * createRate
		return newCosts(input, read, create, output)
	default:
		input := float64(inTokens) / 1000.0 * entry.InputPer1K
		return newCosts(input, 0, 0, output)
	}
}
