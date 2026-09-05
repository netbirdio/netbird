// Package pricing builds the default LLM pricing table the synthesizer
// ships to the proxy's cost_meter middleware. The catalog is the single
// source of default rates: every catalog provider's models are folded
// into the pricing surfaces the provider declares (PricingSurfaces),
// then a small supplemental list adds priced-but-not-operator-selectable
// entries. Management is the sole pricing authority — the proxy carries
// no embedded price list and bills exclusively from the table it is
// sent.
//go:generate go run gen.go

package pricing

import (
	"sync"
	"sync/atomic"

	"github.com/netbirdio/netbird/management/internals/modules/agentnetwork/catalog"
)

// Entry is a single model's pricing in USD per 1k tokens. This struct IS
// the wire shape: the synthesizer marshals it verbatim into cost_meter's
// ConfigJSON, and the proxy unmarshals the same field names.
//
// A zero rate means "no rate configured" — the proxy bills that cache
// bucket at InputPer1k (identical semantics to the retired proxy-embedded
// table). CachedInputPer1k is the OpenAI shape (cached prompt tokens are
// a subset of input); CacheReadPer1k / CacheCreationPer1k are the
// Anthropic shape (additive buckets).
type Entry struct {
	InputPer1k         float64 `json:"input_per_1k"`
	OutputPer1k        float64 `json:"output_per_1k"`
	CachedInputPer1k   float64 `json:"cached_input_per_1k,omitempty"`
	CacheReadPer1k     float64 `json:"cache_read_per_1k,omitempty"`
	CacheCreationPer1k float64 `json:"cache_creation_per_1k,omitempty"`
}

// supplementalDefaults are (surface, model) entries that are priced but
// deliberately not operator-selectable in the catalog. Each carries a
// reason; when one of these models joins a catalog lineup, delete the
// row here — the collision test fails loudly if the rates ever disagree.
var supplementalDefaults = map[string]map[string]Entry{
	"openai": {
		// GPT-5 (2025) family — kept for gateway requests using the
		// unsuffixed ids; the dashboard offers only the 5.x lineup.
		"gpt-5":      {InputPer1k: 0.00125, OutputPer1k: 0.01, CachedInputPer1k: 0.000125},
		"gpt-5-mini": {InputPer1k: 0.00025, OutputPer1k: 0.002, CachedInputPer1k: 0.000025},
		"gpt-5-nano": {InputPer1k: 0.00005, OutputPer1k: 0.0004, CachedInputPer1k: 0.000005},
	},
	"anthropic": {
		// "kimi-k3[1m]" is the 1M-context alias some Claude Code guides
		// configure against Moonshot's Anthropic-compatible endpoint;
		// priced identically to kimi-k3 so those requests aren't skipped.
		"kimi-k3[1m]": {InputPer1k: 0.003, OutputPer1k: 0.015, CacheReadPer1k: 0.0003},
	},
}

var (
	compiledOnce  sync.Once
	compiledTable map[string]map[string]Entry
	// mergedTable holds the current live table when a pricing defaults
	// file is loaded: the file merged entry-whole over the compiled-in
	// base. Nil while no file is loaded (or after the file is removed),
	// in which case the compiled-in table serves. Swapped atomically by
	// the file loader/reloader; readers never block.
	mergedTable atomic.Pointer[map[string]map[string]Entry]
)

// DefaultTable returns the current default pricing table keyed
// surface -> model -> Entry: the management-side defaults file (see
// LoadFile / StartReloader) when one is loaded, merged over the
// compiled-in catalog table, which alone serves as the fallback when no
// file exists. The snapshot may change between calls as the file is
// re-read — consumers (the synthesizer on every reconcile, the catalog
// endpoint on every request) pick up fresh rates automatically. Callers
// must not mutate the returned maps.
func DefaultTable() map[string]map[string]Entry {
	if t := mergedTable.Load(); t != nil {
		return *t
	}
	return compiledBase()
}

// compiledBase returns the compiled-in table (catalog + supplementals),
// built once.
func compiledBase() map[string]map[string]Entry {
	compiledOnce.Do(func() {
		compiledTable = buildDefaultTable()
	})
	return compiledTable
}

func buildDefaultTable() map[string]map[string]Entry {
	out := make(map[string]map[string]Entry)
	for _, p := range catalog.All() {
		for _, surface := range p.PricingSurfaces {
			inner, ok := out[surface]
			if !ok {
				inner = make(map[string]Entry)
				out[surface] = inner
			}
			for _, m := range p.Models {
				// First writer wins; providers contributing the same
				// (surface, model) must agree on rates — enforced by
				// TestDefaultTable_NoConflictingContributions.
				if _, dup := inner[m.ID]; dup {
					continue
				}
				inner[m.ID] = entryFromCatalogModel(m)
			}
		}
	}
	for surface, models := range supplementalDefaults {
		inner, ok := out[surface]
		if !ok {
			inner = make(map[string]Entry)
			out[surface] = inner
		}
		for id, e := range models {
			if _, dup := inner[id]; dup {
				continue
			}
			inner[id] = e
		}
	}
	return out
}

func entryFromCatalogModel(m catalog.Model) Entry {
	return Entry{
		InputPer1k:         m.InputPer1k,
		OutputPer1k:        m.OutputPer1k,
		CachedInputPer1k:   m.CachedInputPer1k,
		CacheReadPer1k:     m.CacheReadPer1k,
		CacheCreationPer1k: m.CacheCreationPer1k,
	}
}

// LookupDefault returns the default entry for model on the first of the
// given surfaces that prices it. Used by the synthesizer to seed a
// per-provider entry with default cache rates before overlaying the
// operator's stored prices.
func LookupDefault(surfaces []string, model string) (Entry, bool) {
	table := DefaultTable()
	for _, s := range surfaces {
		if e, ok := table[s][model]; ok {
			return e, true
		}
	}
	return Entry{}, false
}
