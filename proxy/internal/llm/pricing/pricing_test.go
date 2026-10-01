package pricing

import (
	"math"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestCost_OpenAICachedSubsetDiscount proves OpenAI's cached input
// tokens are billed at the configured cached_input_per_1k rate while
// the non-cached remainder of input_tokens is billed at the regular
// rate. Critical because OpenAI returns cached_tokens as a SUBSET of
// prompt_tokens — naïvely charging the cached count on top of
// prompt_tokens would double-bill that portion.
func TestCost_OpenAICachedSubsetDiscount(t *testing.T) {
	tbl := &Table{entries: map[string]map[string]Entry{
		"openai": {"gpt-4o": {
			InputPer1K:       0.0025, // 0.0025 USD per 1k input tokens
			OutputPer1K:      0.01,
			CachedInputPer1K: 0.00125, // 0.5x discount on cached
		}},
	}}
	// 1000 prompt tokens, 750 of which were cached. 250 non-cached
	// at regular rate, 750 cached at the discount rate, 500 output.
	cost, ok := tbl.Cost("openai", "gpt-4o", 1000, 500, 750, 0)
	require.True(t, ok, "known model resolves")
	want := (250.0/1000.0)*0.0025 + (750.0/1000.0)*0.00125 + (500.0/1000.0)*0.01
	assert.InDelta(t, want, cost, 1e-12,
		"cached subset must bill at the discount rate; non-cached remainder at regular rate")
}

// TestCost_OpenAICachedFallsBackToInputRate covers the fallback
// contract: when CachedInputPer1K is unset (zero), cached tokens bill
// at the regular input rate.
func TestCost_OpenAICachedFallsBackToInputRate(t *testing.T) {
	tbl := &Table{entries: map[string]map[string]Entry{
		"openai": {"gpt-4o": {InputPer1K: 0.0025, OutputPer1K: 0.01}},
	}}
	cost, ok := tbl.Cost("openai", "gpt-4o", 1000, 500, 750, 0)
	require.True(t, ok)
	want := 0.0025 + (500.0/1000.0)*0.01
	assert.InDelta(t, want, cost, 1e-12,
		"absent cached_input_per_1k rate must fall back to input_per_1k")
}

// TestCost_OpenAIClampsCachedToInputCount is the defensive guard
// against malformed upstream responses that report cached_tokens >
// prompt_tokens. We clamp so the formula never produces a negative
// "non-cached remainder" multiplied by the input rate.
func TestCost_OpenAIClampsCachedToInputCount(t *testing.T) {
	tbl := &Table{entries: map[string]map[string]Entry{
		"openai": {"gpt-4o": {InputPer1K: 0.0025, OutputPer1K: 0.01, CachedInputPer1K: 0.00125}},
	}}
	cost, ok := tbl.Cost("openai", "gpt-4o", 100, 0, 9999, 0)
	require.True(t, ok)
	// All 100 cached, 0 non-cached. Output is 0.
	want := (100.0 / 1000.0) * 0.00125
	assert.InDelta(t, want, cost, 1e-12,
		"cached count > input count must clamp to input — never bill negative non-cached tokens")
}

// TestCost_AnthropicCacheReadAndCreationAreAdditive proves the
// Anthropic shape: cache_read and cache_creation tokens are
// ADDITIVE to input_tokens (not subset), each billed at its own
// configured rate.
func TestCost_AnthropicCacheReadAndCreationAreAdditive(t *testing.T) {
	tbl := &Table{entries: map[string]map[string]Entry{
		"anthropic": {"claude-sonnet": {
			InputPer1K:         0.003,
			OutputPer1K:        0.015,
			CacheReadPer1K:     0.0003,  // 0.1x of input
			CacheCreationPer1K: 0.00375, // 1.25x of input
		}},
	}}
	// 256 regular input + 768 cache_read + 512 cache_creation +
	// 200 output. Each input bucket bills at its own rate.
	cost, ok := tbl.Cost("anthropic", "claude-sonnet", 256, 200, 768, 512)
	require.True(t, ok, "known model resolves")
	want := (256.0/1000.0)*0.003 +
		(768.0/1000.0)*0.0003 +
		(512.0/1000.0)*0.00375 +
		(200.0/1000.0)*0.015
	assert.InDelta(t, want, cost, 1e-12,
		"each Anthropic input bucket must bill at its own configured rate")
}

// TestCost_AnthropicCacheRatesFallBackToInput covers the no-rate
// path: when neither CacheReadPer1K nor CacheCreationPer1K is set,
// cache tokens bill at the regular input rate.
func TestCost_AnthropicCacheRatesFallBackToInput(t *testing.T) {
	tbl := &Table{entries: map[string]map[string]Entry{
		"anthropic": {"claude-sonnet": {InputPer1K: 0.003, OutputPer1K: 0.015}},
	}}
	cost, ok := tbl.Cost("anthropic", "claude-sonnet", 256, 200, 768, 512)
	require.True(t, ok)
	// Without overrides: every input bucket at input_per_1k.
	want := ((256.0+768.0+512.0)/1000.0)*0.003 + (200.0/1000.0)*0.015
	assert.InDelta(t, want, cost, 1e-12,
		"absent cache rates must fall back to input_per_1k")
}

// TestEntryCosts_SurfaceSelectsFormula pins that the formula branches on
// the SURFACE, not on which table the entry came from: the same entry
// bills a subset carve-out on "openai", additive buckets on
// "anthropic"/"bedrock", and ignores cache counts everywhere else. This
// is what keeps per-provider-record entries (looked up by record id)
// mathematically identical to defaults-table entries.
func TestEntryCosts_SurfaceSelectsFormula(t *testing.T) {
	e := Entry{InputPer1K: 0.002, OutputPer1K: 0.01, CachedInputPer1K: 0.001, CacheReadPer1K: 0.0002, CacheCreationPer1K: 0.0025}

	openai := EntryCosts(e, "openai", 1000, 0, 400, 300)
	assert.InDelta(t, (600.0/1000.0)*0.002+(400.0/1000.0)*0.001, openai.TotalUSD, 1e-12,
		"openai: cached is a subset, cacheCreation ignored")

	anthropic := EntryCosts(e, "anthropic", 1000, 0, 400, 300)
	assert.InDelta(t, 0.002+(400.0/1000.0)*0.0002+(300.0/1000.0)*0.0025, anthropic.TotalUSD, 1e-12,
		"anthropic: cache buckets are additive")

	bedrock := EntryCosts(e, "bedrock", 1000, 0, 400, 300)
	assert.InDelta(t, anthropic.TotalUSD, bedrock.TotalUSD, 1e-12, "bedrock shares the anthropic formula")

	other := EntryCosts(e, "gemini", 1000, 0, 400, 300)
	assert.InDelta(t, 0.002, other.TotalUSD, 1e-12, "unknown surface: cache counts ignored")
}

// TestEntryCosts_ClampsNegativeTokens: malformed upstream counts must
// never produce a negative cost.
func TestEntryCosts_ClampsNegativeTokens(t *testing.T) {
	e := Entry{InputPer1K: 0.002, OutputPer1K: 0.01}
	c := EntryCosts(e, "openai", -50, -10, -5, -3)
	assert.Zero(t, c.TotalUSD, "all-negative counts clamp to zero cost")
}

func TestTableCost_NilSafe(t *testing.T) {
	var t1 *Table
	cost, ok := t1.Cost("x", "y", 1, 1, 0, 0)
	assert.False(t, ok, "nil table reports unknown")
	assert.Zero(t, cost, "nil table returns zero cost")
	assert.False(t, t1.Has("x", "y"), "nil table has nothing")
}

func TestNewTable_ValidatesRates(t *testing.T) {
	good := map[string]map[string]EntryJSON{
		"openai": {"gpt-4o": {InputPer1K: 0.0025, OutputPer1K: 0.01, CachedInputPer1K: 0.00125}},
	}
	tbl, err := NewTable(good)
	require.NoError(t, err)
	cost, ok := tbl.Cost("openai", "gpt-4o", 1000, 1000, 0, 0)
	require.True(t, ok, "entry survives the wire conversion")
	assert.InDelta(t, 0.0125, cost, 1e-9)

	_, ok = tbl.Cost("openai", "unknown-model", 1, 1, 0, 0)
	assert.False(t, ok, "unknown model misses")

	for name, bad := range map[string]EntryJSON{
		"negative input":  {InputPer1K: -1, OutputPer1K: 0.01},
		"NaN output":      {InputPer1K: 0.01, OutputPer1K: math.NaN()},
		"Inf cache read":  {InputPer1K: 0.01, OutputPer1K: 0.01, CacheReadPer1K: math.Inf(1)},
		"negative cached": {InputPer1K: 0.01, OutputPer1K: 0.01, CachedInputPer1K: -0.001},
	} {
		_, err := NewTable(map[string]map[string]EntryJSON{"openai": {"m": bad}})
		assert.Error(t, err, "case %q must be rejected so a corrupt config fails the chain build instead of mispricing", name)
	}
}

func TestNewTable_NilAndEmpty(t *testing.T) {
	tbl, err := NewTable(nil)
	require.NoError(t, err, "nil map builds an empty (never-matching) table")
	_, ok := tbl.Cost("openai", "gpt-4o", 1, 1, 0, 0)
	assert.False(t, ok, "empty table prices nothing")

	entries, err := NewEntries(nil)
	require.NoError(t, err)
	assert.Empty(t, entries, "nil in, empty (never-matching) map out for the per-record map")
}

// TestLookup_DatedAnthropicIDFallsBackToUndated covers a client pinning a
// release date on a model priced under its undated id. Without the
// fallback the request records no cost at all.
func TestLookup_DatedAnthropicIDFallsBackToUndated(t *testing.T) {
	table, err := NewTable(map[string]map[string]EntryJSON{
		"anthropic": {
			"claude-sonnet-4-5": {InputPer1K: 0.003, OutputPer1K: 0.015},
		},
	})
	require.NoError(t, err, "table must build from a valid defaults map")

	entry, ok := table.Lookup("anthropic", "claude-sonnet-4-5-20250929")
	require.True(t, ok, "a dated id must resolve to the undated entry")
	assert.InDelta(t, 0.003, entry.InputPer1K, 1e-9, "dated id must bill at the registered rate")

	_, ok = table.Lookup("anthropic", "claude-sonnet-9-9-20250929")
	assert.False(t, ok, "an unknown family must stay unpriced")
}
