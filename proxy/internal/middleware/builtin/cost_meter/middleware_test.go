package cost_meter

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/proxy/internal/llm/pricing"
	"github.com/netbirdio/netbird/proxy/internal/middleware"
)

// fixtureConfig mirrors what management's buildCostMeterConfigJSON ships:
// a surface-keyed defaults table. Rates match the retired YAML fixture so
// every cost assertion below is byte-identical to the pre-feature values.
func fixtureConfig(t *testing.T) []byte {
	t.Helper()
	raw, err := json.Marshal(Config{Pricing: &PricingConfig{
		Defaults: map[string]map[string]pricing.EntryJSON{
			"openai": {
				"gpt-4o":      {InputPer1K: 0.0025, OutputPer1K: 0.01},
				"gpt-4o-mini": {InputPer1K: 0.00015, OutputPer1K: 0.0006},
			},
			"anthropic": {
				"claude-sonnet-4-5": {InputPer1K: 0.003, OutputPer1K: 0.015},
			},
		},
	}})
	require.NoError(t, err)
	return raw
}

// fixtureConfigWithCache adds the cache-rate fields.
func fixtureConfigWithCache(t *testing.T) []byte {
	t.Helper()
	raw, err := json.Marshal(Config{Pricing: &PricingConfig{
		Defaults: map[string]map[string]pricing.EntryJSON{
			"openai": {
				"gpt-4o": {InputPer1K: 0.0025, OutputPer1K: 0.01, CachedInputPer1K: 0.00125},
			},
			"anthropic": {
				"claude-sonnet-4-5": {InputPer1K: 0.003, OutputPer1K: 0.015, CacheReadPer1K: 0.0003, CacheCreationPer1K: 0.00375},
			},
		},
	}})
	require.NoError(t, err)
	return raw
}

func metaValue(t *testing.T, kvs []middleware.KV, key string) (string, bool) {
	t.Helper()
	for _, kv := range kvs {
		if kv.Key == key {
			return kv.Value, true
		}
	}
	return "", false
}

func buildMiddleware(t *testing.T, raw []byte) middleware.Middleware {
	t.Helper()
	mw, err := Factory{}.New(raw)
	require.NoError(t, err, "factory must accept the supplied config")
	return mw
}

func TestMiddleware_StaticSurface(t *testing.T) {
	mw := buildMiddleware(t, fixtureConfig(t))

	assert.Equal(t, ID, mw.ID(), "ID must match the registered constant")
	assert.Equal(t, Version, mw.Version(), "Version must match the constant")
	assert.Equal(t, middleware.SlotOnResponse, mw.Slot(), "must run in the response slot")
	assert.Empty(t, mw.AcceptedContentTypes(), "cost_meter does not inspect bodies")
	assert.False(t, mw.MutationsSupported(), "cost_meter never mutates")
	assert.NoError(t, mw.Close(), "Close on stateless middleware is a no-op")

	keys := mw.MetadataKeys()
	expected := []string{
		middleware.KeyCostUSDInput,
		middleware.KeyCostUSDCachedInput,
		middleware.KeyCostUSDCacheCreation,
		middleware.KeyCostUSDOutput,
		middleware.KeyCostUSDTotal,
		middleware.KeyCostUSDCache,
		middleware.KeyCostSkipped,
	}
	assert.Equal(t, expected, keys, "metadata key allowlist must match the spec")
}

// TestFactory_AcceptsEmptyAndJSONConfig: empty/null/{} configs are what an
// old management (pre config-delivered pricing) sends — they must build a
// working (all-skip) instance, never fail the chain.
func TestFactory_AcceptsEmptyAndJSONConfig(t *testing.T) {
	cases := [][]byte{nil, {}, []byte("null"), []byte("{}"), []byte("   ")}
	for _, raw := range cases {
		mw, err := Factory{}.New(raw)
		require.NoError(t, err, "empty/null/object config must be accepted")
		require.NotNil(t, mw, "factory must return a middleware instance")
	}
}

func TestFactory_RejectsMalformedConfig(t *testing.T) {
	mw, err := Factory{}.New([]byte("{not json"))
	require.Error(t, err, "malformed config must surface at construction")
	assert.Nil(t, mw, "no instance is returned on error")
}

// TestFactory_RejectsInvalidRates: a non-finite or negative rate anywhere
// in the table fails the chain build (defense-in-depth behind management's
// API validation) rather than silently mispricing.
func TestFactory_RejectsInvalidRates(t *testing.T) {
	raw, err := json.Marshal(Config{Pricing: &PricingConfig{
		Defaults: map[string]map[string]pricing.EntryJSON{
			"openai": {"gpt-4o": {InputPer1K: -0.0025, OutputPer1K: 0.01}},
		},
	}})
	require.NoError(t, err)
	mw, err := Factory{}.New(raw)
	require.Error(t, err, "negative rate must fail the build")
	assert.Nil(t, mw)

	raw, err = json.Marshal(Config{Pricing: &PricingConfig{
		Providers: map[string]map[string]pricing.EntryJSON{
			"prov-1": {"m": {InputPer1K: 0.01, OutputPer1K: 0.01, CacheReadPer1K: -1}},
		},
	}})
	require.NoError(t, err)
	_, err = Factory{}.New(raw)
	require.Error(t, err, "per-record tables validate too")
}

// TestFactory_NilPricingSkipsEverything is the version-skew contract: a
// new proxy under an old management ({} config) must build, allow, and
// skip with unknown_model — degraded but never broken.
func TestFactory_NilPricingSkipsEverything(t *testing.T) {
	mw := buildMiddleware(t, []byte("{}"))
	out, err := mw.Invoke(context.Background(), &middleware.Input{
		Metadata: []middleware.KV{
			{Key: middleware.KeyLLMProvider, Value: "openai"},
			{Key: middleware.KeyLLMModel, Value: "gpt-4o"},
			{Key: middleware.KeyLLMInputTokens, Value: "1000"},
			{Key: middleware.KeyLLMOutputTokens, Value: "1000"},
		},
	})
	require.NoError(t, err)
	assert.Equal(t, middleware.DecisionAllow, out.Decision, "cost_meter always allows")
	value, ok := metaValue(t, out.Metadata, middleware.KeyCostSkipped)
	require.True(t, ok, "no pricing table means every request skips")
	assert.Equal(t, skipUnknownModel, value)
}

func TestFactory_ConfigDefaultsPriceRequests(t *testing.T) {
	mw := buildMiddleware(t, fixtureConfig(t))

	out, err := mw.Invoke(context.Background(), &middleware.Input{
		Metadata: []middleware.KV{
			{Key: middleware.KeyLLMProvider, Value: "openai"},
			{Key: middleware.KeyLLMModel, Value: "gpt-4o-mini"},
			{Key: middleware.KeyLLMInputTokens, Value: "1000"},
			{Key: middleware.KeyLLMOutputTokens, Value: "1000"},
		},
	})
	require.NoError(t, err)
	require.Equal(t, middleware.DecisionAllow, out.Decision, "cost_meter always allows")

	value, ok := metaValue(t, out.Metadata, middleware.KeyCostUSDTotal)
	require.True(t, ok, "cost.usd_total must be emitted for known model")
	assert.Equal(t, "0.000750000", value, "0.00015 + 0.0006 per 1k tokens, 9-decimal format")
}

// TestInvoke_PerRecordEntryBeatsDefaults: when llm_router resolved a
// provider record whose operator pinned a price for the model, that price
// wins over the surface default.
func TestInvoke_PerRecordEntryBeatsDefaults(t *testing.T) {
	raw, err := json.Marshal(Config{Pricing: &PricingConfig{
		Defaults: map[string]map[string]pricing.EntryJSON{
			"openai": {"gpt-4o": {InputPer1K: 0.0025, OutputPer1K: 0.01}},
		},
		Providers: map[string]map[string]pricing.EntryJSON{
			"prov-azure": {"gpt-4o": {InputPer1K: 0.005, OutputPer1K: 0.02}},
		},
	}})
	require.NoError(t, err)
	mw := buildMiddleware(t, raw)

	out, err := mw.Invoke(context.Background(), &middleware.Input{
		Metadata: []middleware.KV{
			{Key: middleware.KeyLLMProvider, Value: "openai"},
			{Key: middleware.KeyLLMModel, Value: "gpt-4o"},
			{Key: middleware.KeyLLMResolvedProviderID, Value: "prov-azure"},
			{Key: middleware.KeyLLMInputTokens, Value: "1000"},
			{Key: middleware.KeyLLMOutputTokens, Value: "1000"},
		},
	})
	require.NoError(t, err)
	value, ok := metaValue(t, out.Metadata, middleware.KeyCostUSDTotal)
	require.True(t, ok)
	assert.Equal(t, "0.025000000", value, "operator's per-record price (0.005+0.02) wins over the default (0.0025+0.01)")
}

// TestInvoke_PerRecordMissFallsBackToDefaults: a resolved record with no
// entry for this model (or no entries at all) falls through to the
// surface defaults — gateway providers rely on exactly this.
func TestInvoke_PerRecordMissFallsBackToDefaults(t *testing.T) {
	raw, err := json.Marshal(Config{Pricing: &PricingConfig{
		Defaults: map[string]map[string]pricing.EntryJSON{
			"openai": {"gpt-4o": {InputPer1K: 0.0025, OutputPer1K: 0.01}},
		},
		Providers: map[string]map[string]pricing.EntryJSON{
			"prov-1": {"some-other-model": {InputPer1K: 1, OutputPer1K: 1}},
		},
	}})
	require.NoError(t, err)
	mw := buildMiddleware(t, raw)

	for name, recordID := range map[string]string{
		"record with other models": "prov-1",
		"record with no entries":   "prov-gateway",
	} {
		t.Run(name, func(t *testing.T) {
			out, err := mw.Invoke(context.Background(), &middleware.Input{
				Metadata: []middleware.KV{
					{Key: middleware.KeyLLMProvider, Value: "openai"},
					{Key: middleware.KeyLLMModel, Value: "gpt-4o"},
					{Key: middleware.KeyLLMResolvedProviderID, Value: recordID},
					{Key: middleware.KeyLLMInputTokens, Value: "1000"},
					{Key: middleware.KeyLLMOutputTokens, Value: "1000"},
				},
			})
			require.NoError(t, err)
			value, ok := metaValue(t, out.Metadata, middleware.KeyCostUSDTotal)
			require.True(t, ok, "per-record miss must fall back to the surface default, not skip")
			assert.Equal(t, "0.012500000", value, "default rates apply")
		})
	}
}

// TestInvoke_NoResolvedProviderIDUsesDefaults: metadata without a
// resolved provider id (router denied, or a chain without llm_router)
// prices from the defaults table directly.
func TestInvoke_NoResolvedProviderIDUsesDefaults(t *testing.T) {
	mw := buildMiddleware(t, fixtureConfig(t))
	out, err := mw.Invoke(context.Background(), &middleware.Input{
		Metadata: []middleware.KV{
			{Key: middleware.KeyLLMProvider, Value: "anthropic"},
			{Key: middleware.KeyLLMModel, Value: "claude-sonnet-4-5"},
			{Key: middleware.KeyLLMInputTokens, Value: "1000"},
			{Key: middleware.KeyLLMOutputTokens, Value: "1000"},
		},
	})
	require.NoError(t, err)
	value, ok := metaValue(t, out.Metadata, middleware.KeyCostUSDTotal)
	require.True(t, ok)
	assert.Equal(t, "0.018000000", value, "0.003 + 0.015 = 0.018 with 9-decimal format")
	_, skipped := metaValue(t, out.Metadata, middleware.KeyCostSkipped)
	assert.False(t, skipped, "cost.skipped must not be set when cost is computed")
}

func TestInvoke_MissingProvider(t *testing.T) {
	mw := buildMiddleware(t, fixtureConfig(t))

	out, err := mw.Invoke(context.Background(), &middleware.Input{
		Metadata: []middleware.KV{
			{Key: middleware.KeyLLMModel, Value: "gpt-4o"},
			{Key: middleware.KeyLLMInputTokens, Value: "10"},
			{Key: middleware.KeyLLMOutputTokens, Value: "10"},
		},
	})
	require.NoError(t, err)
	value, ok := metaValue(t, out.Metadata, middleware.KeyCostSkipped)
	require.True(t, ok, "cost.skipped must be set when provider is missing")
	assert.Equal(t, skipMissingProvider, value, "skip reason matches missing_provider")
}

func TestInvoke_MissingModel(t *testing.T) {
	mw := buildMiddleware(t, fixtureConfig(t))

	out, err := mw.Invoke(context.Background(), &middleware.Input{
		Metadata: []middleware.KV{
			{Key: middleware.KeyLLMProvider, Value: "openai"},
			{Key: middleware.KeyLLMInputTokens, Value: "10"},
			{Key: middleware.KeyLLMOutputTokens, Value: "10"},
		},
	})
	require.NoError(t, err)
	value, ok := metaValue(t, out.Metadata, middleware.KeyCostSkipped)
	require.True(t, ok, "cost.skipped must be set when model is missing")
	assert.Equal(t, skipMissingModel, value, "skip reason matches missing_model")
}

func TestInvoke_MissingTokens(t *testing.T) {
	mw := buildMiddleware(t, fixtureConfig(t))

	cases := []struct {
		name string
		md   []middleware.KV
	}{
		{
			name: "input only",
			md: []middleware.KV{
				{Key: middleware.KeyLLMProvider, Value: "openai"},
				{Key: middleware.KeyLLMModel, Value: "gpt-4o"},
				{Key: middleware.KeyLLMInputTokens, Value: "10"},
			},
		},
		{
			name: "output only",
			md: []middleware.KV{
				{Key: middleware.KeyLLMProvider, Value: "openai"},
				{Key: middleware.KeyLLMModel, Value: "gpt-4o"},
				{Key: middleware.KeyLLMOutputTokens, Value: "10"},
			},
		},
		{
			name: "neither",
			md: []middleware.KV{
				{Key: middleware.KeyLLMProvider, Value: "openai"},
				{Key: middleware.KeyLLMModel, Value: "gpt-4o"},
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out, err := mw.Invoke(context.Background(), &middleware.Input{Metadata: tc.md})
			require.NoError(t, err)
			value, ok := metaValue(t, out.Metadata, middleware.KeyCostSkipped)
			require.True(t, ok, "cost.skipped must be set when token keys are missing")
			assert.Equal(t, skipMissingTokens, value, "skip reason matches missing_tokens")
		})
	}
}

func TestInvoke_UnparseableTokens(t *testing.T) {
	mw := buildMiddleware(t, fixtureConfig(t))

	cases := []struct {
		name string
		in   string
		out  string
	}{
		{name: "input non-numeric", in: "abc", out: "10"},
		{name: "output non-numeric", in: "10", out: "xyz"},
		{name: "both garbage", in: "??", out: "??"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out, err := mw.Invoke(context.Background(), &middleware.Input{
				Metadata: []middleware.KV{
					{Key: middleware.KeyLLMProvider, Value: "openai"},
					{Key: middleware.KeyLLMModel, Value: "gpt-4o"},
					{Key: middleware.KeyLLMInputTokens, Value: tc.in},
					{Key: middleware.KeyLLMOutputTokens, Value: tc.out},
				},
			})
			require.NoError(t, err)
			value, ok := metaValue(t, out.Metadata, middleware.KeyCostSkipped)
			require.True(t, ok, "cost.skipped must be set on unparseable tokens")
			assert.Equal(t, skipUnparseableTokens, value, "skip reason matches unparseable_tokens")
		})
	}
}

func TestInvoke_ZeroTokens(t *testing.T) {
	mw := buildMiddleware(t, fixtureConfig(t))

	out, err := mw.Invoke(context.Background(), &middleware.Input{
		Metadata: []middleware.KV{
			{Key: middleware.KeyLLMProvider, Value: "openai"},
			{Key: middleware.KeyLLMModel, Value: "gpt-4o"},
			{Key: middleware.KeyLLMInputTokens, Value: "0"},
			{Key: middleware.KeyLLMOutputTokens, Value: "0"},
		},
	})
	require.NoError(t, err)
	value, ok := metaValue(t, out.Metadata, middleware.KeyCostSkipped)
	require.True(t, ok, "cost.skipped must be set when both token counts are zero")
	assert.Equal(t, skipZeroTokens, value, "skip reason matches zero_tokens")
	_, hasCost := metaValue(t, out.Metadata, middleware.KeyCostUSDTotal)
	assert.False(t, hasCost, "cost.usd_total must not be emitted for zero tokens")
}

func TestInvoke_UnknownModel(t *testing.T) {
	mw := buildMiddleware(t, fixtureConfig(t))

	out, err := mw.Invoke(context.Background(), &middleware.Input{
		Metadata: []middleware.KV{
			{Key: middleware.KeyLLMProvider, Value: "openai"},
			{Key: middleware.KeyLLMModel, Value: "fantasy-model-9000"},
			{Key: middleware.KeyLLMInputTokens, Value: "10"},
			{Key: middleware.KeyLLMOutputTokens, Value: "10"},
		},
	})
	require.NoError(t, err)
	value, ok := metaValue(t, out.Metadata, middleware.KeyCostSkipped)
	require.True(t, ok, "cost.skipped must be set when pricing entry is absent")
	assert.Equal(t, skipUnknownModel, value, "skip reason matches unknown_model")
}

func TestInvoke_NilInput(t *testing.T) {
	mw := buildMiddleware(t, fixtureConfig(t))

	out, err := mw.Invoke(context.Background(), nil)
	require.NoError(t, err)
	require.NotNil(t, out, "output must be returned even on nil input")
	assert.Equal(t, middleware.DecisionAllow, out.Decision, "decision must be allow on nil input")
	assert.Empty(t, out.Metadata, "no metadata must be emitted on nil input")
}

// TestInvoke_OpenAICachedSubsetDiscount proves the OpenAI shape end
// to end through the middleware: cached_input_tokens is treated as a
// SUBSET of input_tokens and discounted at the configured rate, not
// added on top.
func TestInvoke_OpenAICachedSubsetDiscount(t *testing.T) {
	mw := buildMiddleware(t, fixtureConfigWithCache(t))

	out, err := mw.Invoke(context.Background(), &middleware.Input{
		Metadata: []middleware.KV{
			{Key: middleware.KeyLLMProvider, Value: "openai"},
			{Key: middleware.KeyLLMModel, Value: "gpt-4o"},
			{Key: middleware.KeyLLMInputTokens, Value: "1000"},
			{Key: middleware.KeyLLMOutputTokens, Value: "500"},
			{Key: middleware.KeyLLMCachedInputTokens, Value: "750"},
		},
	})
	require.NoError(t, err)
	require.Equal(t, middleware.DecisionAllow, out.Decision)

	value, ok := metaValue(t, out.Metadata, middleware.KeyCostUSDTotal)
	require.True(t, ok, "cached subset path must produce a cost — never a skip")
	// 250 non-cached at 0.0025/1k + 750 cached at 0.00125/1k + 500 output at 0.01/1k.
	assert.Equal(t, "0.006562500", value,
		"cached subset must be billed at the discount rate, non-cached at the full rate; never double-billed")

	cache, ok := metaValue(t, out.Metadata, middleware.KeyCostUSDCache)
	require.True(t, ok, "cost.usd_cache must be emitted alongside cost.usd_total")
	// 750 cached at 0.00125/1k = 0.0009375.
	assert.Equal(t, "0.000937500", cache, "cache cost is the discounted cost of the cached subset")

	// Per-bucket breakdown. On OpenAI the cached subset is carved out of the
	// input bucket, so input covers only the 250 non-cached tokens — the two
	// must never double-count the same 750 tokens.
	assertBucket(t, out.Metadata, middleware.KeyCostUSDInput, "0.000625000",
		"input bucket bills only the non-cached remainder")
	assertBucket(t, out.Metadata, middleware.KeyCostUSDCachedInput, "0.000937500",
		"cached-input bucket bills the discounted subset")
	assertBucket(t, out.Metadata, middleware.KeyCostUSDCacheCreation, "0.000000000",
		"OpenAI has no cache-write bucket")
	assertBucket(t, out.Metadata, middleware.KeyCostUSDOutput, "0.005000000",
		"output bucket bills 500 tokens at 0.01/1k")
}

// TestInvoke_AnthropicCacheBucketsAdditive proves the Anthropic
// shape: cache_read and cache_creation are additive to input_tokens
// and each carries its own rate.
func TestInvoke_AnthropicCacheBucketsAdditive(t *testing.T) {
	mw := buildMiddleware(t, fixtureConfigWithCache(t))

	out, err := mw.Invoke(context.Background(), &middleware.Input{
		Metadata: []middleware.KV{
			{Key: middleware.KeyLLMProvider, Value: "anthropic"},
			{Key: middleware.KeyLLMModel, Value: "claude-sonnet-4-5"},
			{Key: middleware.KeyLLMInputTokens, Value: "256"},
			{Key: middleware.KeyLLMOutputTokens, Value: "200"},
			{Key: middleware.KeyLLMCachedInputTokens, Value: "768"},
			{Key: middleware.KeyLLMCacheCreationTokens, Value: "512"},
		},
	})
	require.NoError(t, err)
	require.Equal(t, middleware.DecisionAllow, out.Decision)

	value, ok := metaValue(t, out.Metadata, middleware.KeyCostUSDTotal)
	require.True(t, ok)
	// 256 input * 0.003 + 768 cache_read * 0.0003 + 512 cache_creation * 0.00375 + 200 output * 0.015
	// = 0.000768 + 0.0002304 + 0.00192 + 0.003 = 0.0059184.
	assert.Equal(t, "0.005918400", value,
		"each Anthropic input bucket must bill at its own rate — cache_read cheap, cache_creation expensive, regular input mid")

	cache, ok := metaValue(t, out.Metadata, middleware.KeyCostUSDCache)
	require.True(t, ok, "cost.usd_cache must be emitted alongside cost.usd_total")
	// 768 cache_read * 0.0003 + 512 cache_creation * 0.00375 = 0.0021504.
	assert.Equal(t, "0.002150400", cache, "cache cost sums the read and creation buckets")

	// Per-bucket breakdown: four separately-billed buckets, each at its own rate.
	assertBucket(t, out.Metadata, middleware.KeyCostUSDInput, "0.000768000",
		"input bucket bills 256 tokens at 0.003/1k")
	assertBucket(t, out.Metadata, middleware.KeyCostUSDCachedInput, "0.000230400",
		"cache-read bucket bills 768 tokens at the cheap 0.0003/1k")
	assertBucket(t, out.Metadata, middleware.KeyCostUSDCacheCreation, "0.001920000",
		"cache-write bucket bills 512 tokens at the expensive 0.00375/1k")
	assertBucket(t, out.Metadata, middleware.KeyCostUSDOutput, "0.003000000",
		"output bucket bills 200 tokens at 0.015/1k")
}

// TestInvoke_PerRecordEntryUsesSurfaceFormula: a per-record entry for an
// anthropic-surface request must bill its cache buckets additively — the
// formula follows llm.provider, not which table the entry came from.
func TestInvoke_PerRecordEntryUsesSurfaceFormula(t *testing.T) {
	raw, err := json.Marshal(Config{Pricing: &PricingConfig{
		Providers: map[string]map[string]pricing.EntryJSON{
			"prov-ant": {"claude-sonnet-4-5": {InputPer1K: 0.003, OutputPer1K: 0.015, CacheReadPer1K: 0.0003, CacheCreationPer1K: 0.00375}},
		},
	}})
	require.NoError(t, err)
	mw := buildMiddleware(t, raw)

	out, err := mw.Invoke(context.Background(), &middleware.Input{
		Metadata: []middleware.KV{
			{Key: middleware.KeyLLMProvider, Value: "anthropic"},
			{Key: middleware.KeyLLMModel, Value: "claude-sonnet-4-5"},
			{Key: middleware.KeyLLMResolvedProviderID, Value: "prov-ant"},
			{Key: middleware.KeyLLMInputTokens, Value: "256"},
			{Key: middleware.KeyLLMOutputTokens, Value: "200"},
			{Key: middleware.KeyLLMCachedInputTokens, Value: "768"},
			{Key: middleware.KeyLLMCacheCreationTokens, Value: "512"},
		},
	})
	require.NoError(t, err)
	value, ok := metaValue(t, out.Metadata, middleware.KeyCostUSDTotal)
	require.True(t, ok)
	assert.Equal(t, "0.005918400", value, "identical math to the defaults-table entry with the same rates")
}

// assertBucket asserts one per-bucket cost key carries the expected
// 9-decimal value.
func assertBucket(t *testing.T, md []middleware.KV, key, want, msg string) {
	t.Helper()
	got, ok := metaValue(t, md, key)
	require.Truef(t, ok, "%s must be emitted", key)
	assert.Equal(t, want, got, msg)
}

// TestInvoke_CachedTokensAbsentFallsBackToBaseFormula covers the
// no-cache-metadata path: with no cached keys emitted, the meter must
// produce exactly the input+output cost.
func TestInvoke_CachedTokensAbsentFallsBackToBaseFormula(t *testing.T) {
	mw := buildMiddleware(t, fixtureConfigWithCache(t))

	out, err := mw.Invoke(context.Background(), &middleware.Input{
		Metadata: []middleware.KV{
			{Key: middleware.KeyLLMProvider, Value: "openai"},
			{Key: middleware.KeyLLMModel, Value: "gpt-4o"},
			{Key: middleware.KeyLLMInputTokens, Value: "1000"},
			{Key: middleware.KeyLLMOutputTokens, Value: "500"},
			// No KeyLLMCachedInputTokens — the parser didn't see one.
		},
	})
	require.NoError(t, err)
	value, ok := metaValue(t, out.Metadata, middleware.KeyCostUSDTotal)
	require.True(t, ok)
	// 1000 input * 0.0025 + 500 output * 0.01 = 0.0025 + 0.005 = 0.0075
	assert.Equal(t, "0.007500000", value, "no cached metadata = plain input+output cost")
}

// TestInvoke_UnparseableCachedTokensSkippedSilently proves the
// optional-bucket contract: a malformed cached_input_tokens metadata
// value falls back to 0 (= no cached count) and continues with the
// regular formula. Cache buckets are a refinement, never a reason to
// abort cost computation.
func TestInvoke_UnparseableCachedTokensSkippedSilently(t *testing.T) {
	mw := buildMiddleware(t, fixtureConfigWithCache(t))

	out, err := mw.Invoke(context.Background(), &middleware.Input{
		Metadata: []middleware.KV{
			{Key: middleware.KeyLLMProvider, Value: "openai"},
			{Key: middleware.KeyLLMModel, Value: "gpt-4o"},
			{Key: middleware.KeyLLMInputTokens, Value: "1000"},
			{Key: middleware.KeyLLMOutputTokens, Value: "500"},
			{Key: middleware.KeyLLMCachedInputTokens, Value: "not-a-number"},
		},
	})
	require.NoError(t, err)
	value, ok := metaValue(t, out.Metadata, middleware.KeyCostUSDTotal)
	require.True(t, ok, "garbage cache metadata must NOT switch the response from a cost to a skip — fall back to 0 cached")
	assert.Equal(t, "0.007500000", value, "same as the no-cached-metadata path")
}

// TestMiddleware_CloseNilSafe confirms Close is a no-op (no panic) even
// for a nil receiver.
func TestMiddleware_CloseNilSafe(t *testing.T) {
	require.NoError(t, newMiddleware(nil, nil).Close(), "Close must be a no-op")
	var m *Middleware
	require.NoError(t, m.Close(), "nil-receiver Close must be safe")
}
