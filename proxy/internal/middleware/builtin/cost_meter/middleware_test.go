package cost_meter

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/proxy/internal/middleware"
	"github.com/netbirdio/netbird/proxy/internal/middleware/builtin"
)

const fixturePricing = `openai:
  gpt-4o:
    input_per_1k: 0.0025
    output_per_1k: 0.01
  gpt-4o-mini:
    input_per_1k: 0.00015
    output_per_1k: 0.0006
anthropic:
  claude-sonnet-4-5:
    input_per_1k: 0.003
    output_per_1k: 0.015
`

// configureBuiltin points the package-level FactoryContext at a tmp
// directory containing the test pricing fixture. Returns the path so
// callers can override files later if needed.
func configureBuiltin(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "pricing.yaml"), []byte(fixturePricing), 0o600), "write pricing fixture")
	builtin.Configure(context.Background(), dir, nil, nil, nil)
	return dir
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
	configureBuiltin(t)
	mw := buildMiddleware(t, nil)

	assert.Equal(t, ID, mw.ID(), "ID must match the registered constant")
	assert.Equal(t, Version, mw.Version(), "Version must match the constant")
	assert.Equal(t, middleware.SlotOnResponse, mw.Slot(), "must run in the response slot")
	assert.Empty(t, mw.AcceptedContentTypes(), "cost_meter does not inspect bodies")
	assert.False(t, mw.MutationsSupported(), "cost_meter never mutates")
	assert.NoError(t, mw.Close(), "Close on stateless middleware is a no-op")

	keys := mw.MetadataKeys()
	expected := []string{middleware.KeyCostUSDTotal, middleware.KeyCostSkipped}
	assert.Equal(t, expected, keys, "metadata key allowlist must match the spec")
}

func TestFactory_AcceptsEmptyAndJSONConfig(t *testing.T) {
	configureBuiltin(t)
	cases := [][]byte{nil, {}, []byte("null"), []byte("{}"), []byte("   ")}
	for _, raw := range cases {
		mw, err := Factory{}.New(raw)
		require.NoError(t, err, "empty/null/object config must be accepted")
		require.NotNil(t, mw, "factory must return a middleware instance")
	}
}

func TestFactory_RejectsMalformedConfig(t *testing.T) {
	configureBuiltin(t)
	mw, err := Factory{}.New([]byte("{not json"))
	require.Error(t, err, "malformed config must surface at construction")
	assert.Nil(t, mw, "no instance is returned on error")
}

func TestFactory_DefaultPricingPathLoadsFixture(t *testing.T) {
	configureBuiltin(t)
	mw := buildMiddleware(t, nil)

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
	assert.Equal(t, "0.000750", value, "0.00015 + 0.0006 per 1k tokens, 6-decimal format")
}

func TestFactory_PricingPathOverride(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "custom.yaml"), []byte(fixturePricing), 0o600), "write custom pricing")
	builtin.Configure(context.Background(), dir, nil, nil, nil)

	raw, err := json.Marshal(Config{PricingPath: "custom.yaml"})
	require.NoError(t, err)

	mw := buildMiddleware(t, raw)
	out, err := mw.Invoke(context.Background(), &middleware.Input{
		Metadata: []middleware.KV{
			{Key: middleware.KeyLLMProvider, Value: "openai"},
			{Key: middleware.KeyLLMModel, Value: "gpt-4o"},
			{Key: middleware.KeyLLMInputTokens, Value: "2000"},
			{Key: middleware.KeyLLMOutputTokens, Value: "1000"},
		},
	})
	require.NoError(t, err)

	value, ok := metaValue(t, out.Metadata, middleware.KeyCostUSDTotal)
	require.True(t, ok, "cost.usd_total must be emitted with custom pricing path")
	assert.Equal(t, "0.015000", value, "2*0.0025 + 1*0.01 = 0.015 with 6-decimal format")
}

func TestInvoke_ComputesCostForKnownModel(t *testing.T) {
	configureBuiltin(t)
	mw := buildMiddleware(t, nil)

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
	require.True(t, ok, "cost.usd_total must be emitted")
	assert.Equal(t, "0.018000", value, "0.003 + 0.015 = 0.018 with 6-decimal format")
	_, skipped := metaValue(t, out.Metadata, middleware.KeyCostSkipped)
	assert.False(t, skipped, "cost.skipped must not be set when cost is computed")
}

func TestInvoke_MissingProvider(t *testing.T) {
	configureBuiltin(t)
	mw := buildMiddleware(t, nil)

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
	configureBuiltin(t)
	mw := buildMiddleware(t, nil)

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
	configureBuiltin(t)
	mw := buildMiddleware(t, nil)

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
	configureBuiltin(t)
	mw := buildMiddleware(t, nil)

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
	configureBuiltin(t)
	mw := buildMiddleware(t, nil)

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
	configureBuiltin(t)
	mw := buildMiddleware(t, nil)

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
	configureBuiltin(t)
	mw := buildMiddleware(t, nil)

	out, err := mw.Invoke(context.Background(), nil)
	require.NoError(t, err)
	require.NotNil(t, out, "output must be returned even on nil input")
	assert.Equal(t, middleware.DecisionAllow, out.Decision, "decision must be allow on nil input")
	assert.Empty(t, out.Metadata, "no metadata must be emitted on nil input")
}

const fixturePricingWithCache = `openai:
  gpt-4o:
    input_per_1k: 0.0025
    output_per_1k: 0.01
    cached_input_per_1k: 0.00125
anthropic:
  claude-sonnet-4-5:
    input_per_1k: 0.003
    output_per_1k: 0.015
    cache_read_per_1k: 0.0003
    cache_creation_per_1k: 0.00375
`

// configureBuiltinWithCacheRates points the package-level
// FactoryContext at a tmp directory containing pricing entries that
// include the cache rate fields.
func configureBuiltinWithCacheRates(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "pricing.yaml"), []byte(fixturePricingWithCache), 0o600), "write cache-aware pricing fixture")
	builtin.Configure(context.Background(), dir, nil, nil, nil)
}

// TestInvoke_OpenAICachedSubsetDiscount proves the OpenAI shape end
// to end through the middleware: cached_input_tokens is treated as a
// SUBSET of input_tokens and discounted at the configured rate, not
// added on top.
func TestInvoke_OpenAICachedSubsetDiscount(t *testing.T) {
	configureBuiltinWithCacheRates(t)
	mw := buildMiddleware(t, nil)

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
	assert.Equal(t, "0.006563", value,
		"cached subset must be billed at the discount rate, non-cached at the full rate; never double-billed")
}

// TestInvoke_AnthropicCacheBucketsAdditive proves the Anthropic
// shape: cache_read and cache_creation are additive to input_tokens
// and each carries its own rate.
func TestInvoke_AnthropicCacheBucketsAdditive(t *testing.T) {
	configureBuiltinWithCacheRates(t)
	mw := buildMiddleware(t, nil)

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
	// = 0.000768 + 0.0002304 + 0.00192 + 0.003 = 0.0059184 → "0.005918" with 6-decimal format.
	assert.Equal(t, "0.005918", value,
		"each Anthropic input bucket must bill at its own rate — cache_read cheap, cache_creation expensive, regular input mid")
}

// TestInvoke_CachedTokensAbsentFallsBackToBaseFormula covers the
// "operator hasn't opted in" path: with no cached metadata keys
// emitted, the meter must produce exactly the same cost as before
// the feature landed. Critical so operators with the new binary but
// no YAML changes see no behavioural drift on OpenAI requests.
func TestInvoke_CachedTokensAbsentFallsBackToBaseFormula(t *testing.T) {
	configureBuiltinWithCacheRates(t)
	mw := buildMiddleware(t, nil)

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
	assert.Equal(t, "0.007500", value, "no cached metadata = same cost as before the feature landed")
}

// TestInvoke_UnparseableCachedTokensSkippedSilently proves the
// optional-bucket contract: a malformed cached_input_tokens metadata
// value falls back to 0 (= no cached count) and continues with the
// regular formula. Cache buckets are a refinement, never a reason to
// abort cost computation.
func TestInvoke_UnparseableCachedTokensSkippedSilently(t *testing.T) {
	configureBuiltinWithCacheRates(t)
	mw := buildMiddleware(t, nil)

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
	assert.Equal(t, "0.007500", value, "same as the no-cached-metadata path")
}

// TestMiddleware_CloseCancelsReloader proves Close stops the per-instance
// pricing-reload goroutine: a chain rebuild retires the old instance and
// calls Close, which must invoke the cancel func startReloader handed it so
// the mtime-poll loop doesn't outlive the chain.
func TestMiddleware_CloseCancelsReloader(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	m := newMiddleware(nil, cancel)

	require.NoError(t, m.Close(), "Close must not error")
	require.Error(t, ctx.Err(), "Close must cancel the reloader context so the poll goroutine exits")
}

// TestMiddleware_CloseNilSafe confirms Close is a no-op (no panic) for an
// instance with no reloader and for a nil receiver.
func TestMiddleware_CloseNilSafe(t *testing.T) {
	require.NoError(t, newMiddleware(nil, nil).Close(), "no-reloader Close must be a no-op")
	var m *Middleware
	require.NoError(t, m.Close(), "nil-receiver Close must be safe")
}
