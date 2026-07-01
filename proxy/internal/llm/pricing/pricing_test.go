//go:build unix

package pricing

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func copyFixture(t *testing.T, src, dst string) {
	t.Helper()
	data, err := os.ReadFile(src)
	require.NoError(t, err, "read source fixture")
	require.NoError(t, os.WriteFile(dst, data, 0o600), "write target fixture")
}

func TestNewLoader_HappyPath(t *testing.T) {
	base := t.TempDir()
	copyFixture(t, filepath.Join("..", "fixtures", "pricing.yaml"), filepath.Join(base, "pricing.yaml"))

	l, err := NewLoader(base, "pricing.yaml", "llm_observability", nil)
	require.NoError(t, err, "NewLoader must succeed with a valid fixture")
	table := l.Get()
	require.NotNil(t, table, "table populated after load")

	cost, ok := table.Cost("openai", "gpt-4o-mini", 1000, 1000, 0, 0)
	require.True(t, ok, "known provider/model resolves")
	assert.InDelta(t, 0.00075, cost, 1e-9, "cost = 0.00015 + 0.0006 per 1k tokens")

	cost, ok = table.Cost("openai", "gpt-4o", 2000, 1000, 0, 0)
	require.True(t, ok, "second known model resolves")
	assert.InDelta(t, 0.015, cost, 1e-9, "cost for gpt-4o: 2*0.0025 + 1*0.01")

	cost, ok = table.Cost("anthropic", "claude-sonnet-4-5", 1000, 1000, 0, 0)
	require.True(t, ok, "anthropic model resolves")
	assert.InDelta(t, 0.018, cost, 1e-9, "cost for claude-sonnet-4-5: 0.003 + 0.015")
}

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

// TestCost_OpenAICachedFallsBackToInputRate covers the operator
// opt-in contract: when CachedInputPer1K is unset (zero), cached
// tokens bill at the regular input rate. This matches today's
// behaviour (cached counts weren't extracted at all so they
// implicitly billed at the input rate via prompt_tokens).
func TestCost_OpenAICachedFallsBackToInputRate(t *testing.T) {
	tbl := &Table{entries: map[string]map[string]Entry{
		"openai": {"gpt-4o": {InputPer1K: 0.0025, OutputPer1K: 0.01}},
	}}
	cost, ok := tbl.Cost("openai", "gpt-4o", 1000, 500, 750, 0)
	require.True(t, ok)
	want := 0.0025 + (500.0/1000.0)*0.01
	assert.InDelta(t, want, cost, 1e-12,
		"absent cached_input_per_1k rate must fall back to input_per_1k — same as pre-feature behaviour")
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
// configured rate. The two rates pull in opposite directions —
// cache_read is the cheaper read-from-cache rate (≈0.1× input),
// cache_creation is the more expensive write-to-cache rate
// (≈1.25× input).
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

// TestCost_AnthropicCacheRatesFallBackToInput covers the no-opt-in
// path: when neither CacheReadPer1K nor CacheCreationPer1K is set,
// cache tokens bill at the regular input rate. This is more
// accurate than today's behaviour (cache tokens ignored entirely)
// without requiring operators to opt in via YAML.
func TestCost_AnthropicCacheRatesFallBackToInput(t *testing.T) {
	tbl := &Table{entries: map[string]map[string]Entry{
		"anthropic": {"claude-sonnet": {InputPer1K: 0.003, OutputPer1K: 0.015}},
	}}
	cost, ok := tbl.Cost("anthropic", "claude-sonnet", 256, 200, 768, 512)
	require.True(t, ok)
	// Without overrides: every input bucket at input_per_1k.
	want := ((256.0+768.0+512.0)/1000.0)*0.003 + (200.0/1000.0)*0.015
	assert.InDelta(t, want, cost, 1e-12,
		"absent cache rates must fall back to input_per_1k — Anthropic cache tokens were ignored before this change, billing at input rate is more accurate as a default")
}

func TestNewLoader_UnknownModel(t *testing.T) {
	base := t.TempDir()
	copyFixture(t, filepath.Join("..", "fixtures", "pricing.yaml"), filepath.Join(base, "pricing.yaml"))

	l, err := NewLoader(base, "pricing.yaml", "llm_observability", nil)
	require.NoError(t, err)

	_, ok := l.Get().Cost("openai", "fantasy-model", 10, 10, 0, 0)
	assert.False(t, ok, "unknown model returns ok=false")

	_, ok = l.Get().Cost("cohere", "anything", 10, 10, 0, 0)
	assert.False(t, ok, "unknown provider returns ok=false")
}

func TestNewLoader_InvalidYAMLRejected(t *testing.T) {
	base := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(base, "pricing.yaml"), []byte("\t- this is not: valid: yaml: :["), 0o600))

	_, err := NewLoader(base, "pricing.yaml", "llm_observability", nil)
	require.Error(t, err, "invalid YAML must surface as construction error")
}

func TestLoader_ReloadKeepsPreviousOnParseError(t *testing.T) {
	base := t.TempDir()
	target := filepath.Join(base, "pricing.yaml")
	copyFixture(t, filepath.Join("..", "fixtures", "pricing.yaml"), target)

	l, err := NewLoader(base, "pricing.yaml", "llm_observability", nil)
	require.NoError(t, err)
	require.NotNil(t, l.Get(), "initial table populated")

	// Overwrite with content that violates the strict schema (extra field)
	// plus a bumped mtime to trigger reload.
	require.NoError(t, os.WriteFile(target, []byte("openai:\n  gpt-4o:\n    input_per_1k: 1.0\n    output_per_1k: 2.0\n    bogus_field: nope\n"), 0o600))
	future := time.Now().Add(time.Hour)
	require.NoError(t, os.Chtimes(target, future, future))

	err = l.reload()
	require.Error(t, err, "parse error surfaced by reload()")

	cost, ok := l.Get().Cost("openai", "gpt-4o-mini", 1000, 1000, 0, 0)
	require.True(t, ok, "previous table still available after parse failure")
	assert.InDelta(t, 0.00075, cost, 1e-9, "previous cost preserved")
}

func TestLoader_ReloadNoChangeIsNoOp(t *testing.T) {
	base := t.TempDir()
	target := filepath.Join(base, "pricing.yaml")
	copyFixture(t, filepath.Join("..", "fixtures", "pricing.yaml"), target)

	l, err := NewLoader(base, "pricing.yaml", "llm_observability", nil)
	require.NoError(t, err)
	ptrBefore := l.Get()

	require.NoError(t, l.reload(), "no-change reload must not error")
	ptrAfter := l.Get()
	assert.Same(t, ptrBefore, ptrAfter, "table pointer unchanged when mtime unchanged")
}

func TestLoader_ReloadDetectsChange(t *testing.T) {
	base := t.TempDir()
	target := filepath.Join(base, "pricing.yaml")
	copyFixture(t, filepath.Join("..", "fixtures", "pricing.yaml"), target)

	l, err := NewLoader(base, "pricing.yaml", "llm_observability", nil)
	require.NoError(t, err)

	updated := []byte("openai:\n  gpt-4o-mini:\n    input_per_1k: 1.00\n    output_per_1k: 2.00\n")
	require.NoError(t, os.WriteFile(target, updated, 0o600))
	future := time.Now().Add(time.Hour)
	require.NoError(t, os.Chtimes(target, future, future))

	require.NoError(t, l.reload(), "reload must succeed on valid new content")

	cost, ok := l.Get().Cost("openai", "gpt-4o-mini", 1000, 1000, 0, 0)
	require.True(t, ok, "updated model still present")
	assert.InDelta(t, 3.0, cost, 0.0001, "new prices are applied: 1 + 2 per 1k")
}

// TestLoader_ReloadGoroutinePicksUpChanges proves the background goroutine
// started via Reload actually swaps the pricing table when the file changes
// on disk. Without that goroutine running, pricing edits would never reach
// requests until a proxy restart.
func TestLoader_ReloadGoroutinePicksUpChanges(t *testing.T) {
	base := t.TempDir()
	target := filepath.Join(base, "pricing.yaml")
	copyFixture(t, filepath.Join("..", "fixtures", "pricing.yaml"), target)

	l, err := NewLoader(base, "pricing.yaml", "llm_observability", nil)
	require.NoError(t, err)
	l.SetReloadInterval(20 * time.Millisecond)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		l.Reload(ctx)
		close(done)
	}()

	// Before any rewrite, the loader holds the fixture's prices.
	costBefore, ok := l.Get().Cost("openai", "gpt-4o-mini", 1000, 1000, 0, 0)
	require.True(t, ok, "fixture model must resolve initially")
	assert.InDelta(t, 0.00075, costBefore, 1e-9, "fixture prices apply before rewrite")

	updated := []byte("openai:\n  gpt-4o-mini:\n    input_per_1k: 1.00\n    output_per_1k: 2.00\n")
	require.NoError(t, os.WriteFile(target, updated, 0o600))
	future := time.Now().Add(time.Hour)
	require.NoError(t, os.Chtimes(target, future, future))

	deadline := time.Now().Add(2 * time.Second)
	for {
		cost, ok := l.Get().Cost("openai", "gpt-4o-mini", 1000, 1000, 0, 0)
		if ok && cost > 2.5 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("background reloader did not pick up rewrite within deadline")
		}
		time.Sleep(10 * time.Millisecond)
	}

	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Reload loop did not exit after cancel")
	}
}

func TestLoader_ReloadBackgroundLoopCancellation(t *testing.T) {
	base := t.TempDir()
	copyFixture(t, filepath.Join("..", "fixtures", "pricing.yaml"), filepath.Join(base, "pricing.yaml"))
	l, err := NewLoader(base, "pricing.yaml", "llm_observability", nil)
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		l.Reload(ctx)
		close(done)
	}()
	cancel()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Reload loop did not exit on context cancel")
	}
}

func TestNewLoader_PathValidation(t *testing.T) {
	base := t.TempDir()
	copyFixture(t, filepath.Join("..", "fixtures", "pricing.yaml"), filepath.Join(base, "pricing.yaml"))

	cases := []struct {
		name    string
		relPath string
	}{
		{"traversal", "../../etc/passwd"},
		{"absolute", "/etc/passwd"},
		{"slash in basename", "sub/pricing.yaml"},
		{"control chars", "pricing\x00.yaml"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewLoader(base, tc.relPath, "llm_observability", nil)
			require.Error(t, err, "NewLoader must reject %q", tc.relPath)
		})
	}

	// Empty relPath is no longer a validation error: the loader treats it
	// as "no override file, defaults only" so cost metadata is still
	// emitted for the embedded models out of the box.
	t.Run("empty falls back to defaults", func(t *testing.T) {
		l, err := NewLoader(base, "", "llm_observability", nil)
		require.NoError(t, err, "empty relPath should yield a defaults-only loader")
		require.NotNil(t, l, "loader must be returned")
		require.False(t, l.WatchesFile(), "no file watching when no override is given")
		_, ok := l.Get().Cost("openai", "gpt-4o-mini", 1000, 1000, 0, 0)
		assert.True(t, ok, "embedded defaults should still resolve gpt-4o-mini")
	})
}

// TestNewLoader_PathValidation_Extended covers the remaining attack shapes
// called out in C2: dot references, embedded traversal segments, and a
// newline in the basename. The basename regex must reject each one even
// though filepath.Clean would otherwise collapse them.
func TestNewLoader_PathValidation_Extended(t *testing.T) {
	base := t.TempDir()
	copyFixture(t, filepath.Join("..", "fixtures", "pricing.yaml"), filepath.Join(base, "pricing.yaml"))

	cases := []struct {
		name    string
		relPath string
	}{
		{"dot", "."},
		{"dotdot", ".."},
		{"relative traversal", "../pricing.yaml"},
		{"embedded slash", "pri/cing.yaml"},
		{"newline", "pricing\n.yaml"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewLoader(base, tc.relPath, "llm_observability", nil)
			require.Error(t, err, "NewLoader must reject %q", tc.relPath)
		})
	}
}

// TestNewLoader_ValidBasenameLoads proves the allowlist is exclusive: a
// basename containing only safe characters under baseDir loads. Without this
// a regression that over-tightened the regex would silently break valid
// deployments.
func TestNewLoader_ValidBasenameLoads(t *testing.T) {
	base := t.TempDir()
	copyFixture(t, filepath.Join("..", "fixtures", "pricing.yaml"), filepath.Join(base, "pricing-v2_prod.yaml"))

	l, err := NewLoader(base, "pricing-v2_prod.yaml", "llm_observability", nil)
	require.NoError(t, err, "basename with _, -, . must load")
	require.NotNil(t, l.Get(), "table populated")
}

// TestNewLoader_SymlinkOutsideBaseDirRejected constructs a symlink under
// baseDir that points to a file outside it. O_NOFOLLOW must refuse to open
// the symlink even though the symlink path itself is a valid basename under
// baseDir.
func TestNewLoader_SymlinkOutsideBaseDirRejected(t *testing.T) {
	outside := t.TempDir()
	target := filepath.Join(outside, "evil.yaml")
	copyFixture(t, filepath.Join("..", "fixtures", "pricing.yaml"), target)

	base := t.TempDir()
	link := filepath.Join(base, "pricing.yaml")
	require.NoError(t, os.Symlink(target, link), "symlink setup")

	_, err := NewLoader(base, "pricing.yaml", "llm_observability", nil)
	require.Error(t, err, "O_NOFOLLOW must reject symlink even when it points outside baseDir")
}

func TestNewLoader_SymlinkRejected(t *testing.T) {
	base := t.TempDir()
	concrete := filepath.Join(base, "real.yaml")
	copyFixture(t, filepath.Join("..", "fixtures", "pricing.yaml"), concrete)

	link := filepath.Join(base, "pricing.yaml")
	require.NoError(t, os.Symlink(concrete, link), "symlink setup")

	_, err := NewLoader(base, "pricing.yaml", "llm_observability", nil)
	require.Error(t, err, "O_NOFOLLOW must reject symlinked targets")
}

func TestTableCost_NilSafe(t *testing.T) {
	var t1 *Table
	cost, ok := t1.Cost("x", "y", 1, 1, 0, 0)
	assert.False(t, ok, "nil table reports unknown")
	assert.Zero(t, cost, "nil table returns zero cost")
	assert.False(t, t1.Has("x", "y"), "nil table has nothing")
}

func TestLoaderGet_NilSafe(t *testing.T) {
	var l *Loader
	assert.Nil(t, l.Get(), "nil loader returns nil table")
}

// TestNewLoader_RejectsOversizedFile_FixesM4 proves the loader bounds reads
// at maxPricingBytes so a hostile file cannot exhaust process memory.
func TestNewLoader_RejectsOversizedFile_FixesM4(t *testing.T) {
	base := t.TempDir()
	target := filepath.Join(base, "pricing.yaml")

	// Build a YAML payload larger than the cap. We pad with valid YAML
	// comments so a partial read would still fail the size check rather
	// than the parser.
	header := "openai:\n"
	bigComment := make([]byte, maxPricingBytes+1024)
	for i := range bigComment {
		bigComment[i] = ' '
	}
	bigComment[0] = '#'
	bigComment[len(bigComment)-1] = '\n'
	payload := append([]byte(header), bigComment...)
	require.NoError(t, os.WriteFile(target, payload, 0o600))

	_, err := NewLoader(base, "pricing.yaml", "llm_observability", nil)
	require.Error(t, err, "oversized pricing file must be rejected")
	assert.Contains(t, err.Error(), "exceeds", "rejection must reference the byte cap")
}
