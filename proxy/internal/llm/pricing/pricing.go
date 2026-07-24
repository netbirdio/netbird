// Package pricing implements the embedded-default + override pricing table
// shared by middleware that converts LLM token usage into a USD cost
// estimate. The table is hot-reloadable from a basename under the proxy
// data directory; missing override files keep the embedded defaults so
// cost annotation works without operator action.
package pricing

import (
	"bytes"
	"context"
	_ "embed"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"math"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	log "github.com/sirupsen/logrus"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
	"gopkg.in/yaml.v3"
)

//go:embed defaults_pricing.yaml
var defaultPricingYAML []byte

var (
	defaultTableOnce sync.Once
	defaultTablePtr  *Table
)

// DefaultTable returns the pricing table embedded in the binary. The result
// is parsed once and shared; callers must not mutate the returned value.
// Cost annotation works without any operator action because every loader
// starts with this table.
func DefaultTable() *Table {
	defaultTableOnce.Do(func() {
		t, err := parsePricingBytes(defaultPricingYAML)
		if err != nil {
			panic(fmt.Sprintf("llmobs: embedded default pricing failed to parse: %v", err))
		}
		defaultTablePtr = t
	})
	return defaultTablePtr
}

// mergeOver returns a new Table containing every entry from base, with any
// matching entry from overlay replacing the base value. Either argument may
// be nil. Result is a fresh allocation so callers can mutate / Store safely.
func mergeOver(base, overlay *Table) *Table {
	if overlay == nil || len(overlay.entries) == 0 {
		return base
	}
	if base == nil || len(base.entries) == 0 {
		return overlay
	}
	out := make(map[string]map[string]Entry, len(base.entries))
	for provider, models := range base.entries {
		inner := make(map[string]Entry, len(models))
		for model, e := range models {
			inner[model] = e
		}
		out[provider] = inner
	}
	for provider, models := range overlay.entries {
		inner, ok := out[provider]
		if !ok {
			inner = make(map[string]Entry, len(models))
			out[provider] = inner
		}
		for model, e := range models {
			inner[model] = e
		}
	}
	return &Table{entries: out}
}

// Entry is a single model's input and output pricing, expressed in USD per
// 1000 tokens.
//
// CachedInputPer1K applies to OpenAI's cached prompt tokens, which are a
// subset of input_tokens — when set, the cached portion is billed at this
// rate and the non-cached remainder at InputPer1K. Zero means "no discount
// configured", and cached tokens are billed at InputPer1K (matches current
// behaviour where cached counts weren't extracted at all).
//
// CacheReadPer1K and CacheCreationPer1K apply to Anthropic's two prompt-
// cache fields, which are additive to input_tokens: cache_read is the
// cheaper read-from-cache rate, cache_creation is the more expensive
// write-to-cache rate. Zero means "no rate configured" and the
// corresponding token bucket is billed at InputPer1K. This is more
// accurate than today's behaviour, where Anthropic's cache tokens are
// ignored and not charged at all.
type Entry struct {
	InputPer1K         float64
	OutputPer1K        float64
	CachedInputPer1K   float64
	CacheReadPer1K     float64
	CacheCreationPer1K float64
}

// Table is a provider-to-model pricing lookup. Instances are immutable once
// built and are swapped atomically by Loader.
type Table struct {
	entries map[string]map[string]Entry
}

// Cost returns the estimated USD cost for the given token counts. ok is
// false when the provider or model is not present in the table; the caller
// can still emit token metrics with a model=unknown label.
//
// Provider-shape semantics for cached / cache-creation counts:
//
//   - OpenAI: cachedInput is a SUBSET of inTokens. The cached portion is
//     billed at CachedInputPer1K (or InputPer1K when no override), and the
//     non-cached remainder of inTokens at InputPer1K. cacheCreation is
//     ignored (OpenAI has no analogue).
//   - Anthropic: cachedInput (cache_read) and cacheCreation are ADDITIVE to
//     inTokens. The three buckets are billed at CacheReadPer1K,
//     CacheCreationPer1K, and InputPer1K respectively, each falling back
//     to InputPer1K when the corresponding rate is zero.
//   - Other providers: cached and cacheCreation are ignored; cost is
//     inTokens*InputPer1K + outTokens*OutputPer1K.
func (t *Table) Cost(provider, model string, inTokens, outTokens, cachedInput, cacheCreation int64) (float64, bool) {
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
	if t == nil {
		return 0, false
	}
	byModel, ok := t.entries[provider]
	if !ok {
		return 0, false
	}
	entry, ok := byModel[model]
	if !ok {
		return 0, false
	}
	output := (float64(outTokens) / 1000.0) * entry.OutputPer1K
	switch provider {
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
		total := nonCached + cached + output
		log.Warnf("pricing %s/%s: non_cached_input %d/1000×$%v=$%.6f + cached_input %d/1000×$%v=$%.6f + output %d/1000×$%v=$%.6f => $%.6f",
			provider, model, inTokens-clamped, entry.InputPer1K, nonCached, clamped, cachedRate, cached, outTokens, entry.OutputPer1K, output, total)
		return total, true
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
		total := input + read + create + output
		log.Warnf("pricing %s/%s: input %d/1000×$%v=$%.6f + cache_read %d/1000×$%v=$%.6f + cache_creation %d/1000×$%v=$%.6f + output %d/1000×$%v=$%.6f => $%.6f",
			provider, model, inTokens, entry.InputPer1K, input, cachedInput, readRate, read, cacheCreation, createRate, create, outTokens, entry.OutputPer1K, output, total)
		return total, true
	default:
		input := float64(inTokens) / 1000.0 * entry.InputPer1K
		total := input + output
		log.Warnf("pricing %s/%s: input %d/1000×$%v=$%.6f + output %d/1000×$%v=$%.6f => $%.6f",
			provider, model, inTokens, entry.InputPer1K, input, outTokens, entry.OutputPer1K, output, total)
		return total, true
	}
}

// Has reports whether the provider/model pair is present in the table.
func (t *Table) Has(provider, model string) bool {
	if t == nil {
		return false
	}
	byModel, ok := t.entries[provider]
	if !ok {
		return false
	}
	_, ok = byModel[model]
	return ok
}

// pricingFile mirrors the on-disk YAML schema. Keys are provider names; the
// nested map keys are model names.
type pricingFile map[string]map[string]struct {
	InputPer1K         float64 `yaml:"input_per_1k"`
	OutputPer1K        float64 `yaml:"output_per_1k"`
	CachedInputPer1K   float64 `yaml:"cached_input_per_1k"`
	CacheReadPer1K     float64 `yaml:"cache_read_per_1k"`
	CacheCreationPer1K float64 `yaml:"cache_creation_per_1k"`
}

const (
	// ReloadInterval is the mtime-poll cadence for the background reloader.
	ReloadInterval = 30 * time.Second

	// errorBackoff bounds how often the loader logs a repeated parse error.
	errorBackoff = 5 * time.Minute
)

var basenameRegex = regexp.MustCompile(`^[a-zA-Z0-9._-]+$`)

// Loader is a confined, hot-reloadable pricing table reader. Construction
// must succeed against the target file; subsequent reload failures keep the
// previously-loaded table so callers never observe a blank price list.
type Loader struct {
	baseDir  string
	fullPath string
	pluginID string
	table    atomic.Pointer[Table]
	mtime    atomic.Int64
	failures metric.Int64Counter
	interval time.Duration
}

// NewLoader returns a pricing loader that overlays an optional file-based
// table on top of the embedded defaults. Missing override file, baseDir, or
// relPath is not an error: the loader keeps the embedded defaults so cost
// metadata is still emitted for known models.
//
// Errors:
//   - bad basename, traversal segment, or absolute relPath are rejected so a
//     misconfigured target surfaces immediately.
//   - permission errors and YAML parse errors keep the defaults but log a
//     warning; cost annotation does not silently break.
//
// failures is optional; pass nil in tests that do not care about
// reload-failure telemetry.
func NewLoader(baseDir, relPath, pluginID string, failures metric.Int64Counter) (*Loader, error) {
	defaults := DefaultTable()
	l := &Loader{
		baseDir:  baseDir,
		pluginID: pluginID,
		failures: failures,
	}
	l.table.Store(defaults)

	if strings.TrimSpace(baseDir) == "" || strings.TrimSpace(relPath) == "" {
		return l, nil
	}

	full, err := resolveMiddlewareDataPath(baseDir, relPath)
	if err != nil {
		return nil, err
	}
	l.fullPath = full

	overlay, mtime, err := loadPricing(full)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			// Override file is optional. Defaults already stored.
			return l, nil
		}
		// Symlink rejection, oversize file, parse failure, permission errors
		// — surface so a misconfigured operator sees the problem instead of
		// silently running with stale defaults.
		return nil, fmt.Errorf("load pricing %s: %w", full, err)
	}
	l.table.Store(mergeOver(defaults, overlay))
	l.mtime.Store(mtime.UnixNano())
	return l, nil
}

// Get returns the current pricing table. The returned pointer is immutable;
// callers must not mutate its contents.
func (l *Loader) Get() *Table {
	if l == nil {
		return nil
	}
	return l.table.Load()
}

// WatchesFile reports whether this loader is bound to an override file on
// disk. False for defaults-only loaders (no operator override given).
// Callers use this to decide whether to spawn the mtime-poll goroutine.
func (l *Loader) WatchesFile() bool {
	if l == nil {
		return false
	}
	return l.fullPath != ""
}

// SetReloadInterval overrides the mtime-poll cadence used by Reload. Calls
// after Reload has started have no effect on the running loop. Intended for
// tests; production code uses the default ReloadInterval.
func (l *Loader) SetReloadInterval(d time.Duration) {
	if l == nil || d <= 0 {
		return
	}
	l.interval = d
}

// Reload runs a polling loop that checks the pricing file mtime every
// ReloadInterval (or the value passed to SetReloadInterval). Returns when
// ctx is cancelled.
func (l *Loader) Reload(ctx context.Context) {
	if l == nil {
		return
	}
	interval := l.interval
	if interval <= 0 {
		interval = ReloadInterval
	}
	t := time.NewTicker(interval)
	defer t.Stop()

	var lastErrAt time.Time
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := l.reload(); err != nil {
				if l.failures != nil {
					l.failures.Add(ctx, 1, metric.WithAttributes(
						attribute.String("plugin", l.pluginID),
					))
				}
				now := time.Now()
				if now.Sub(lastErrAt) >= errorBackoff {
					log.Warnf("llmobs: pricing reload failed for %s: %v", l.fullPath, err)
					lastErrAt = now
				}
			}
		}
	}
}

// reload performs a single-shot mtime check and reload. The reloaded
// override file is merged on top of the embedded defaults; missing override
// (e.g. operator deleted the file) is not an error and reverts to defaults.
func (l *Loader) reload() error {
	if l.fullPath == "" {
		// Defaults-only loader; nothing on disk to reload.
		return nil
	}
	mtime, err := statMtime(l.fullPath)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			// File was removed since startup. Drop back to defaults and
			// reset mtime so a future re-creation triggers a reload.
			l.table.Store(DefaultTable())
			l.mtime.Store(0)
			return nil
		}
		return err
	}
	if mtime.UnixNano() == l.mtime.Load() {
		return nil
	}

	overlay, newMtime, err := loadPricing(l.fullPath)
	if err != nil {
		return err
	}
	l.table.Store(mergeOver(DefaultTable(), overlay))
	l.mtime.Store(newMtime.UnixNano())
	return nil
}

// resolveMiddlewareDataPath validates relPath is a safe basename and resolves
// it under baseDir. An additional cleaned-prefix check guards against
// CVE-style edge cases where Join is used with trailing path segments.
func resolveMiddlewareDataPath(baseDir, relPath string) (string, error) {
	if strings.TrimSpace(baseDir) == "" {
		return "", errors.New("middleware-data-dir is not configured")
	}
	if relPath == "" {
		return "", errors.New("pricing path is empty")
	}
	if !basenameRegex.MatchString(relPath) {
		return "", fmt.Errorf("pricing path %q is not a safe basename", relPath)
	}
	if filepath.IsAbs(relPath) {
		return "", fmt.Errorf("pricing path %q must be a basename, not absolute", relPath)
	}

	cleanBase, err := filepath.Abs(filepath.Clean(baseDir))
	if err != nil {
		return "", fmt.Errorf("resolve middleware-data-dir: %w", err)
	}
	full := filepath.Join(cleanBase, relPath)
	cleanedFull := filepath.Clean(full)
	if !strings.HasPrefix(cleanedFull, cleanBase+string(filepath.Separator)) && cleanedFull != cleanBase {
		return "", fmt.Errorf("pricing path %q escapes middleware-data-dir", relPath)
	}
	return cleanedFull, nil
}

func parsePricingBytes(data []byte) (*Table, error) {
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)

	var raw pricingFile
	if err := dec.Decode(&raw); err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("decode pricing yaml: %w", err)
	}

	out := make(map[string]map[string]Entry, len(raw))
	for provider, models := range raw {
		inner := make(map[string]Entry, len(models))
		for model, entry := range models {
			for field, v := range map[string]float64{
				"input_per_1k":          entry.InputPer1K,
				"output_per_1k":         entry.OutputPer1K,
				"cached_input_per_1k":   entry.CachedInputPer1K,
				"cache_read_per_1k":     entry.CacheReadPer1K,
				"cache_creation_per_1k": entry.CacheCreationPer1K,
			} {
				if v < 0 || math.IsNaN(v) || math.IsInf(v, 0) {
					return nil, fmt.Errorf("pricing %s/%s: %s must be a finite, non-negative rate, got %v", provider, model, field, v)
				}
			}
			inner[model] = Entry{
				InputPer1K:         entry.InputPer1K,
				OutputPer1K:        entry.OutputPer1K,
				CachedInputPer1K:   entry.CachedInputPer1K,
				CacheReadPer1K:     entry.CacheReadPer1K,
				CacheCreationPer1K: entry.CacheCreationPer1K,
			}
		}
		out[provider] = inner
	}
	return &Table{entries: out}, nil
}
