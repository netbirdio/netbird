package pricing

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"math"
	"os"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v3"
)

// DefaultFileName is the basename probed under management's datadir when
// AgentNetwork.PricingDefaultsFile doesn't configure an explicit path.
const DefaultFileName = "defaults_llm_pricing.yaml"

// ReloadInterval is the cadence at which the pricing file's mtime is
// polled for changes.
const ReloadInterval = time.Minute

// maxFileBytes bounds the pricing file read so a misconfigured path
// (pointed at a huge file) cannot exhaust process memory.
const maxFileBytes = 4 << 20

// pricingFile mirrors the on-disk YAML schema — the same schema the
// proxy's retired embedded defaults_pricing.yaml used, so files written
// for it keep working. Keys are pricing surfaces ("openai", "anthropic",
// "bedrock"); nested keys are normalized model ids.
type pricingFile map[string]map[string]struct {
	InputPer1k         float64 `yaml:"input_per_1k"`
	OutputPer1k        float64 `yaml:"output_per_1k"`
	CachedInputPer1k   float64 `yaml:"cached_input_per_1k"`
	CacheReadPer1k     float64 `yaml:"cache_read_per_1k"`
	CacheCreationPer1k float64 `yaml:"cache_creation_per_1k"`
}

// fileState tracks the watched pricing file across reloads.
var fileState struct {
	mu    sync.Mutex
	path  string
	mtime int64
}

// LoadFile loads the management-side pricing defaults file and makes it
// the live table (merged entry-whole over the compiled-in fallback; see
// DefaultTable). The path stays registered for the periodic reloader, so
// later edits — or the file (re)appearing after deletion — are picked up
// without a restart.
//
// required governs the missing-file case: true for an explicitly
// configured path (a typo must fail startup rather than silently bill
// with built-ins the operator believes they replaced), false for the
// conventional <datadir>/defaults_llm_pricing.yaml probe (absent file =
// compiled-in defaults, still watched in case it appears). A file that
// exists but is malformed is always an error at load time.
func LoadFile(path string, required bool) error {
	if path == "" {
		return nil
	}
	fileState.mu.Lock()
	fileState.path = path
	fileState.mu.Unlock()

	table, mtime, err := readFile(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) && !required {
			log.Infof("agent-network pricing defaults file %s not present; serving built-in defaults", path)
			return nil
		}
		return err
	}
	storeFileTable(table, mtime)
	log.Infof("agent-network pricing defaults loaded from %s", path)
	return nil
}

// StartReloader launches the periodic mtime-poll goroutine for the file
// registered by LoadFile. Runtime failures are lenient — a parse error
// keeps the previously loaded table and logs a warning; a deleted file
// reverts to the compiled-in defaults — so a mid-edit save can never
// take pricing down. Returns immediately when no path was registered.
func StartReloader(ctx context.Context, interval time.Duration) {
	fileState.mu.Lock()
	path := fileState.path
	fileState.mu.Unlock()
	if path == "" {
		return
	}
	if interval <= 0 {
		interval = ReloadInterval
	}
	go func() {
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				reload()
			}
		}
	}()
}

// reload performs one mtime check + reload cycle.
func reload() {
	fileState.mu.Lock()
	path, lastMtime := fileState.path, fileState.mtime
	fileState.mu.Unlock()

	log.Debugf("agent-network pricing defaults reload: checking %s for changes", path)

	st, err := os.Stat(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			// File removed (or not yet created): serve compiled-in
			// defaults and reset mtime so a future (re)appearance loads.
			if mergedTable.Swap(nil) != nil {
				log.Warnf("agent-network pricing defaults file %s removed; reverting to built-in defaults", path)
			}
			setMtime(0)
			return
		}
		log.Warnf("agent-network pricing defaults reload: stat %s: %v", path, err)
		return
	}
	if st.ModTime().UnixNano() == lastMtime {
		log.Debugf("agent-network pricing defaults %s unchanged since last check", path)
		return
	}

	table, mtime, err := readFile(path)
	if err != nil {
		// Keep the previously loaded table — never blank prices because
		// an operator saved mid-edit.
		log.Warnf("agent-network pricing defaults reload failed for %s (keeping previous table): %v", path, err)
		return
	}
	storeFileTable(table, mtime)
	log.Infof("agent-network pricing defaults reloaded from %s", path)
}

func readFile(path string) (map[string]map[string]Entry, int64, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, 0, fmt.Errorf("open pricing defaults %s: %w", path, err)
	}
	defer func() { _ = f.Close() }()

	st, err := f.Stat()
	if err != nil {
		return nil, 0, fmt.Errorf("stat pricing defaults %s: %w", path, err)
	}
	data, err := io.ReadAll(io.LimitReader(f, maxFileBytes+1))
	if err != nil {
		return nil, 0, fmt.Errorf("read pricing defaults %s: %w", path, err)
	}
	if len(data) > maxFileBytes {
		return nil, 0, fmt.Errorf("pricing defaults %s exceeds %d bytes", path, maxFileBytes)
	}
	table, err := parsePricingYAML(data)
	if err != nil {
		return nil, 0, fmt.Errorf("parse pricing defaults %s: %w", path, err)
	}
	return table, st.ModTime().UnixNano(), nil
}

// storeFileTable merges the parsed file over the compiled-in base and
// publishes the result as the live table. File entries replace the
// built-in entry for the same (surface, model) whole — they are not
// field-merged — and surfaces/models the file doesn't mention keep the
// built-in rates, so a partial file only needs the entries it changes.
func storeFileTable(table map[string]map[string]Entry, mtime int64) {
	base := compiledBase()
	merged := make(map[string]map[string]Entry, len(base)+len(table))
	for surface, models := range base {
		inner := make(map[string]Entry, len(models))
		for id, e := range models {
			inner[id] = e
		}
		merged[surface] = inner
	}
	for surface, models := range table {
		inner, ok := merged[surface]
		if !ok {
			inner = make(map[string]Entry, len(models))
			merged[surface] = inner
		}
		for id, e := range models {
			inner[id] = e
		}
	}
	mergedTable.Store(&merged)
	setMtime(mtime)
}

func setMtime(v int64) {
	fileState.mu.Lock()
	fileState.mtime = v
	fileState.mu.Unlock()
}

// parsePricingYAML decodes and validates the pricing YAML. Unknown
// fields are rejected (typos surface instead of silently pricing at 0)
// and every rate must be a finite, non-negative USD amount — the same
// constraints the HTTP API enforces on operator per-provider prices.
func parsePricingYAML(data []byte) (map[string]map[string]Entry, error) {
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)

	var raw pricingFile
	if err := dec.Decode(&raw); err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("decode yaml: %w", err)
	}

	out := make(map[string]map[string]Entry, len(raw))
	for surface, models := range raw {
		inner := make(map[string]Entry, len(models))
		for model, e := range models {
			for field, v := range map[string]float64{
				"input_per_1k":          e.InputPer1k,
				"output_per_1k":         e.OutputPer1k,
				"cached_input_per_1k":   e.CachedInputPer1k,
				"cache_read_per_1k":     e.CacheReadPer1k,
				"cache_creation_per_1k": e.CacheCreationPer1k,
			} {
				if v < 0 || math.IsNaN(v) || math.IsInf(v, 0) {
					return nil, fmt.Errorf("%s/%s: %s must be a finite, non-negative rate, got %v", surface, model, field, v)
				}
			}
			inner[model] = Entry{
				InputPer1k:         e.InputPer1k,
				OutputPer1k:        e.OutputPer1k,
				CachedInputPer1k:   e.CachedInputPer1k,
				CacheReadPer1k:     e.CacheReadPer1k,
				CacheCreationPer1k: e.CacheCreationPer1k,
			}
		}
		out[surface] = inner
	}
	return out, nil
}
