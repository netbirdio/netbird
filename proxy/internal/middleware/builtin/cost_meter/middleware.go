// Package cost_meter implements the SlotOnResponse middleware that
// converts token-usage metadata emitted by llm_response_parser into a
// per-request USD cost estimate. The middleware uses the shared pricing
// loader so operator pricing overrides apply to the chain.
package cost_meter

import (
	"context"
	"fmt"
	"strconv"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/proxy/internal/llm/pricing"
	"github.com/netbirdio/netbird/proxy/internal/middleware"
	"github.com/netbirdio/netbird/proxy/internal/middleware/builtin"
)

// ID is the registry identifier for this middleware.
const ID = "cost_meter"

// Version is the implementation version emitted via the spec merge.
const Version = "1.0.0"

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
	middleware.KeyCostUSDTotal,
	middleware.KeyCostSkipped,
}

// Middleware computes a per-response cost estimate from the token
// counts emitted upstream by llm_response_parser.
type Middleware struct {
	loader *pricing.Loader
	// cancel stops this instance's pricing-reload goroutine. Non-nil only
	// when the loader watches an override file; Close calls it so a chain
	// rebuild doesn't leak a poll goroutine per retired instance.
	cancel context.CancelFunc
}

// newMiddleware constructs a Middleware bound to the given pricing loader.
// cancel may be nil (defaults-only loader with no reloader to stop).
func newMiddleware(loader *pricing.Loader, cancel context.CancelFunc) *Middleware {
	return &Middleware{loader: loader, cancel: cancel}
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

// Close stops this instance's pricing-reload goroutine, if any. Called by
// the chain when a rebuild retires the instance, so the mtime-poll loop
// doesn't outlive the chain it belonged to. Safe to call on a nil receiver
// and on an instance with no reloader.
func (m *Middleware) Close() error {
	if m != nil && m.cancel != nil {
		m.cancel()
	}
	return nil
}

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

	table := m.loader.Get()
	cost, ok := table.Cost(provider, model, inTokens, outTokens, cachedTokens, cacheCreationTokens)
	if !ok {
		if logger := auditLogger(); logger != nil {
			logger.WithFields(log.Fields{"middleware": ID, "provider": provider, "model": model}).
				Warnf("cost skipped: no pricing entry (tokens input=%d output=%d cache_read=%d cache_creation=%d)",
					inTokens, outTokens, cachedTokens, cacheCreationTokens)
		}
		out.Metadata = skip(skipUnknownModel)
		return out, nil
	}

	if logger := auditLogger(); logger != nil {
		logger.WithFields(log.Fields{"middleware": ID, "provider": provider, "model": model}).
			Warnf("cost computed: tokens input=%d output=%d cache_read=%d cache_creation=%d => cost_usd=%.6f",
				inTokens, outTokens, cachedTokens, cacheCreationTokens, cost)
	}

	out.Metadata = []middleware.KV{
		{Key: middleware.KeyCostUSDTotal, Value: fmt.Sprintf("%.6f", cost)},
	}
	return out, nil
}

// auditLogger returns the logger the cost-audit lines are emitted on. The
// lines carry WARN severity so they surface on default production log
// levels, but emission is not gated on any level check here — filtering is
// left entirely to the logger's own configuration. Falls back to the
// process-wide standard logger when the middleware context carries none, so
// the audit trail never silently disappears.
func auditLogger() *log.Logger {
	if logger := builtin.Context().Logger; logger != nil {
		return logger
	}
	return log.StandardLogger()
}

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
