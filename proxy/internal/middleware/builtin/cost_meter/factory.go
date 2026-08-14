package cost_meter

import (
	"bytes"
	"encoding/json"
	"fmt"

	"github.com/netbirdio/netbird/proxy/internal/llm/pricing"
	"github.com/netbirdio/netbird/proxy/internal/middleware"
	"github.com/netbirdio/netbird/proxy/internal/middleware/builtin"
)

// Config is the on-wire configuration for the middleware, synthesized by
// management (buildCostMeterConfigJSON). The proxy has no embedded price
// list: this payload is the only pricing source, and updates arrive as
// ordinary mapping pushes that rebuild the chain (and with it this
// middleware instance) — no per-request fetches, no reload loops.
type Config struct {
	Pricing *PricingConfig `json:"pricing"`
}

// PricingConfig carries the full pricing table:
//   - Defaults: parser surface ("openai"/"anthropic"/"bedrock") ->
//     normalized model id -> rates, matched against llm.provider +
//     llm.model.
//   - Providers: provider record id -> normalized model id -> rates,
//     matched against the llm.resolved_provider_id metadata llm_router
//     stamps. Entries arrive fully materialized (management folds default
//     cache rates in at synth time), so lookup order is simply
//     per-record first, defaults second.
type PricingConfig struct {
	Defaults  map[string]map[string]pricing.EntryJSON `json:"defaults"`
	Providers map[string]map[string]pricing.EntryJSON `json:"providers"`
}

// Factory builds cost_meter instances from raw config bytes.
type Factory struct{}

// ID returns the registry identifier.
func (Factory) ID() string { return ID }

// New constructs a middleware instance. Empty, null, and {} configs are
// accepted for backward compatibility with a management server that
// predates config-delivered pricing — the instance then skips every cost
// computation (unknown_model) and a warning is logged once at build time.
// Non-empty rawConfig that fails to unmarshal, or a table carrying a
// non-finite / negative rate, is rejected so misconfigurations surface at
// chain build time.
func (Factory) New(rawConfig []byte) (middleware.Middleware, error) {
	cfg, err := decodeConfig(rawConfig)
	if err != nil {
		return nil, err
	}

	if cfg.Pricing == nil {
		if logger := builtin.Context().Logger; logger != nil {
			logger.Warnf("cost_meter: no pricing table in middleware config; management predates config-delivered pricing — every request will record cost.skipped=unknown_model ($0)")
		}
		return newMiddleware(mustEmptyTable(), nil), nil
	}

	defaults, err := pricing.NewTable(cfg.Pricing.Defaults)
	if err != nil {
		return nil, fmt.Errorf("cost_meter pricing defaults: %w", err)
	}
	perRecord, err := pricing.NewEntries(cfg.Pricing.Providers)
	if err != nil {
		return nil, fmt.Errorf("cost_meter per-provider pricing: %w", err)
	}
	return newMiddleware(defaults, perRecord), nil
}

// mustEmptyTable returns a valid empty table. NewTable on a nil map cannot
// fail; the panic guard documents that invariant.
func mustEmptyTable() *pricing.Table {
	t, err := pricing.NewTable(nil)
	if err != nil {
		panic(fmt.Sprintf("cost_meter: empty pricing table must build: %v", err))
	}
	return t
}

// decodeConfig accepts empty, null, and {} configs, returning a
// zero-value Config. Non-empty payloads must parse cleanly.
func decodeConfig(rawConfig []byte) (Config, error) {
	var cfg Config
	if len(bytes.TrimSpace(rawConfig)) == 0 {
		return cfg, nil
	}
	if err := json.Unmarshal(rawConfig, &cfg); err != nil {
		return cfg, fmt.Errorf("decode config: %w", err)
	}
	return cfg, nil
}

func init() {
	builtin.Register(Factory{})
}
