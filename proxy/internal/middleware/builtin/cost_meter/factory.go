package cost_meter

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"

	"github.com/netbirdio/netbird/proxy/internal/llm/pricing"
	"github.com/netbirdio/netbird/proxy/internal/middleware"
	"github.com/netbirdio/netbird/proxy/internal/middleware/builtin"
)

// defaultPricingFilename is the basename probed inside the proxy data
// directory when no override is configured.
const defaultPricingFilename = "pricing.yaml"

// Config is the on-wire configuration for the middleware.
type Config struct {
	// PricingPath optionally overrides the basename of the pricing
	// file probed inside the proxy data directory. When empty the
	// loader falls back to "pricing.yaml".
	PricingPath string `json:"pricing_path"`
}

// Factory builds cost_meter instances from raw config bytes.
type Factory struct{}

// ID returns the registry identifier.
func (Factory) ID() string { return ID }

// New constructs a middleware instance. Empty, null, and {} configs
// are accepted; non-empty rawConfig that fails to unmarshal is
// rejected so misconfigurations surface at chain build time. The
// pricing loader is built once per instance and reused across
// invocations.
func (Factory) New(rawConfig []byte) (middleware.Middleware, error) {
	cfg, err := decodeConfig(rawConfig)
	if err != nil {
		return nil, err
	}

	fctx := builtin.Context()
	pricingPath := cfg.PricingPath
	if pricingPath == "" {
		pricingPath = defaultPricingFilename
	}

	loader, err := pricing.NewLoader(fctx.DataDir, pricingPath, ID, nil)
	if err != nil {
		return nil, fmt.Errorf("init pricing loader: %w", err)
	}

	cancel := startReloader(fctx.Context, loader)

	return newMiddleware(loader, cancel), nil
}

// startReloader binds the loader's mtime-poll goroutine to a context
// derived from the proxy-lifetime context and returns its cancel func so
// the owning middleware can stop the goroutine on teardown. Returns nil
// when there's nothing to watch (nil context or defaults-only loader), in
// which case the middleware's Close is a no-op.
func startReloader(ctx context.Context, loader *pricing.Loader) context.CancelFunc {
	if ctx == nil || !loader.WatchesFile() {
		return nil
	}
	cctx, cancel := context.WithCancel(ctx)
	go loader.Reload(cctx)
	return cancel
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
