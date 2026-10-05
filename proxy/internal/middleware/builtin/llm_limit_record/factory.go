// Package llm_limit_record is the SlotOnResponse middleware that
// posts the served request's token + cost deltas back to management
// so the per-(user, group, window) consumption counters tick. Reads
// the attribution metadata stamped by llm_limit_check on the request
// leg + the token / cost metadata stamped by llm_response_parser and
// cost_meter; skips the write entirely when no attribution metadata
// is present (e.g. catch-all-allow policy with no caps configured).
package llm_limit_record

import (
	"github.com/netbirdio/netbird/proxy/internal/middleware"
	"github.com/netbirdio/netbird/proxy/internal/middleware/builtin"
)

// ID is the registry identifier for this middleware.
const ID = "llm_limit_record"

// Factory builds a configured llm_limit_record instance bound to the
// FactoryContext's MgmtClient. nil-MgmtClient disables the post-flight
// write entirely (no-op pass-through), matching the request-leg gate's
// behaviour so a partially wired environment is consistent.
type Factory struct{}

// ID returns the registry identifier matching the middleware ID.
func (Factory) ID() string { return ID }

// New ignores the rawConfig payload (no per-target config today).
func (Factory) New(_ []byte) (middleware.Middleware, error) {
	ctx := builtin.Context()
	return New(ctx.MgmtClient, ctx.Logger), nil
}

func init() {
	builtin.Register(Factory{})
}
