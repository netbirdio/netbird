// Package llm_limit_check is the SlotOnRequest middleware that asks
// management which agent-network policy "pays" for the current LLM
// request. On allow, it stamps the selected policy id, attribution
// group id, and effective window length onto the metadata bag so the
// post-flight llm_limit_record middleware can tick the right counters.
// On deny, it returns a 403 carrying the canonical llm_policy.* deny
// code surfaced by management.
package llm_limit_check

import (
	"github.com/netbirdio/netbird/proxy/internal/middleware"
	"github.com/netbirdio/netbird/proxy/internal/middleware/builtin"
)

// ID is the registry identifier for this middleware.
const ID = "llm_limit_check"

// Factory builds a configured llm_limit_check instance. The factory
// has no per-target config — it pulls the management gRPC client from
// the package-level FactoryContext at construction time. A nil
// MgmtClient on the context is allowed; the middleware then becomes
// a no-op pass-through (allow without attribution) so a partially
// wired environment doesn't break the chain.
type Factory struct{}

// ID returns the registry identifier matching the middleware ID.
func (Factory) ID() string { return ID }

// New ignores the rawConfig payload (no per-target config today) and
// returns a Middleware bound to the FactoryContext's MgmtClient.
func (Factory) New(_ []byte) (middleware.Middleware, error) {
	ctx := builtin.Context()
	return New(ctx.MgmtClient, ctx.Logger), nil
}

func init() {
	builtin.Register(Factory{})
}
