package types

// EffectiveSetup is the caller-scoped answer to "what may this caller
// use on the Agent Network?" — the account's proxy endpoint plus the
// providers and models the caller's groups authorize. It intentionally
// carries display metadata only: no keys, no upstream URLs, no policy or
// guardrail structure, and no hint of providers the caller cannot reach.
type EffectiveSetup struct {
	// Configured is false when the account has no Agent Network set up or
	// when nothing is authorized for the caller's groups — the two cases
	// are deliberately indistinguishable so the response leaks nothing
	// about what exists for others.
	Configured bool
	// Endpoint is the account's proxy base URL
	// ("https://<subdomain>.<cluster>"), reachable over the NetBird tunnel
	// only. Empty when Configured is false.
	Endpoint string
	// Providers lists the providers at least one applicable policy
	// authorizes for the caller, in the account's created_at order.
	Providers []EffectiveProvider
}

// EffectiveProvider is one authorized provider in an EffectiveSetup.
type EffectiveProvider struct {
	// Name is the operator-assigned label, e.g. "Bedrock prod".
	Name string
	// CatalogID names the catalog entry, e.g. "anthropic_api".
	CatalogID string
	// APIFlavor is the request-body shape the provider speaks — the
	// catalog entry's parser id ("anthropic", "openai"); empty when the
	// proxy dispatches the provider by URL path instead.
	APIFlavor string
	// AllModelsAllowed is true when no model allowlist restricts this
	// provider for the caller. Models then lists the declared/catalog
	// models as a courtesy (possibly none for gateway-style providers).
	AllModelsAllowed bool
	// Models is the effective model allowlist for the caller, or the
	// declared/catalog models when AllModelsAllowed is true.
	Models []string
}
