package types

import "time"

// AgentConfig is the caller-scoped answer to "what may this caller
// use on the Agent Network?" — the account's proxy endpoint plus the
// providers and models the caller's groups authorize. It intentionally
// carries display metadata only: no keys, no upstream URLs, no policy or
// guardrail structure, and no hint of providers the caller cannot reach.
type AgentConfig struct {
	// Configured is false only when the account has no Agent Network set
	// up. A caller no policy covers yet still reads as configured, with an
	// empty Providers list: every member gets the same connection config,
	// and the empty list is what tells them to ask for access.
	Configured bool
	// Endpoint is the account's proxy base URL
	// ("https://<subdomain>.<cluster>"), reachable over the NetBird tunnel
	// only. Empty when Configured is false. Handing it to a member the
	// policies do not cover authorizes nothing on its own — the proxy
	// still refuses every request no policy permits.
	Endpoint string
	// Providers lists the providers at least one applicable policy
	// authorizes for the caller, in the account's created_at order.
	Providers []AgentConfigProvider
}

// AgentConfigProvider is one authorized provider in an AgentConfig.
type AgentConfigProvider struct {
	// ID is the provider record id.
	ID string
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
	// Allowance is the caller's remaining allowance on this provider. Set
	// only on the peer answer, which knows the calling principal.
	Allowance *ProviderAllowance
}

// AllowanceSource names what a limit comes from.
type AllowanceSource string

// AllowanceUnit is what a limit counts.
type AllowanceUnit string

// AllowanceScope is whose consumption a limit counts.
type AllowanceScope string

const (
	AllowanceSourcePolicy      AllowanceSource = "policy"
	AllowanceSourceAccountRule AllowanceSource = "account_rule"

	AllowanceUnitTokens AllowanceUnit = "tokens"
	AllowanceUnitUSD    AllowanceUnit = "usd"

	AllowanceScopeUser  AllowanceScope = "user"
	AllowanceScopeGroup AllowanceScope = "group"
)

// AllowanceLimit is one cap that binds the caller on a provider, with the
// caller's consumption in the cap's current epoch-aligned window.
type AllowanceLimit struct {
	Source     AllowanceSource
	SourceID   string
	SourceName string
	Unit       AllowanceUnit
	Scope      AllowanceScope
	// GroupID and GroupName are set for group-scoped limits.
	GroupID   string
	GroupName string
	Cap       float64
	Used      float64
	// ResetsAt is the end of the cap's current window.
	ResetsAt time.Time
}

// ProviderAllowance is what the caller may still spend on one provider.
// Tokens and USD are never folded together: each binding cap is its own
// limit.
type ProviderAllowance struct {
	// Unlimited means a policy without caps pays for the caller and no
	// account rule binds them.
	Unlimited bool
	// Exhausted mirrors the proxy: true exactly when the policy selector
	// would deny the caller's next request on this provider.
	Exhausted bool
	Limits    []AllowanceLimit
}

// PeerAgentNetworkState is the availability of Agent Networks for a peer.
type PeerAgentNetworkState string

const (
	// PeerAgentNetworkOK means the account has an Agent Network; the
	// providers in Config may still be empty when no policy covers the peer.
	PeerAgentNetworkOK PeerAgentNetworkState = "ok"
	// PeerAgentNetworkNoUser means the peer has no owning user, e.g. it
	// was registered with a setup key.
	PeerAgentNetworkNoUser PeerAgentNetworkState = "no_user"
	// PeerAgentNetworkNotEnabled means the account has no Agent Network.
	PeerAgentNetworkNotEnabled PeerAgentNetworkState = "not_enabled"
	// PeerAgentNetworkUserBlocked means the owning user is blocked or
	// pending approval, so the proxy refuses the peer.
	PeerAgentNetworkUserBlocked PeerAgentNetworkState = "user_blocked"
)

// PeerAgentNetworkInfo is what Agent Networks offers one peer, computed
// from the peer's own groups and owning user.
type PeerAgentNetworkInfo struct {
	State PeerAgentNetworkState
	// Config carries the endpoint and providers; set only when State is OK.
	Config *AgentConfig
}
