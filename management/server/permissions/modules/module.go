package modules

import "strings"

type Module string

const (
	Networks          Module = "networks"
	Peers             Module = "peers"
	RemoteJobs        Module = "remote_jobs"
	Groups            Module = "groups"
	Settings          Module = "settings"
	Accounts          Module = "accounts"
	Dns               Module = "dns"
	Nameservers       Module = "nameservers"
	Events            Module = "events"
	Policies          Module = "policies"
	Routes            Module = "routes"
	Users             Module = "users"
	SetupKeys         Module = "setup_keys"
	Pats              Module = "pats"
	IdentityProviders Module = "identity_providers"
	Services          Module = "services"
	AgentNetwork      Module = "agent_network"

	// Agent Network submodules. A role may grant one of these directly
	// or grant the AgentNetwork parent, which covers all of them (see
	// permissions.Manager cascade resolution).
	AgentNetworkProviders  Module = "agent_network.providers"
	AgentNetworkPolicies   Module = "agent_network.policies"
	AgentNetworkGuardrails Module = "agent_network.guardrails"
	AgentNetworkBudgets    Module = "agent_network.budgets"
	AgentNetworkUsage      Module = "agent_network.usage"
	AgentNetworkLogs       Module = "agent_network.logs"
	AgentNetworkSettings   Module = "agent_network.settings"
)

var All = map[Module]struct{}{
	Networks:          {},
	Peers:             {},
	RemoteJobs:        {},
	Groups:            {},
	Settings:          {},
	Accounts:          {},
	Dns:               {},
	Nameservers:       {},
	Events:            {},
	Policies:          {},
	Routes:            {},
	Users:             {},
	SetupKeys:         {},
	Pats:              {},
	IdentityProviders: {},
	Services:          {},
	AgentNetwork:      {},

	AgentNetworkProviders:  {},
	AgentNetworkPolicies:   {},
	AgentNetworkGuardrails: {},
	AgentNetworkBudgets:    {},
	AgentNetworkUsage:      {},
	AgentNetworkLogs:       {},
	AgentNetworkSettings:   {},
}

// Parent returns the module owning a dotted submodule name and true, or the
// module itself and false when it has no parent.
func (m Module) Parent() (Module, bool) {
	if i := strings.IndexByte(string(m), '.'); i > 0 {
		return Module(string(m)[:i]), true
	}
	return m, false
}
