package roles

import (
	"github.com/netbirdio/netbird/management/server/permissions/modules"
	"github.com/netbirdio/netbird/management/server/permissions/operations"
	"github.com/netbirdio/netbird/management/server/types"
)

// AgentNetworkAdmin is the delegated administrator for the Agent Network
// area: full control over providers, policies, guardrails, budgets, usage,
// logs, and its settings, plus read-only visibility into the account
// objects needed to build policies (users, groups, peers) and the account
// settings/meta read the dashboard needs to boot (GET /api/accounts
// validates Settings read, same as network_admin). Nothing else in the
// account is visible.
var AgentNetworkAdmin = RolePermissions{
	Role: types.UserRoleAgentNetworkAdmin,
	AutoAllowNew: map[operations.Operation]bool{
		operations.Read:   false,
		operations.Create: false,
		operations.Update: false,
		operations.Delete: false,
	},
	Permissions: Permissions{
		modules.AgentNetwork: {
			operations.Read:   true,
			operations.Create: true,
			operations.Update: true,
			operations.Delete: true,
		},
		modules.Users: {
			operations.Read:   true,
			operations.Create: false,
			operations.Update: false,
			operations.Delete: false,
		},
		modules.Groups: {
			operations.Read:   true,
			operations.Create: false,
			operations.Update: false,
			operations.Delete: false,
		},
		modules.Peers: {
			operations.Read:   true,
			operations.Create: false,
			operations.Update: false,
			operations.Delete: false,
		},
		modules.Accounts: {
			operations.Read:   true,
			operations.Create: false,
			operations.Update: false,
			operations.Delete: false,
		},
		modules.Settings: {
			operations.Read:   true,
			operations.Create: false,
			operations.Update: false,
			operations.Delete: false,
		},
	},
}
