package roles

import (
	"github.com/netbirdio/netbird/management/server/permissions/modules"
	"github.com/netbirdio/netbird/management/server/permissions/operations"
	"github.com/netbirdio/netbird/management/server/types"
)

// AgentNetworkViewer is the read-only counterpart of AgentNetworkAdmin: it
// reads the whole Agent Network area, including account-wide usage and the
// request-level access logs (which can contain captured prompts), plus the
// account objects the dashboard resolves names and filters against. It
// cannot change anything, and provider connection config stays redacted
// because it holds no update grant on agent_network.providers.
var AgentNetworkViewer = RolePermissions{
	Role: types.UserRoleAgentNetworkViewer,
	AutoAllowNew: map[operations.Operation]bool{
		operations.Read:   false,
		operations.Create: false,
		operations.Update: false,
		operations.Delete: false,
	},
	Permissions: Permissions{
		modules.AgentNetwork: {
			operations.Read:   true,
			operations.Create: false,
			operations.Update: false,
			operations.Delete: false,
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
