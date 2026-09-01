package roles

import (
	"github.com/netbirdio/netbird/management/server/permissions/modules"
	"github.com/netbirdio/netbird/management/server/permissions/operations"
	"github.com/netbirdio/netbird/management/server/types"
)

// UsageViewer is the regular User baseline plus read access to the
// aggregated Agent Network usage and cost overview, and read-only access
// to the resources the usage filters and display columns resolve against:
// users and groups (identity filters and name resolution), peers (agent
// principals in the caller column), and the provider list (provider and
// model filter options — the manager redacts connection config such as
// upstream URLs and operator-supplied header values for callers holding
// read without update). It sees no policies and no account-wide
// request-level access logs (which can contain captured prompts); its own
// requests remain readable through the self-scoped endpoints, like any
// caller's.
var UsageViewer = RolePermissions{
	Role: types.UserRoleUsageViewer,
	AutoAllowNew: map[operations.Operation]bool{
		operations.Read:   false,
		operations.Create: false,
		operations.Update: false,
		operations.Delete: false,
	},
	Permissions: Permissions{
		modules.AgentNetworkUsage: {
			operations.Read:   true,
			operations.Create: false,
			operations.Update: false,
			operations.Delete: false,
		},
		modules.AgentNetworkProviders: {
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
	},
}
