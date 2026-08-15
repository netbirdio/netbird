package roles

import (
	"github.com/netbirdio/netbird/management/server/permissions/modules"
	"github.com/netbirdio/netbird/management/server/permissions/operations"
	"github.com/netbirdio/netbird/management/server/types"
)

// UsageViewer is the regular User baseline plus read access to the
// aggregated Agent Network usage and cost overview. It sees no provider
// configuration, no policies, and no request-level access logs (which can
// contain captured prompts): usage rows carry user and group display names
// in the response itself, so no team-wide read access is needed.
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
	},
}
