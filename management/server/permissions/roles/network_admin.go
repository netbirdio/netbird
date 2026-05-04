package roles

import (
	"github.com/netbirdio/netbird/management/server/permissions/modules"
	"github.com/netbirdio/netbird/management/server/permissions/operations"
	"github.com/netbirdio/netbird/management/server/types"
)

var NetworkAdmin = RolePermissions{
	Role: types.UserRoleNetworkAdmin,
	AutoAllowNew: map[operations.Operation]bool{
		operations.Read:   false,
		operations.Create: false,
		operations.Update: false,
		operations.Delete: false,
	},
	Permissions: Permissions{
		modules.Networks: {
			operations.Read:   true,
			operations.Create: true,
			operations.Update: true,
			operations.Delete: true,
		},
		modules.Groups: {
			operations.Read:   true,
			operations.Create: true,
			operations.Update: true,
			operations.Delete: true,
		},
		modules.Settings: {
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
		modules.Dns: {
			operations.Read:   true,
			operations.Create: true,
			operations.Update: true,
			operations.Delete: true,
		},
		modules.Nameservers: {
			operations.Read:   true,
			operations.Create: true,
			operations.Update: true,
			operations.Delete: true,
		},
		modules.Events: {
			operations.Read:   true,
			operations.Create: false,
			operations.Update: false,
			operations.Delete: false,
		},
		modules.Policies: {
			operations.Read:   true,
			operations.Create: true,
			operations.Update: true,
			operations.Delete: true,
		},
		modules.Routes: {
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
		modules.SetupKeys: {
			operations.Read:   true,
			operations.Create: false,
			operations.Update: false,
			operations.Delete: false,
		},
		modules.Pats: {
			operations.Read:   true,
			operations.Create: true,
			operations.Update: true,
			operations.Delete: true,
		},
		modules.Peers: {
			operations.Read:   true,
			operations.Create: false,
			operations.Update: false,
			operations.Delete: false,
		},
		modules.IdentityProviders: {
			operations.Read:   true,
			operations.Create: false,
			operations.Update: false,
			operations.Delete: false,
		},
	},
}
