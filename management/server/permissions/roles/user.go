package roles

import (
	"github.com/netbirdio/netbird/management/server/permissions/modules"
	"github.com/netbirdio/netbird/management/server/permissions/operations"
	"github.com/netbirdio/netbird/management/server/types"
)

var User = RolePermissions{
	Role: types.UserRoleUser,
	AutoAllowNew: map[operations.Operation]bool{
		operations.Read:  false,
		operations.Write: false,
	},
	Permissions: Permissions{
		modules.Accounts: {
			operations.Read:  true,
			operations.Write: false,
		},
		modules.Networks: {
			operations.Write: false,
			operations.Read:  false,
		},
		modules.Peers: {
			operations.Read:  false,
			operations.Write: false,
		},
		modules.Groups: {
			operations.Read:  false,
			operations.Write: false,
		},
		modules.Settings: {
			operations.Read:  false,
			operations.Write: false,
		},
		modules.Dns: {
			operations.Read:  false,
			operations.Write: false,
		},
		modules.Nameservers: {
			operations.Read:  false,
			operations.Write: false,
		},
		modules.Events: {
			operations.Read:  false,
			operations.Write: false,
		},
		modules.Policies: {
			operations.Read:  false,
			operations.Write: false,
		},
		modules.Routes: {
			operations.Read:  false,
			operations.Write: false,
		},
		modules.Users: {
			operations.Read:  false,
			operations.Write: false,
		},
		modules.SetupKeys: {
			operations.Read:  false,
			operations.Write: false,
		},
		modules.Pats: {
			operations.Read:  true,
			operations.Write: true,
		},
	},
}
