package roles

import (
	"github.com/netbirdio/netbird/management/server/permissions/modules"
	"github.com/netbirdio/netbird/management/server/permissions/operations"
)

var Owner = RolePermissions{
	AutoAllowNew: map[operations.Operation]bool{
		operations.Read:  true,
		operations.Write: true,
	},
	Permissions: Permissions{
		modules.Accounts: {
			operations.Read:  true,
			operations.Write: true,
		},
		modules.Networks: {
			operations.Write: true,
			operations.Read:  true,
		},
		modules.Peers: {
			operations.Read:  true,
			operations.Write: true,
		},
		modules.Groups: {
			operations.Read:  true,
			operations.Write: true,
		},
		modules.Settings: {
			operations.Read:  true,
			operations.Write: true,
		},
		modules.Dns: {
			operations.Read:  true,
			operations.Write: true,
		},
		modules.Nameservers: {
			operations.Read:  true,
			operations.Write: true,
		},
		modules.Events: {
			operations.Read:  true,
			operations.Write: true,
		},
		modules.Policies: {
			operations.Read:  true,
			operations.Write: true,
		},
		modules.Routes: {
			operations.Read:  true,
			operations.Write: true,
		},
		modules.Users: {
			operations.Read:  true,
			operations.Write: true,
		},
		modules.SetupKeys: {
			operations.Read:  true,
			operations.Write: true,
		},
		modules.Pats: {
			operations.Read:  true,
			operations.Write: true,
		},
	},
}
