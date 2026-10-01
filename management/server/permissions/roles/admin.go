package roles

import (
	"github.com/netbirdio/netbird/management/server/permissions/modules"
	"github.com/netbirdio/netbird/management/server/permissions/operations"
	"github.com/netbirdio/netbird/management/server/types"
)

var Admin = RolePermissions{
	Role: types.UserRoleAdmin,
	AutoAllowNew: map[operations.Operation]bool{
		operations.Read:   true,
		operations.Create: true,
		operations.Update: true,
		operations.Delete: true,
	},
	Permissions: Permissions{
		modules.Accounts: {
			operations.Read:   true,
			operations.Create: false,
			operations.Update: false,
			operations.Delete: false,
		},
	},
}
