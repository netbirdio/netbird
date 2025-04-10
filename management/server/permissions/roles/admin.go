package roles

import (
	"github.com/netbirdio/netbird/management/server/permissions/modules"
	"github.com/netbirdio/netbird/management/server/permissions/operations"
	"github.com/netbirdio/netbird/management/server/types"
)

var Admin = RolePermissions{
	Role: types.UserRoleAdmin,
	AutoAllowNew: map[operations.Operation]bool{
		operations.Read:  true,
		operations.Write: true,
	},
	Permissions: Permissions{
		modules.Accounts: {
			operations.Read:  true,
			operations.Write: false,
		},
	},
}
