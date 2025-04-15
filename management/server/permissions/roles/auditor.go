package roles

import (
	"github.com/netbirdio/netbird/management/server/permissions/operations"
	"github.com/netbirdio/netbird/management/server/types"
)

var Auditor = RolePermissions{
	Role: types.UserRoleAuditor,
	AutoAllowNew: map[operations.Operation]bool{
		operations.Read:  true,
		operations.Write: false,
	},
}
