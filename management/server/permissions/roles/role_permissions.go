package roles

import (
	"github.com/netbirdio/netbird/management/server/permissions/modules"
	"github.com/netbirdio/netbird/management/server/permissions/operations"
	"github.com/netbirdio/netbird/management/server/types"
)

type RolePermissions map[modules.Module]map[operations.Operation]bool

var RolesMap = map[types.UserRole]RolePermissions{
	types.UserRoleOwner: Owner,
	types.UserRoleAdmin: Admin,
	types.UserRoleUser:  User,
}
