package users

import (
	"github.com/netbirdio/netbird/management/server/permissions/roles"
	"github.com/netbirdio/netbird/management/server/types"
)

// Wrapped UserInfo with Role Permissions
type UserInfoWithPermissions struct {
	*types.UserInfo

	Permissions roles.RolePermissions
	Restricted  bool
}
