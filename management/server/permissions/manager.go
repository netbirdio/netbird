package permissions

//go:generate go run github.com/golang/mock/mockgen -package permissions -destination=manager_mock.go -source=./manager.go -build_flags=-mod=mod

import (
	"context"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/management/server/activity"
	"github.com/netbirdio/netbird/management/server/permissions/modules"
	"github.com/netbirdio/netbird/management/server/permissions/operations"
	"github.com/netbirdio/netbird/management/server/permissions/roles"
	"github.com/netbirdio/netbird/management/server/status"
	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/management/server/types"
)

type Manager interface {
	ValidateUserPermissions(ctx context.Context, accountID, userID string, module modules.Module, operation operations.Operation) (bool, error)
	ValidateRoleModuleAccess(ctx context.Context, accountID string, role roles.RolePermissions, module modules.Module, operation operations.Operation) bool
	ValidateAccountAccess(ctx context.Context, accountID string, user *types.User, allowOwnerAndAdmin bool) error

	GetPermissionsByRole(ctx context.Context, role types.UserRole) (roles.Permissions, error)
}

type managerImpl struct {
	store store.Store
}

func NewManager(store store.Store) Manager {
	return &managerImpl{
		store: store,
	}
}

func (m *managerImpl) ValidateUserPermissions(
	ctx context.Context,
	accountID string,
	userID string,
	module modules.Module,
	operation operations.Operation,
) (bool, error) {
	if userID == activity.SystemInitiator {
		return true, nil
	}

	user, err := m.store.GetUserByUserID(ctx, store.LockingStrengthNone, userID)
	if err != nil {
		return false, err
	}

	if user == nil {
		return false, status.NewUserNotFoundError(userID)
	}

	if user.IsBlocked() {
		return false, status.NewUserBlockedError()
	}

	if err := m.ValidateAccountAccess(ctx, accountID, user, false); err != nil {
		return false, err
	}

	if operation == operations.Read && user.IsServiceUser {
		return true, nil // this should be replaced by proper granular access role
	}

	role, ok := roles.RolesMap[user.Role]
	if !ok {
		return false, status.NewUserRoleNotFoundError(string(user.Role))
	}

	return m.ValidateRoleModuleAccess(ctx, accountID, role, module, operation), nil
}

func (m *managerImpl) ValidateRoleModuleAccess(
	ctx context.Context,
	accountID string,
	role roles.RolePermissions,
	module modules.Module,
	operation operations.Operation,
) bool {
	if permissions, ok := role.Permissions[module]; ok {
		if allowed, exists := permissions[operation]; exists {
			return allowed
		}
		log.WithContext(ctx).Tracef("operation %s not found on module %s for role %s", operation, module, role.Role)
		return false
	}

	return role.AutoAllowNew[operation]
}

func (m *managerImpl) ValidateAccountAccess(ctx context.Context, accountID string, user *types.User, allowOwnerAndAdmin bool) error {
	if user.AccountID != accountID {
		return status.NewUserNotPartOfAccountError()
	}
	return nil
}

func (m *managerImpl) GetPermissionsByRole(ctx context.Context, role types.UserRole) (roles.Permissions, error) {
	roleMap, ok := roles.RolesMap[role]
	if !ok {
		return roles.Permissions{}, status.NewUserRoleNotFoundError(string(role))
	}

	permissions := roles.Permissions{}

	for k := range modules.All {
		if rolePermissions, ok := roleMap.Permissions[k]; ok {
			permissions[k] = rolePermissions
			continue
		}
		permissions[k] = roleMap.AutoAllowNew
	}

	return permissions, nil
}
