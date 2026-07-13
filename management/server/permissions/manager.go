package permissions

//go:generate go run github.com/golang/mock/mockgen -package permissions -destination=manager_mock.go -source=./manager.go -build_flags=-mod=mod

import (
	"context"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/management/server/account"
	"github.com/netbirdio/netbird/management/server/activity"
	nbcontext "github.com/netbirdio/netbird/management/server/context"
	"github.com/netbirdio/netbird/management/server/permissions/modules"
	"github.com/netbirdio/netbird/management/server/permissions/operations"
	"github.com/netbirdio/netbird/management/server/permissions/roles"
	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/shared/management/status"
)

type Manager interface {
	ValidateUserPermissions(ctx context.Context, accountID, userID string, module modules.Module, operation operations.Operation) (bool, context.Context, error)
	ValidateRoleModuleAccess(ctx context.Context, accountID string, role roles.RolePermissions, module modules.Module, operation operations.Operation) bool
	ValidateAccountAccess(ctx context.Context, accountID string, user *types.User, allowOwnerAndAdmin bool) (context.Context, error)

	GetPermissionsByRole(ctx context.Context, role types.UserRole) (roles.Permissions, error)
	SetAccountManager(accountManager account.Manager)
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
) (bool, context.Context, error) {
	if userID == activity.SystemInitiator {
		return true, ctx, nil
	}

	user, err := m.store.GetUserByUserID(ctx, store.LockingStrengthNone, userID)
	if err != nil {
		return false, ctx, err
	}

	if user == nil {
		return false, ctx, status.NewUserNotFoundError(userID)
	}

	if user.IsBlocked() && !user.PendingApproval {
		return false, ctx, status.NewUserBlockedError()
	}

	if user.IsBlocked() && user.PendingApproval {
		return false, ctx, status.NewUserPendingApprovalError()
	}

	ctxEnriched, err := m.ValidateAccountAccess(ctx, accountID, user, false)
	if err != nil {
		return false, ctx, err
	}

	if operation == operations.Read && user.IsServiceUser {
		return true, ctxEnriched, nil // this should be replaced by proper granular access role
	}

	role, ok := roles.RolesMap[user.Role]
	if !ok {
		return false, ctxEnriched, status.NewUserRoleNotFoundError(string(user.Role))
	}

	return m.ValidateRoleModuleAccess(ctx, accountID, role, module, operation), ctxEnriched, nil
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

func (m *managerImpl) ValidateAccountAccess(ctx context.Context, accountID string, user *types.User, allowOwnerAndAdmin bool) (context.Context, error) {
	if user.AccountID != accountID {
		return ctx, status.NewUserNotPartOfAccountError()
	}

	ctx = nbcontext.WithRole(ctx, string(user.Role))

	return ctx, nil
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

func (m *managerImpl) SetAccountManager(accountManager account.Manager) {
	// no-op
}
