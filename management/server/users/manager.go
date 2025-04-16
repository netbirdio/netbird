package users

//go:generate go run github.com/golang/mock/mockgen -package users -destination=manager_mock.go -source=./manager.go -build_flags=-mod=mod

import (
	"context"

	"github.com/netbirdio/netbird/management/server/permissions"
	"github.com/netbirdio/netbird/management/server/permissions/roles"
	"github.com/netbirdio/netbird/management/server/status"
	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/management/server/types"
)

type Manager interface {
	GetUser(ctx context.Context, userID string) (*types.User, error)
	GetRoles(ctx context.Context, accountId, userId string) (map[types.UserRole]roles.RolePermissions, error)
}

type managerImpl struct {
	store              store.Store
	permissionsManager permissions.Manager
}

func NewManager(store store.Store, permissionsManager permissions.Manager) Manager {
	return &managerImpl{
		store:              store,
		permissionsManager: permissionsManager,
	}
}

func (m *managerImpl) GetUser(ctx context.Context, userID string) (*types.User, error) {
	return m.store.GetUserByUserID(ctx, store.LockingStrengthShare, userID)
}

func (m *managerImpl) GetRoles(ctx context.Context, accountId, userId string) (map[types.UserRole]roles.RolePermissions, error) {
	user, err := m.store.GetUserByUserID(ctx, store.LockingStrengthShare, userId)
	if err != nil {
		return nil, err
	}

	if user.IsBlocked() {
		return nil, status.NewUserBlockedError()
	}

	if user.IsServiceUser {
		return nil, status.NewPermissionDeniedError()
	}

	if err := m.permissionsManager.ValidateAccountAccess(ctx, accountId, user, false); err != nil {
		return nil, err
	}

	return m.permissionsManager.GetPermissions(ctx), nil
}
