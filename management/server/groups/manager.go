package groups

import (
	"context"
	"fmt"

	"github.com/netbirdio/netbird/management/server/permissions"
	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/management/server/types"
)

type Manager interface {
	GetAllGroups(ctx context.Context, accountID, userID string) (map[string]*types.Group, error)
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

func (m *managerImpl) GetAllGroups(ctx context.Context, accountID, userID string) (map[string]*types.Group, error) {
	ok, err := m.permissionsManager.ValidateUserPermissions(ctx, accountID, userID, permissions.Groups, permissions.Read)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, err
	}

	groups, err := m.store.GetAccountGroups(ctx, store.LockingStrengthShare, accountID)
	if err != nil {
		return nil, fmt.Errorf("error getting account groups: %w", err)
	}

	groupsMap := make(map[string]*types.Group)
	for _, group := range groups {
		groupsMap[group.ID] = group
	}

	return groupsMap, nil
}
