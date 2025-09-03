package groups

import (
	"context"
	"fmt"

	"github.com/netbirdio/netbird/management/server/account"
	"github.com/netbirdio/netbird/management/server/activity"
	"github.com/netbirdio/netbird/management/server/permissions"
	"github.com/netbirdio/netbird/management/server/permissions/modules"
	"github.com/netbirdio/netbird/management/server/permissions/operations"
	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/shared/management/http/api"
)

type Manager interface {
	GetAllGroups(ctx context.Context, accountID, userID string) ([]*types.Group, error)
	GetAllGroupsMap(ctx context.Context, accountID, userID string) (map[string]*types.Group, error)
	GetResourceGroupsInTransaction(ctx context.Context, transaction store.Store, lockingStrength store.LockingStrength, accountID, resourceID string) ([]*types.Group, error)
	AddResourceToGroup(ctx context.Context, accountID, userID, groupID string, resourceID *types.Resource) error
	AddResourceToGroupInTransaction(ctx context.Context, transaction store.Store, accountID, userID, groupID string, resourceID *types.Resource) (func(), error)
	RemoveResourceFromGroupInTransaction(ctx context.Context, transaction store.Store, accountID, userID, groupID, resourceID string) (func(), error)
	GetPeerGroupIDs(ctx context.Context, accountID, peerID string) ([]string, error)
}

type managerImpl struct {
	store              store.Store
	permissionsManager permissions.Manager
	accountManager     account.Manager
}

type mockManager struct {
}

func NewManager(store store.Store, permissionsManager permissions.Manager, accountManager account.Manager) Manager {
	return &managerImpl{
		store:              store,
		permissionsManager: permissionsManager,
		accountManager:     accountManager,
	}
}

func (m *managerImpl) GetAllGroups(ctx context.Context, accountID, userID string) ([]*types.Group, error) {
	ok, err := m.permissionsManager.ValidateUserPermissions(ctx, accountID, userID, modules.Groups, operations.Read)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, err
	}

	groups, err := m.store.GetAccountGroups(ctx, store.LockingStrengthNone, accountID)
	if err != nil {
		return nil, fmt.Errorf("error getting account groups: %w", err)
	}

	return groups, nil
}

func (m *managerImpl) GetAllGroupsMap(ctx context.Context, accountID, userID string) (map[string]*types.Group, error) {
	groups, err := m.GetAllGroups(ctx, accountID, userID)
	if err != nil {
		return nil, err
	}

	groupsMap := make(map[string]*types.Group)
	for _, group := range groups {
		groupsMap[group.ID] = group
	}

	return groupsMap, nil
}

func (m *managerImpl) AddResourceToGroup(ctx context.Context, accountID, userID, groupID string, resource *types.Resource) error {
	ok, err := m.permissionsManager.ValidateUserPermissions(ctx, accountID, userID, modules.Groups, operations.Update)
	if err != nil {
		return err
	}
	if !ok {
		return err
	}

	event, err := m.AddResourceToGroupInTransaction(ctx, m.store, accountID, userID, groupID, resource)
	if err != nil {
		return fmt.Errorf("error adding resource to group: %w", err)
	}

	event()

	return nil
}

func (m *managerImpl) AddResourceToGroupInTransaction(ctx context.Context, transaction store.Store, accountID, userID, groupID string, resource *types.Resource) (func(), error) {
	err := transaction.AddResourceToGroup(ctx, accountID, groupID, resource)
	if err != nil {
		return nil, fmt.Errorf("error adding resource to group: %w", err)
	}

	group, err := transaction.GetGroupByID(ctx, store.LockingStrengthNone, accountID, groupID)
	if err != nil {
		return nil, fmt.Errorf("error getting group: %w", err)
	}

	// TODO: at some point, this will need to become a switch statement
	networkResource, err := transaction.GetNetworkResourceByID(ctx, store.LockingStrengthNone, accountID, resource.ID)
	if err != nil {
		return nil, fmt.Errorf("error getting network resource: %w", err)
	}

	event := func() {
		m.accountManager.StoreEvent(ctx, userID, groupID, accountID, activity.ResourceAddedToGroup, group.EventMetaResource(networkResource))
	}

	return event, nil
}

func (m *managerImpl) RemoveResourceFromGroupInTransaction(ctx context.Context, transaction store.Store, accountID, userID, groupID, resourceID string) (func(), error) {
	err := transaction.RemoveResourceFromGroup(ctx, accountID, groupID, resourceID)
	if err != nil {
		return nil, fmt.Errorf("error removing resource from group: %w", err)
	}

	group, err := transaction.GetGroupByID(ctx, store.LockingStrengthNone, accountID, groupID)
	if err != nil {
		return nil, fmt.Errorf("error getting group: %w", err)
	}

	// TODO: at some point, this will need to become a switch statement
	networkResource, err := transaction.GetNetworkResourceByID(ctx, store.LockingStrengthNone, accountID, resourceID)
	if err != nil {
		return nil, fmt.Errorf("error getting network resource: %w", err)
	}

	event := func() {
		m.accountManager.StoreEvent(ctx, userID, groupID, accountID, activity.ResourceRemovedFromGroup, group.EventMetaResource(networkResource))
	}

	return event, nil
}

func (m *managerImpl) GetResourceGroupsInTransaction(ctx context.Context, transaction store.Store, lockingStrength store.LockingStrength, accountID, resourceID string) ([]*types.Group, error) {
	return transaction.GetResourceGroups(ctx, lockingStrength, accountID, resourceID)
}

func (m *managerImpl) GetPeerGroupIDs(ctx context.Context, accountID, peerID string) ([]string, error) {
	return m.store.GetPeerGroupIDs(ctx, store.LockingStrengthShare, accountID, peerID)
}

func ToGroupsInfoMap(groups []*types.Group, idCount int) map[string][]api.GroupMinimum {
	groupsInfoMap := make(map[string][]api.GroupMinimum, idCount)
	groupsChecked := make(map[string]struct{}, len(groups)) // not sure why this is needed (left over from old implementation)
	for _, group := range groups {
		_, ok := groupsChecked[group.ID]
		if ok {
			continue
		}

		groupsChecked[group.ID] = struct{}{}
		for _, pk := range group.Peers {
			info := api.GroupMinimum{
				Id:             group.ID,
				Name:           group.Name,
				PeersCount:     len(group.Peers),
				ResourcesCount: len(group.Resources),
			}
			groupsInfoMap[pk] = append(groupsInfoMap[pk], info)
		}
		for _, rk := range group.Resources {
			info := api.GroupMinimum{
				Id:             group.ID,
				Name:           group.Name,
				PeersCount:     len(group.Peers),
				ResourcesCount: len(group.Resources),
			}
			groupsInfoMap[rk.ID] = append(groupsInfoMap[rk.ID], info)
		}
	}
	return groupsInfoMap
}

func (m *mockManager) GetAllGroups(ctx context.Context, accountID, userID string) ([]*types.Group, error) {
	return []*types.Group{}, nil
}

func (m *mockManager) GetAllGroupsMap(ctx context.Context, accountID, userID string) (map[string]*types.Group, error) {
	return map[string]*types.Group{}, nil
}

func (m *mockManager) GetResourceGroupsInTransaction(ctx context.Context, transaction store.Store, lockingStrength store.LockingStrength, accountID, resourceID string) ([]*types.Group, error) {
	return []*types.Group{}, nil
}

func (m *mockManager) AddResourceToGroup(ctx context.Context, accountID, userID, groupID string, resourceID *types.Resource) error {
	return nil
}

func (m *mockManager) AddResourceToGroupInTransaction(ctx context.Context, transaction store.Store, accountID, userID, groupID string, resourceID *types.Resource) (func(), error) {
	return func() {
		// noop
	}, nil
}

func (m *mockManager) RemoveResourceFromGroupInTransaction(ctx context.Context, transaction store.Store, accountID, userID, groupID, resourceID string) (func(), error) {
	return func() {
		// noop
	}, nil
}

func (m *mockManager) GetPeerGroupIDs(ctx context.Context, accountID, peerID string) ([]string, error) {
	return []string{}, nil
}

func NewManagerMock() Manager {
	return &mockManager{}
}
