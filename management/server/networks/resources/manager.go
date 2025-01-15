package resources

import (
	"context"
	"errors"
	"fmt"

	s "github.com/netbirdio/netbird/management/server"
	"github.com/netbirdio/netbird/management/server/activity"
	"github.com/netbirdio/netbird/management/server/groups"
	"github.com/netbirdio/netbird/management/server/networks/resources/types"
	"github.com/netbirdio/netbird/management/server/permissions"
	"github.com/netbirdio/netbird/management/server/status"
	"github.com/netbirdio/netbird/management/server/store"
	nbtypes "github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/management/server/util"
)

type Manager interface {
	GetAllResourcesInNetwork(ctx context.Context, accountID, userID, networkID string) ([]*types.NetworkResource, error)
	GetAllResourcesInAccount(ctx context.Context, accountID, userID string) ([]*types.NetworkResource, error)
	GetAllResourceIDsInAccount(ctx context.Context, accountID, userID string) (map[string][]string, error)
	CreateResource(ctx context.Context, userID string, resource *types.NetworkResource) (*types.NetworkResource, error)
	GetResource(ctx context.Context, accountID, userID, networkID, resourceID string) (*types.NetworkResource, error)
	UpdateResource(ctx context.Context, userID string, resource *types.NetworkResource) (*types.NetworkResource, error)
	DeleteResource(ctx context.Context, accountID, userID, networkID, resourceID string) error
	DeleteResourceInTransaction(ctx context.Context, transaction store.Store, accountID, userID, networkID, resourceID string) ([]func(), error)
}

type managerImpl struct {
	store              store.Store
	permissionsManager permissions.Manager
	groupsManager      groups.Manager
	accountManager     s.AccountManager
}

type mockManager struct {
}

func NewManager(store store.Store, permissionsManager permissions.Manager, groupsManager groups.Manager, accountManager s.AccountManager) Manager {
	return &managerImpl{
		store:              store,
		permissionsManager: permissionsManager,
		groupsManager:      groupsManager,
		accountManager:     accountManager,
	}
}

func (m *managerImpl) GetAllResourcesInNetwork(ctx context.Context, accountID, userID, networkID string) ([]*types.NetworkResource, error) {
	ok, err := m.permissionsManager.ValidateUserPermissions(ctx, accountID, userID, permissions.Networks, permissions.Read)
	if err != nil {
		return nil, status.NewPermissionValidationError(err)
	}
	if !ok {
		return nil, status.NewPermissionDeniedError()
	}

	return m.store.GetNetworkResourcesByNetID(ctx, store.LockingStrengthShare, accountID, networkID)
}

func (m *managerImpl) GetAllResourcesInAccount(ctx context.Context, accountID, userID string) ([]*types.NetworkResource, error) {
	ok, err := m.permissionsManager.ValidateUserPermissions(ctx, accountID, userID, permissions.Networks, permissions.Read)
	if err != nil {
		return nil, status.NewPermissionValidationError(err)
	}
	if !ok {
		return nil, status.NewPermissionDeniedError()
	}

	return m.store.GetNetworkResourcesByAccountID(ctx, store.LockingStrengthShare, accountID)
}

func (m *managerImpl) GetAllResourceIDsInAccount(ctx context.Context, accountID, userID string) (map[string][]string, error) {
	ok, err := m.permissionsManager.ValidateUserPermissions(ctx, accountID, userID, permissions.Networks, permissions.Read)
	if err != nil {
		return nil, status.NewPermissionValidationError(err)
	}
	if !ok {
		return nil, status.NewPermissionDeniedError()
	}

	resources, err := m.store.GetNetworkResourcesByAccountID(ctx, store.LockingStrengthShare, accountID)
	if err != nil {
		return nil, fmt.Errorf("failed to get network resources: %w", err)
	}

	resourceMap := make(map[string][]string)
	for _, resource := range resources {
		resourceMap[resource.NetworkID] = append(resourceMap[resource.NetworkID], resource.ID)
	}

	return resourceMap, nil
}

func (m *managerImpl) CreateResource(ctx context.Context, userID string, resource *types.NetworkResource) (*types.NetworkResource, error) {
	ok, err := m.permissionsManager.ValidateUserPermissions(ctx, resource.AccountID, userID, permissions.Networks, permissions.Write)
	if err != nil {
		return nil, status.NewPermissionValidationError(err)
	}
	if !ok {
		return nil, status.NewPermissionDeniedError()
	}

	resource, err = types.NewNetworkResource(resource.AccountID, resource.NetworkID, resource.Name, resource.Description, resource.Address, resource.GroupIDs, resource.Enabled)
	if err != nil {
		return nil, fmt.Errorf("failed to create new network resource: %w", err)
	}

	unlock := m.store.AcquireWriteLockByUID(ctx, resource.AccountID)
	defer unlock()

	var eventsToStore []func()
	err = m.store.ExecuteInTransaction(ctx, func(transaction store.Store) error {
		_, err = transaction.GetNetworkResourceByName(ctx, store.LockingStrengthShare, resource.AccountID, resource.Name)
		if err == nil {
			return errors.New("resource already exists")
		}

		network, err := transaction.GetNetworkByID(ctx, store.LockingStrengthUpdate, resource.AccountID, resource.NetworkID)
		if err != nil {
			return fmt.Errorf("failed to get network: %w", err)
		}

		err = transaction.SaveNetworkResource(ctx, store.LockingStrengthUpdate, resource)
		if err != nil {
			return fmt.Errorf("failed to save network resource: %w", err)
		}

		event := func() {
			m.accountManager.StoreEvent(ctx, userID, resource.ID, resource.AccountID, activity.NetworkResourceCreated, resource.EventMeta(network))
		}
		eventsToStore = append(eventsToStore, event)

		res := nbtypes.Resource{
			ID:   resource.ID,
			Type: resource.Type.String(),
		}
		for _, groupID := range resource.GroupIDs {
			event, err := m.groupsManager.AddResourceToGroupInTransaction(ctx, transaction, resource.AccountID, userID, groupID, &res)
			if err != nil {
				return fmt.Errorf("failed to add resource to group: %w", err)
			}
			eventsToStore = append(eventsToStore, event)
		}

		err = transaction.IncrementNetworkSerial(ctx, store.LockingStrengthUpdate, resource.AccountID)
		if err != nil {
			return fmt.Errorf("failed to increment network serial: %w", err)
		}

		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create network resource: %w", err)
	}

	for _, event := range eventsToStore {
		event()
	}

	go m.accountManager.UpdateAccountPeers(ctx, resource.AccountID)

	return resource, nil
}

func (m *managerImpl) GetResource(ctx context.Context, accountID, userID, networkID, resourceID string) (*types.NetworkResource, error) {
	ok, err := m.permissionsManager.ValidateUserPermissions(ctx, accountID, userID, permissions.Networks, permissions.Read)
	if err != nil {
		return nil, status.NewPermissionValidationError(err)
	}
	if !ok {
		return nil, status.NewPermissionDeniedError()
	}

	resource, err := m.store.GetNetworkResourceByID(ctx, store.LockingStrengthShare, accountID, resourceID)
	if err != nil {
		return nil, fmt.Errorf("failed to get network resource: %w", err)
	}

	if resource.NetworkID != networkID {
		return nil, errors.New("resource not part of network")
	}

	return resource, nil
}

func (m *managerImpl) UpdateResource(ctx context.Context, userID string, resource *types.NetworkResource) (*types.NetworkResource, error) {
	ok, err := m.permissionsManager.ValidateUserPermissions(ctx, resource.AccountID, userID, permissions.Networks, permissions.Write)
	if err != nil {
		return nil, status.NewPermissionValidationError(err)
	}
	if !ok {
		return nil, status.NewPermissionDeniedError()
	}

	resourceType, domain, prefix, err := types.GetResourceType(resource.Address)
	if err != nil {
		return nil, fmt.Errorf("failed to get resource type: %w", err)
	}

	resource.Type = resourceType
	resource.Domain = domain
	resource.Prefix = prefix

	unlock := m.store.AcquireWriteLockByUID(ctx, resource.AccountID)
	defer unlock()

	var eventsToStore []func()
	err = m.store.ExecuteInTransaction(ctx, func(transaction store.Store) error {
		network, err := transaction.GetNetworkByID(ctx, store.LockingStrengthUpdate, resource.AccountID, resource.NetworkID)
		if err != nil {
			return fmt.Errorf("failed to get network: %w", err)
		}

		if network.ID != resource.NetworkID {
			return status.NewResourceNotPartOfNetworkError(resource.ID, resource.NetworkID)
		}

		_, err = transaction.GetNetworkResourceByID(ctx, store.LockingStrengthShare, resource.AccountID, resource.ID)
		if err != nil {
			return fmt.Errorf("failed to get network resource: %w", err)
		}

		oldResource, err := transaction.GetNetworkResourceByName(ctx, store.LockingStrengthShare, resource.AccountID, resource.Name)
		if err == nil && oldResource.ID != resource.ID {
			return errors.New("new resource name already exists")
		}

		oldResource, err = transaction.GetNetworkResourceByID(ctx, store.LockingStrengthShare, resource.AccountID, resource.ID)
		if err != nil {
			return fmt.Errorf("failed to get network resource: %w", err)
		}

		err = transaction.SaveNetworkResource(ctx, store.LockingStrengthUpdate, resource)
		if err != nil {
			return fmt.Errorf("failed to save network resource: %w", err)
		}

		events, err := m.updateResourceGroups(ctx, transaction, userID, resource, oldResource)
		if err != nil {
			return fmt.Errorf("failed to update resource groups: %w", err)
		}

		eventsToStore = append(eventsToStore, events...)
		eventsToStore = append(eventsToStore, func() {
			m.accountManager.StoreEvent(ctx, userID, resource.ID, resource.AccountID, activity.NetworkResourceUpdated, resource.EventMeta(network))
		})

		err = transaction.IncrementNetworkSerial(ctx, store.LockingStrengthUpdate, resource.AccountID)
		if err != nil {
			return fmt.Errorf("failed to increment network serial: %w", err)
		}

		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("failed to update network resource: %w", err)
	}

	for _, event := range eventsToStore {
		event()
	}

	go m.accountManager.UpdateAccountPeers(ctx, resource.AccountID)

	return resource, nil
}

func (m *managerImpl) updateResourceGroups(ctx context.Context, transaction store.Store, userID string, newResource, oldResource *types.NetworkResource) ([]func(), error) {
	res := nbtypes.Resource{
		ID:   newResource.ID,
		Type: newResource.Type.String(),
	}

	oldResourceGroups, err := m.groupsManager.GetResourceGroupsInTransaction(ctx, transaction, store.LockingStrengthUpdate, oldResource.AccountID, oldResource.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to get resource groups: %w", err)
	}

	oldGroupsIds := make([]string, 0)
	for _, group := range oldResourceGroups {
		oldGroupsIds = append(oldGroupsIds, group.ID)
	}

	var eventsToStore []func()
	groupsToAdd := util.Difference(newResource.GroupIDs, oldGroupsIds)
	for _, groupID := range groupsToAdd {
		events, err := m.groupsManager.AddResourceToGroupInTransaction(ctx, transaction, newResource.AccountID, userID, groupID, &res)
		if err != nil {
			return nil, fmt.Errorf("failed to add resource to group: %w", err)
		}
		eventsToStore = append(eventsToStore, events)
	}

	groupsToRemove := util.Difference(oldGroupsIds, newResource.GroupIDs)
	for _, groupID := range groupsToRemove {
		events, err := m.groupsManager.RemoveResourceFromGroupInTransaction(ctx, transaction, newResource.AccountID, userID, groupID, res.ID)
		if err != nil {
			return nil, fmt.Errorf("failed to add resource to group: %w", err)
		}
		eventsToStore = append(eventsToStore, events)
	}

	return eventsToStore, nil
}

func (m *managerImpl) DeleteResource(ctx context.Context, accountID, userID, networkID, resourceID string) error {
	ok, err := m.permissionsManager.ValidateUserPermissions(ctx, accountID, userID, permissions.Networks, permissions.Write)
	if err != nil {
		return status.NewPermissionValidationError(err)
	}
	if !ok {
		return status.NewPermissionDeniedError()
	}

	unlock := m.store.AcquireWriteLockByUID(ctx, accountID)
	defer unlock()

	var events []func()
	err = m.store.ExecuteInTransaction(ctx, func(transaction store.Store) error {
		events, err = m.DeleteResourceInTransaction(ctx, transaction, accountID, userID, networkID, resourceID)
		if err != nil {
			return fmt.Errorf("failed to delete resource: %w", err)
		}

		err = transaction.IncrementNetworkSerial(ctx, store.LockingStrengthUpdate, accountID)
		if err != nil {
			return fmt.Errorf("failed to increment network serial: %w", err)
		}

		return nil
	})
	if err != nil {
		return fmt.Errorf("failed to delete network resource: %w", err)
	}

	for _, event := range events {
		event()
	}

	go m.accountManager.UpdateAccountPeers(ctx, accountID)

	return nil
}

func (m *managerImpl) DeleteResourceInTransaction(ctx context.Context, transaction store.Store, accountID, userID, networkID, resourceID string) ([]func(), error) {
	resource, err := transaction.GetNetworkResourceByID(ctx, store.LockingStrengthUpdate, accountID, resourceID)
	if err != nil {
		return nil, fmt.Errorf("failed to get network resource: %w", err)
	}

	network, err := transaction.GetNetworkByID(ctx, store.LockingStrengthUpdate, accountID, networkID)
	if err != nil {
		return nil, fmt.Errorf("failed to get network: %w", err)
	}

	if resource.NetworkID != networkID {
		return nil, errors.New("resource not part of network")
	}

	groups, err := m.groupsManager.GetResourceGroupsInTransaction(ctx, transaction, store.LockingStrengthUpdate, accountID, resourceID)
	if err != nil {
		return nil, fmt.Errorf("failed to get resource groups: %w", err)
	}

	var eventsToStore []func()

	for _, group := range groups {
		event, err := m.groupsManager.RemoveResourceFromGroupInTransaction(ctx, transaction, accountID, userID, group.ID, resourceID)
		if err != nil {
			return nil, fmt.Errorf("failed to remove resource from group: %w", err)
		}
		eventsToStore = append(eventsToStore, event)
	}

	err = transaction.DeleteNetworkResource(ctx, store.LockingStrengthUpdate, accountID, resourceID)
	if err != nil {
		return nil, fmt.Errorf("failed to delete network resource: %w", err)
	}

	eventsToStore = append(eventsToStore, func() {
		m.accountManager.StoreEvent(ctx, userID, resourceID, accountID, activity.NetworkResourceDeleted, resource.EventMeta(network))
	})

	return eventsToStore, nil
}

func NewManagerMock() Manager {
	return &mockManager{}
}

func (m *mockManager) GetAllResourcesInNetwork(ctx context.Context, accountID, userID, networkID string) ([]*types.NetworkResource, error) {
	return []*types.NetworkResource{}, nil
}

func (m *mockManager) GetAllResourcesInAccount(ctx context.Context, accountID, userID string) ([]*types.NetworkResource, error) {
	return []*types.NetworkResource{}, nil
}

func (m *mockManager) GetAllResourceIDsInAccount(ctx context.Context, accountID, userID string) (map[string][]string, error) {
	return map[string][]string{}, nil
}

func (m *mockManager) CreateResource(ctx context.Context, userID string, resource *types.NetworkResource) (*types.NetworkResource, error) {
	return &types.NetworkResource{}, nil
}

func (m *mockManager) GetResource(ctx context.Context, accountID, userID, networkID, resourceID string) (*types.NetworkResource, error) {
	return &types.NetworkResource{}, nil
}

func (m *mockManager) UpdateResource(ctx context.Context, userID string, resource *types.NetworkResource) (*types.NetworkResource, error) {
	return &types.NetworkResource{}, nil
}

func (m *mockManager) DeleteResource(ctx context.Context, accountID, userID, networkID, resourceID string) error {
	return nil
}

func (m *mockManager) DeleteResourceInTransaction(ctx context.Context, transaction store.Store, accountID, userID, networkID, resourceID string) ([]func(), error) {
	return []func(){}, nil
}
