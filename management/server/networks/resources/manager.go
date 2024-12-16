package resources

import (
	"context"
	"errors"
	"fmt"

	s "github.com/netbirdio/netbird/management/server"
	"github.com/netbirdio/netbird/management/server/networks/resources/types"
	"github.com/netbirdio/netbird/management/server/permissions"
	"github.com/netbirdio/netbird/management/server/status"
	"github.com/netbirdio/netbird/management/server/store"
)

type Manager interface {
	GetAllResourcesInNetwork(ctx context.Context, accountID, userID, networkID string) ([]*types.NetworkResource, error)
	GetAllResourcesInAccount(ctx context.Context, accountID, userID string) ([]*types.NetworkResource, error)
	GetAllResourceIDsInAccount(ctx context.Context, accountID, userID string) (map[string][]string, error)
	CreateResource(ctx context.Context, userID string, resource *types.NetworkResource) (*types.NetworkResource, error)
	GetResource(ctx context.Context, accountID, userID, networkID, resourceID string) (*types.NetworkResource, error)
	UpdateResource(ctx context.Context, userID string, resource *types.NetworkResource) (*types.NetworkResource, error)
	DeleteResource(ctx context.Context, accountID, userID, networkID, resourceID string) error
}

type managerImpl struct {
	store              store.Store
	permissionsManager permissions.Manager
	accountManager     s.AccountManager
}

func NewManager(store store.Store, permissionsManager permissions.Manager, accountManager s.AccountManager) Manager {
	return &managerImpl{
		store:              store,
		permissionsManager: permissionsManager,
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

	resource, err = types.NewNetworkResource(resource.AccountID, resource.NetworkID, resource.Name, resource.Description, resource.Address)
	if err != nil {
		return nil, fmt.Errorf("failed to create new network resource: %w", err)
	}

	err = m.store.SaveNetworkResource(ctx, store.LockingStrengthUpdate, resource)
	if err != nil {
		return nil, fmt.Errorf("failed to create network resource: %w", err)
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

	resourceType, err := types.GetResourceType(resource.Address)
	if err != nil {
		return nil, fmt.Errorf("failed to get resource type: %w", err)
	}

	resource.Type = resourceType

	err = m.store.SaveNetworkResource(ctx, store.LockingStrengthUpdate, resource)
	if err != nil {
		return nil, fmt.Errorf("failed to update network resource: %w", err)
	}

	go m.accountManager.UpdateAccountPeers(ctx, resource.AccountID)

	return resource, nil
}

func (m *managerImpl) DeleteResource(ctx context.Context, accountID, userID, networkID, resourceID string) error {
	ok, err := m.permissionsManager.ValidateUserPermissions(ctx, accountID, userID, permissions.Networks, permissions.Write)
	if err != nil {
		return status.NewPermissionValidationError(err)
	}
	if !ok {
		return status.NewPermissionDeniedError()
	}

	err = m.store.DeleteNetworkResource(ctx, store.LockingStrengthUpdate, accountID, resourceID)
	if err != nil {
		return fmt.Errorf("failed to delete network resource: %w", err)
	}

	go m.accountManager.UpdateAccountPeers(ctx, accountID)

	return nil
}
