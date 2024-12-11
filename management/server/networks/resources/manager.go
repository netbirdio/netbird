package resources

import (
	"context"
	"errors"
	"fmt"

	"github.com/netbirdio/netbird/management/server/networks/resources/types"
	"github.com/netbirdio/netbird/management/server/permissions"
	"github.com/netbirdio/netbird/management/server/store"
)

type Manager interface {
	GetAllResources(ctx context.Context, accountID, userID, networkID string) ([]*types.NetworkResource, error)
	CreateResource(ctx context.Context, userID string, resource *types.NetworkResource) (*types.NetworkResource, error)
	GetResource(ctx context.Context, accountID, userID, networkID, resourceID string) (*types.NetworkResource, error)
	UpdateResource(ctx context.Context, userID string, resource *types.NetworkResource) (*types.NetworkResource, error)
	DeleteResource(ctx context.Context, accountID, userID, networkID, resourceID string) error
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

func (m *managerImpl) GetAllResources(ctx context.Context, accountID, userID, networkID string) ([]*types.NetworkResource, error) {
	ok, err := m.permissionsManager.ValidateUserPermissions(ctx, accountID, userID, permissions.Networks, permissions.Read)
	if err != nil {
		return nil, fmt.Errorf("failed to validate user permissions: %w", err)
	}
	if !ok {
		return nil, errors.New("permission denied")
	}

	return m.store.GetNetworkResourcesByNetID(ctx, store.LockingStrengthShare, accountID, networkID)
}

func (m *managerImpl) CreateResource(ctx context.Context, userID string, resource *types.NetworkResource) (*types.NetworkResource, error) {
	ok, err := m.permissionsManager.ValidateUserPermissions(ctx, resource.AccountID, userID, permissions.Networks, permissions.Write)
	if err != nil {
		return nil, fmt.Errorf("failed to validate user permissions: %w", err)
	}
	if !ok {
		return nil, errors.New("permission denied")
	}

	resource, err = types.NewNetworkResource(resource.AccountID, resource.NetworkID, resource.Name, resource.Description, resource.Address)
	if err != nil {
		return nil, fmt.Errorf("failed to create new network resource: %w", err)
	}

	return resource, m.store.SaveNetworkResource(ctx, store.LockingStrengthUpdate, resource)
}

func (m *managerImpl) GetResource(ctx context.Context, accountID, userID, networkID, resourceID string) (*types.NetworkResource, error) {
	ok, err := m.permissionsManager.ValidateUserPermissions(ctx, accountID, userID, permissions.Networks, permissions.Read)
	if err != nil {
		return nil, fmt.Errorf("failed to validate user permissions: %w", err)
	}
	if !ok {
		return nil, errors.New("permission denied")
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
		return nil, fmt.Errorf("failed to validate user permissions: %w", err)
	}
	if !ok {
		return nil, errors.New("permission denied")
	}

	resourceType, err := types.GetResourceType(resource.Address)
	if err != nil {
		return nil, fmt.Errorf("failed to get resource type: %w", err)
	}

	resource.Type = resourceType

	return resource, m.store.SaveNetworkResource(ctx, store.LockingStrengthUpdate, resource)
}

func (m *managerImpl) DeleteResource(ctx context.Context, accountID, userID, networkID, resourceID string) error {
	ok, err := m.permissionsManager.ValidateUserPermissions(ctx, accountID, userID, permissions.Networks, permissions.Write)
	if err != nil {
		return fmt.Errorf("failed to validate user permissions: %w", err)
	}
	if !ok {
		return errors.New("permission denied")
	}

	return m.store.DeleteNetworkResource(ctx, store.LockingStrengthUpdate, accountID, resourceID)
}
