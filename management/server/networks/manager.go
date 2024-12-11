package networks

import (
	"context"
	"fmt"

	"github.com/rs/xid"

	"github.com/netbirdio/netbird/management/server/networks/resources"
	"github.com/netbirdio/netbird/management/server/networks/routers"
	"github.com/netbirdio/netbird/management/server/networks/types"
	"github.com/netbirdio/netbird/management/server/permissions"
	"github.com/netbirdio/netbird/management/server/status"
	"github.com/netbirdio/netbird/management/server/store"
)

type Manager interface {
	GetAllNetworks(ctx context.Context, accountID, userID string) ([]*types.Network, error)
	CreateNetwork(ctx context.Context, userID string, network *types.Network) (*types.Network, error)
	GetNetwork(ctx context.Context, accountID, userID, networkID string) (*types.Network, error)
	UpdateNetwork(ctx context.Context, userID string, network *types.Network) (*types.Network, error)
	DeleteNetwork(ctx context.Context, accountID, userID, networkID string) error
	GetResourceManager() resources.Manager
	GetRouterManager() routers.Manager
}

type managerImpl struct {
	store              store.Store
	permissionsManager permissions.Manager
	routersManager     routers.Manager
	resourcesManager   resources.Manager
}

func NewManager(store store.Store, permissionsManager permissions.Manager) Manager {
	return &managerImpl{
		store:              store,
		permissionsManager: permissionsManager,
		routersManager:     routers.NewManager(store, permissionsManager),
		resourcesManager:   resources.NewManager(store, permissionsManager),
	}
}

func (m *managerImpl) GetAllNetworks(ctx context.Context, accountID, userID string) ([]*types.Network, error) {
	ok, err := m.permissionsManager.ValidateUserPermissions(ctx, accountID, userID, permissions.Networks, permissions.Read)
	if err != nil {
		return nil, fmt.Errorf("failed to validate user permissions: %w", err)
	}
	if !ok {
		return nil, status.NewPermissionDeniedError()
	}

	return m.store.GetAccountNetworks(ctx, store.LockingStrengthShare, accountID)
}

func (m *managerImpl) CreateNetwork(ctx context.Context, userID string, network *types.Network) (*types.Network, error) {
	ok, err := m.permissionsManager.ValidateUserPermissions(ctx, network.AccountID, userID, permissions.Networks, permissions.Write)
	if err != nil {
		return nil, fmt.Errorf("failed to validate user permissions: %w", err)
	}
	if !ok {
		return nil, status.NewPermissionDeniedError()
	}

	network.ID = xid.New().String()

	return network, m.store.SaveNetwork(ctx, store.LockingStrengthUpdate, network)
}

func (m *managerImpl) GetNetwork(ctx context.Context, accountID, userID, networkID string) (*types.Network, error) {
	ok, err := m.permissionsManager.ValidateUserPermissions(ctx, accountID, userID, permissions.Networks, permissions.Read)
	if err != nil {
		return nil, fmt.Errorf("failed to validate user permissions: %w", err)
	}
	if !ok {
		return nil, status.NewPermissionDeniedError()
	}

	return m.store.GetNetworkByID(ctx, store.LockingStrengthShare, accountID, networkID)
}

func (m *managerImpl) UpdateNetwork(ctx context.Context, userID string, network *types.Network) (*types.Network, error) {
	ok, err := m.permissionsManager.ValidateUserPermissions(ctx, network.AccountID, userID, permissions.Networks, permissions.Write)
	if err != nil {
		return nil, fmt.Errorf("failed to validate user permissions: %w", err)
	}
	if !ok {
		return nil, status.NewPermissionDeniedError()
	}

	return network, m.store.SaveNetwork(ctx, store.LockingStrengthUpdate, network)
}

func (m *managerImpl) DeleteNetwork(ctx context.Context, accountID, userID, networkID string) error {
	ok, err := m.permissionsManager.ValidateUserPermissions(ctx, accountID, userID, permissions.Networks, permissions.Write)
	if err != nil {
		return fmt.Errorf("failed to validate user permissions: %w", err)
	}
	if !ok {
		return status.NewPermissionDeniedError()
	}

	return m.store.DeleteNetwork(ctx, store.LockingStrengthUpdate, accountID, networkID)
}

func (m *managerImpl) GetResourceManager() resources.Manager {
	return m.resourcesManager
}

func (m *managerImpl) GetRouterManager() routers.Manager {
	return m.routersManager
}
