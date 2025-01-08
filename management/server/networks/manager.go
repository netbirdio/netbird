package networks

import (
	"context"
	"fmt"

	"github.com/rs/xid"

	s "github.com/netbirdio/netbird/management/server"
	"github.com/netbirdio/netbird/management/server/activity"
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
}

type managerImpl struct {
	store              store.Store
	accountManager     s.AccountManager
	permissionsManager permissions.Manager
	resourcesManager   resources.Manager
	routersManager     routers.Manager
}

type mockManager struct {
}

func NewManager(store store.Store, permissionsManager permissions.Manager, resourceManager resources.Manager, routersManager routers.Manager, accountManager s.AccountManager) Manager {
	return &managerImpl{
		store:              store,
		permissionsManager: permissionsManager,
		resourcesManager:   resourceManager,
		routersManager:     routersManager,
		accountManager:     accountManager,
	}
}

func (m *managerImpl) GetAllNetworks(ctx context.Context, accountID, userID string) ([]*types.Network, error) {
	ok, err := m.permissionsManager.ValidateUserPermissions(ctx, accountID, userID, permissions.Networks, permissions.Read)
	if err != nil {
		return nil, status.NewPermissionValidationError(err)
	}
	if !ok {
		return nil, status.NewPermissionDeniedError()
	}

	return m.store.GetAccountNetworks(ctx, store.LockingStrengthShare, accountID)
}

func (m *managerImpl) CreateNetwork(ctx context.Context, userID string, network *types.Network) (*types.Network, error) {
	ok, err := m.permissionsManager.ValidateUserPermissions(ctx, network.AccountID, userID, permissions.Networks, permissions.Write)
	if err != nil {
		return nil, status.NewPermissionValidationError(err)
	}
	if !ok {
		return nil, status.NewPermissionDeniedError()
	}

	network.ID = xid.New().String()

	unlock := m.store.AcquireWriteLockByUID(ctx, network.AccountID)
	defer unlock()

	err = m.store.SaveNetwork(ctx, store.LockingStrengthUpdate, network)
	if err != nil {
		return nil, fmt.Errorf("failed to save network: %w", err)
	}

	m.accountManager.StoreEvent(ctx, userID, network.ID, network.AccountID, activity.NetworkCreated, network.EventMeta())

	return network, nil
}

func (m *managerImpl) GetNetwork(ctx context.Context, accountID, userID, networkID string) (*types.Network, error) {
	ok, err := m.permissionsManager.ValidateUserPermissions(ctx, accountID, userID, permissions.Networks, permissions.Read)
	if err != nil {
		return nil, status.NewPermissionValidationError(err)
	}
	if !ok {
		return nil, status.NewPermissionDeniedError()
	}

	return m.store.GetNetworkByID(ctx, store.LockingStrengthShare, accountID, networkID)
}

func (m *managerImpl) UpdateNetwork(ctx context.Context, userID string, network *types.Network) (*types.Network, error) {
	ok, err := m.permissionsManager.ValidateUserPermissions(ctx, network.AccountID, userID, permissions.Networks, permissions.Write)
	if err != nil {
		return nil, status.NewPermissionValidationError(err)
	}
	if !ok {
		return nil, status.NewPermissionDeniedError()
	}

	unlock := m.store.AcquireWriteLockByUID(ctx, network.AccountID)
	defer unlock()

	_, err = m.store.GetNetworkByID(ctx, store.LockingStrengthUpdate, network.AccountID, network.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to get network: %w", err)
	}

	m.accountManager.StoreEvent(ctx, userID, network.ID, network.AccountID, activity.NetworkUpdated, network.EventMeta())

	return network, m.store.SaveNetwork(ctx, store.LockingStrengthUpdate, network)
}

func (m *managerImpl) DeleteNetwork(ctx context.Context, accountID, userID, networkID string) error {
	ok, err := m.permissionsManager.ValidateUserPermissions(ctx, accountID, userID, permissions.Networks, permissions.Write)
	if err != nil {
		return status.NewPermissionValidationError(err)
	}
	if !ok {
		return status.NewPermissionDeniedError()
	}

	network, err := m.store.GetNetworkByID(ctx, store.LockingStrengthUpdate, accountID, networkID)
	if err != nil {
		return fmt.Errorf("failed to get network: %w", err)
	}

	unlock := m.store.AcquireWriteLockByUID(ctx, accountID)
	defer unlock()

	var eventsToStore []func()
	err = m.store.ExecuteInTransaction(ctx, func(transaction store.Store) error {
		resources, err := transaction.GetNetworkResourcesByNetID(ctx, store.LockingStrengthUpdate, accountID, networkID)
		if err != nil {
			return fmt.Errorf("failed to get resources in network: %w", err)
		}

		for _, resource := range resources {
			event, err := m.resourcesManager.DeleteResourceInTransaction(ctx, transaction, accountID, userID, networkID, resource.ID)
			if err != nil {
				return fmt.Errorf("failed to delete resource: %w", err)
			}
			eventsToStore = append(eventsToStore, event...)
		}

		routers, err := transaction.GetNetworkRoutersByNetID(ctx, store.LockingStrengthUpdate, accountID, networkID)
		if err != nil {
			return fmt.Errorf("failed to get routers in network: %w", err)
		}

		for _, router := range routers {
			event, err := m.routersManager.DeleteRouterInTransaction(ctx, transaction, accountID, userID, networkID, router.ID)
			if err != nil {
				return fmt.Errorf("failed to delete router: %w", err)
			}
			eventsToStore = append(eventsToStore, event)
		}

		err = transaction.DeleteNetwork(ctx, store.LockingStrengthUpdate, accountID, networkID)
		if err != nil {
			return fmt.Errorf("failed to delete network: %w", err)
		}

		err = transaction.IncrementNetworkSerial(ctx, store.LockingStrengthUpdate, accountID)
		if err != nil {
			return fmt.Errorf("failed to increment network serial: %w", err)
		}

		eventsToStore = append(eventsToStore, func() {
			m.accountManager.StoreEvent(ctx, userID, networkID, accountID, activity.NetworkDeleted, network.EventMeta())
		})

		return nil
	})
	if err != nil {
		return fmt.Errorf("failed to delete network: %w", err)
	}

	for _, event := range eventsToStore {
		event()
	}

	go m.accountManager.UpdateAccountPeers(ctx, accountID)

	return nil
}

func NewManagerMock() Manager {
	return &mockManager{}
}

func (m *mockManager) GetAllNetworks(ctx context.Context, accountID, userID string) ([]*types.Network, error) {
	return []*types.Network{}, nil
}

func (m *mockManager) CreateNetwork(ctx context.Context, userID string, network *types.Network) (*types.Network, error) {
	return network, nil
}

func (m *mockManager) GetNetwork(ctx context.Context, accountID, userID, networkID string) (*types.Network, error) {
	return &types.Network{}, nil
}

func (m *mockManager) UpdateNetwork(ctx context.Context, userID string, network *types.Network) (*types.Network, error) {
	return network, nil
}

func (m *mockManager) DeleteNetwork(ctx context.Context, accountID, userID, networkID string) error {
	return nil
}
