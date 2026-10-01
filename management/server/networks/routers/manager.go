package routers

import (
	"context"
	"errors"
	"fmt"

	"github.com/rs/xid"

	"github.com/netbirdio/netbird/management/server/account"
	"github.com/netbirdio/netbird/management/server/activity"
	"github.com/netbirdio/netbird/management/server/affectedpeers"
	"github.com/netbirdio/netbird/management/server/networks/routers/types"
	networkTypes "github.com/netbirdio/netbird/management/server/networks/types"
	"github.com/netbirdio/netbird/management/server/permissions"
	"github.com/netbirdio/netbird/management/server/permissions/modules"
	"github.com/netbirdio/netbird/management/server/permissions/operations"
	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/shared/management/status"
)

type Manager interface {
	GetAllRoutersInNetwork(ctx context.Context, accountID, userID, networkID string) ([]*types.NetworkRouter, error)
	GetAllRoutersInAccount(ctx context.Context, accountID, userID string) (map[string][]*types.NetworkRouter, error)
	CreateRouter(ctx context.Context, userID string, router *types.NetworkRouter) (*types.NetworkRouter, error)
	GetRouter(ctx context.Context, accountID, userID, networkID, routerID string) (*types.NetworkRouter, error)
	UpdateRouter(ctx context.Context, userID string, router *types.NetworkRouter) (*types.NetworkRouter, error)
	DeleteRouter(ctx context.Context, accountID, userID, networkID, routerID string) error
	DeleteRouterInTransaction(ctx context.Context, transaction store.Store, accountID, userID, networkID, routerID string) (*types.NetworkRouter, func(), error)
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

func (m *managerImpl) GetAllRoutersInNetwork(ctx context.Context, accountID, userID, networkID string) ([]*types.NetworkRouter, error) {
	ok, ctx, err := m.permissionsManager.ValidateUserPermissions(ctx, accountID, userID, modules.Networks, operations.Read)
	if err != nil {
		return nil, status.NewPermissionValidationError(err)
	}
	if !ok {
		return nil, status.NewPermissionDeniedError()
	}

	return m.store.GetNetworkRoutersByNetID(ctx, store.LockingStrengthNone, accountID, networkID)
}

func (m *managerImpl) GetAllRoutersInAccount(ctx context.Context, accountID, userID string) (map[string][]*types.NetworkRouter, error) {
	ok, ctx, err := m.permissionsManager.ValidateUserPermissions(ctx, accountID, userID, modules.Networks, operations.Read)
	if err != nil {
		return nil, status.NewPermissionValidationError(err)
	}
	if !ok {
		return nil, status.NewPermissionDeniedError()
	}

	routers, err := m.store.GetNetworkRoutersByAccountID(ctx, store.LockingStrengthNone, accountID)
	if err != nil {
		return nil, fmt.Errorf("failed to get network routers: %w", err)
	}

	routersMap := make(map[string][]*types.NetworkRouter)
	for _, router := range routers {
		routersMap[router.NetworkID] = append(routersMap[router.NetworkID], router)
	}

	return routersMap, nil
}

func (m *managerImpl) CreateRouter(ctx context.Context, userID string, router *types.NetworkRouter) (*types.NetworkRouter, error) {
	ok, ctx, err := m.permissionsManager.ValidateUserPermissions(ctx, router.AccountID, userID, modules.Networks, operations.Create)
	if err != nil {
		return nil, status.NewPermissionValidationError(err)
	}
	if !ok {
		return nil, status.NewPermissionDeniedError()
	}

	var network *networkTypes.Network
	var snap *affectedpeers.Snapshot
	change := affectedpeers.Change{Routers: []*types.NetworkRouter{router}}
	err = m.store.ExecuteInTransaction(ctx, func(transaction store.Store) error {
		network, err = transaction.GetNetworkByID(ctx, store.LockingStrengthNone, router.AccountID, router.NetworkID)
		if err != nil {
			return fmt.Errorf("failed to get network: %w", err)
		}

		if network.ID != router.NetworkID {
			return status.NewNetworkNotFoundError(router.NetworkID)
		}

		router.ID = xid.New().String()

		router.PublicID = xid.New().String()

		err = transaction.CreateNetworkRouter(ctx, router)
		if err != nil {
			return fmt.Errorf("failed to create network router: %w", err)
		}

		err = transaction.IncrementNetworkSerial(ctx, router.AccountID)
		if err != nil {
			return fmt.Errorf("failed to increment network serial: %w", err)
		}

		if snap, err = affectedpeers.Load(ctx, transaction, router.AccountID, change); err != nil {
			return err
		}

		return nil
	})
	if err != nil {
		return nil, err
	}

	m.accountManager.StoreEvent(ctx, userID, router.ID, router.AccountID, activity.NetworkRouterCreated, router.EventMeta(network))

	m.accountManager.ExpandAndUpdateAffected(ctx, router.AccountID, snap, change)

	return router, nil
}

func (m *managerImpl) GetRouter(ctx context.Context, accountID, userID, networkID, routerID string) (*types.NetworkRouter, error) {
	ok, ctx, err := m.permissionsManager.ValidateUserPermissions(ctx, accountID, userID, modules.Networks, operations.Read)
	if err != nil {
		return nil, status.NewPermissionValidationError(err)
	}
	if !ok {
		return nil, status.NewPermissionDeniedError()
	}

	router, err := m.store.GetNetworkRouterByID(ctx, store.LockingStrengthNone, accountID, routerID)
	if err != nil {
		return nil, fmt.Errorf("failed to get network router: %w", err)
	}

	if router.NetworkID != networkID {
		return nil, errors.New("router not part of network")
	}

	return router, nil
}

func (m *managerImpl) UpdateRouter(ctx context.Context, userID string, router *types.NetworkRouter) (*types.NetworkRouter, error) {
	ok, ctx, err := m.permissionsManager.ValidateUserPermissions(ctx, router.AccountID, userID, modules.Networks, operations.Update)
	if err != nil {
		return nil, status.NewPermissionValidationError(err)
	}
	if !ok {
		return nil, status.NewPermissionDeniedError()
	}

	var network *networkTypes.Network
	var snap *affectedpeers.Snapshot
	var change affectedpeers.Change
	err = m.store.ExecuteInTransaction(ctx, func(transaction store.Store) error {
		var txErr error
		network, snap, change, txErr = m.updateRouterInTransaction(ctx, transaction, router)
		return txErr
	})
	if err != nil {
		return nil, err
	}

	m.accountManager.StoreEvent(ctx, userID, router.ID, router.AccountID, activity.NetworkRouterUpdated, router.EventMeta(network))

	m.accountManager.ExpandAndUpdateAffected(ctx, router.AccountID, snap, change)

	return router, nil
}

func (m *managerImpl) updateRouterInTransaction(ctx context.Context, transaction store.Store, router *types.NetworkRouter) (*networkTypes.Network, *affectedpeers.Snapshot, affectedpeers.Change, error) {
	network, err := transaction.GetNetworkByID(ctx, store.LockingStrengthNone, router.AccountID, router.NetworkID)
	if err != nil {
		return nil, nil, affectedpeers.Change{}, fmt.Errorf("failed to get network: %w", err)
	}

	existing, err := transaction.GetNetworkRouterByID(ctx, store.LockingStrengthUpdate, router.AccountID, router.ID)
	if err != nil {
		return nil, nil, affectedpeers.Change{}, fmt.Errorf("failed to get network router: %w", err)
	}

	if existing.AccountID != router.AccountID {
		return nil, nil, affectedpeers.Change{}, status.NewNetworkRouterNotFoundError(router.ID)
	}

	if existing.NetworkID != router.NetworkID {
		return nil, nil, affectedpeers.Change{}, status.NewRouterNotPartOfNetworkError(router.ID, router.NetworkID)
	}

	// Preserve PublicID from the existing router so the upstream
	// UpdateNetworkRouter (which does Updates(router) with Select("*"))
	// doesn't clobber it with the request's zero value.
	router.PublicID = existing.PublicID

	if err = transaction.UpdateNetworkRouter(ctx, router); err != nil {
		return nil, nil, affectedpeers.Change{}, fmt.Errorf("failed to update network router: %w", err)
	}

	if err = transaction.IncrementNetworkSerial(ctx, router.AccountID); err != nil {
		return nil, nil, affectedpeers.Change{}, fmt.Errorf("failed to increment network serial: %w", err)
	}

	change := affectedpeers.Change{Routers: []*types.NetworkRouter{existing, router}}
	snap, err := affectedpeers.Load(ctx, transaction, router.AccountID, change)
	if err != nil {
		return nil, nil, affectedpeers.Change{}, err
	}

	return network, snap, change, nil
}

func (m *managerImpl) DeleteRouter(ctx context.Context, accountID, userID, networkID, routerID string) error {
	ok, ctx, err := m.permissionsManager.ValidateUserPermissions(ctx, accountID, userID, modules.Networks, operations.Delete)
	if err != nil {
		return status.NewPermissionValidationError(err)
	}
	if !ok {
		return status.NewPermissionDeniedError()
	}

	var event func()
	var snap *affectedpeers.Snapshot
	var change affectedpeers.Change
	err = m.store.ExecuteInTransaction(ctx, func(transaction store.Store) error {
		existing, err := transaction.GetNetworkRouterByID(ctx, store.LockingStrengthUpdate, accountID, routerID)
		if err != nil {
			return fmt.Errorf("failed to get network router: %w", err)
		}
		change = affectedpeers.Change{Routers: []*types.NetworkRouter{existing}}
		if snap, err = affectedpeers.Load(ctx, transaction, accountID, change); err != nil {
			return err
		}

		_, event, err = m.DeleteRouterInTransaction(ctx, transaction, accountID, userID, networkID, routerID)
		if err != nil {
			return fmt.Errorf("failed to delete network router: %w", err)
		}

		err = transaction.IncrementNetworkSerial(ctx, accountID)
		if err != nil {
			return fmt.Errorf("failed to increment network serial: %w", err)
		}

		return nil
	})
	if err != nil {
		return err
	}

	event()

	m.accountManager.ExpandAndUpdateAffected(ctx, accountID, snap, change)

	return nil
}

func (m *managerImpl) DeleteRouterInTransaction(ctx context.Context, transaction store.Store, accountID, userID, networkID, routerID string) (*types.NetworkRouter, func(), error) {
	network, err := transaction.GetNetworkByID(ctx, store.LockingStrengthNone, accountID, networkID)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get network: %w", err)
	}

	router, err := transaction.GetNetworkRouterByID(ctx, store.LockingStrengthUpdate, accountID, routerID)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get network router: %w", err)
	}

	if router.NetworkID != networkID {
		return nil, nil, status.NewRouterNotPartOfNetworkError(routerID, networkID)
	}

	err = transaction.DeleteNetworkRouter(ctx, accountID, routerID)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to delete network router: %w", err)
	}

	event := func() {
		m.accountManager.StoreEvent(ctx, userID, routerID, accountID, activity.NetworkRouterDeleted, router.EventMeta(network))
	}

	return router, event, nil
}

func NewManagerMock() Manager {
	return &mockManager{}
}

func (m *mockManager) GetAllRoutersInNetwork(ctx context.Context, accountID, userID, networkID string) ([]*types.NetworkRouter, error) {
	return []*types.NetworkRouter{}, nil
}

func (m *mockManager) GetAllRoutersInAccount(ctx context.Context, accountID, userID string) (map[string][]*types.NetworkRouter, error) {
	return map[string][]*types.NetworkRouter{}, nil
}

func (m *mockManager) CreateRouter(ctx context.Context, userID string, router *types.NetworkRouter) (*types.NetworkRouter, error) {
	return router, nil
}

func (m *mockManager) GetRouter(ctx context.Context, accountID, userID, networkID, routerID string) (*types.NetworkRouter, error) {
	return &types.NetworkRouter{}, nil
}

func (m *mockManager) UpdateRouter(ctx context.Context, userID string, router *types.NetworkRouter) (*types.NetworkRouter, error) {
	return router, nil
}

func (m *mockManager) DeleteRouter(ctx context.Context, accountID, userID, networkID, routerID string) error {
	return nil
}

func (m *mockManager) DeleteRouterInTransaction(ctx context.Context, transaction store.Store, accountID, userID, networkID, routerID string) (*types.NetworkRouter, func(), error) {
	return nil, func() {
		// no-op mock: returns zero values so tests that don't exercise router deletion
		// can satisfy the Manager interface without a real store.
	}, nil
}
