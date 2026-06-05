package routers

import (
	"context"
	"errors"
	"fmt"

	"github.com/rs/xid"
	log "github.com/sirupsen/logrus"

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
	DeleteRouterInTransaction(ctx context.Context, transaction store.Store, accountID, userID, networkID, routerID string) (func(), error)
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

	affectedPeerIDs := snap.Expand(ctx, router.AccountID, change)
	if len(affectedPeerIDs) > 0 {
		log.WithContext(ctx).Debugf("CreateRouter %s: updating %d affected peers: %v", router.ID, len(affectedPeerIDs), affectedPeerIDs)
		go m.accountManager.UpdateAffectedPeers(ctx, router.AccountID, affectedPeerIDs)
	} else {
		log.WithContext(ctx).Tracef("CreateRouter %s: no affected peers", router.ID)
	}

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

	affectedPeerIDs := snap.Expand(ctx, router.AccountID, change)
	if len(affectedPeerIDs) > 0 {
		log.WithContext(ctx).Debugf("UpdateRouter %s: updating %d affected peers: %v", router.ID, len(affectedPeerIDs), affectedPeerIDs)
		go m.accountManager.UpdateAffectedPeers(ctx, router.AccountID, affectedPeerIDs)
	} else {
		log.WithContext(ctx).Tracef("UpdateRouter %s: no affected peers", router.ID)
	}

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

	if err = transaction.UpdateNetworkRouter(ctx, router); err != nil {
		return nil, nil, affectedpeers.Change{}, fmt.Errorf("failed to update network router: %w", err)
	}

	if err = transaction.IncrementNetworkSerial(ctx, router.AccountID); err != nil {
		return nil, nil, affectedpeers.Change{}, fmt.Errorf("failed to increment network serial: %w", err)
	}

	// Carry both the previous and updated router so the bridge folds the old and
	// new routing peers; a repoint loses the old peers' routing role and the
	// post-update state can no longer reach them.
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
		// Capture the router before delete: its peers lose their routing role and
		// the post-delete state can no longer reach them.
		existing, err := transaction.GetNetworkRouterByID(ctx, store.LockingStrengthUpdate, accountID, routerID)
		if err != nil {
			return fmt.Errorf("failed to get network router: %w", err)
		}
		change = affectedpeers.Change{Routers: []*types.NetworkRouter{existing}}
		if snap, err = affectedpeers.Load(ctx, transaction, accountID, change); err != nil {
			return err
		}

		event, err = m.DeleteRouterInTransaction(ctx, transaction, accountID, userID, networkID, routerID)
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

	affectedPeerIDs := snap.Expand(ctx, accountID, change)
	if len(affectedPeerIDs) > 0 {
		log.WithContext(ctx).Debugf("DeleteRouter %s: updating %d affected peers: %v", routerID, len(affectedPeerIDs), affectedPeerIDs)
		go m.accountManager.UpdateAffectedPeers(ctx, accountID, affectedPeerIDs)
	} else {
		log.WithContext(ctx).Tracef("DeleteRouter %s: no affected peers", routerID)
	}

	return nil
}

func (m *managerImpl) DeleteRouterInTransaction(ctx context.Context, transaction store.Store, accountID, userID, networkID, routerID string) (func(), error) {
	network, err := transaction.GetNetworkByID(ctx, store.LockingStrengthNone, accountID, networkID)
	if err != nil {
		return nil, fmt.Errorf("failed to get network: %w", err)
	}

	router, err := transaction.GetNetworkRouterByID(ctx, store.LockingStrengthUpdate, accountID, routerID)
	if err != nil {
		return nil, fmt.Errorf("failed to get network router: %w", err)
	}

	if router.NetworkID != networkID {
		return nil, status.NewRouterNotPartOfNetworkError(routerID, networkID)
	}

	err = transaction.DeleteNetworkRouter(ctx, accountID, routerID)
	if err != nil {
		return nil, fmt.Errorf("failed to delete network router: %w", err)
	}

	event := func() {
		m.accountManager.StoreEvent(ctx, userID, routerID, accountID, activity.NetworkRouterDeleted, router.EventMeta(network))
	}

	return event, nil
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

func (m *mockManager) DeleteRouterInTransaction(ctx context.Context, transaction store.Store, accountID, userID, networkID, routerID string) (func(), error) {
	return func() {}, nil
}
