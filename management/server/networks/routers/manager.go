package routers

import (
	"context"
	"errors"
	"fmt"

	"github.com/rs/xid"

	"github.com/netbirdio/netbird/management/server/networks/routers/types"
	"github.com/netbirdio/netbird/management/server/permissions"
	"github.com/netbirdio/netbird/management/server/store"
)

type Manager interface {
	GetAllRouters(ctx context.Context, accountID, userID, networkID string) ([]*types.NetworkRouter, error)
	CreateRouter(ctx context.Context, userID string, router *types.NetworkRouter) (*types.NetworkRouter, error)
	GetRouter(ctx context.Context, accountID, userID, networkID, routerID string) (*types.NetworkRouter, error)
	UpdateRouter(ctx context.Context, userID string, router *types.NetworkRouter) (*types.NetworkRouter, error)
	DeleteRouter(ctx context.Context, accountID, userID, networkID, routerID string) error
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

func (m *managerImpl) GetAllRouters(ctx context.Context, accountID, userID, networkID string) ([]*types.NetworkRouter, error) {
	ok, err := m.permissionsManager.ValidateUserPermissions(ctx, accountID, userID, permissions.Networks, permissions.Read)
	if err != nil {
		return nil, fmt.Errorf("failed to validate user permissions: %w", err)
	}
	if !ok {
		return nil, errors.New("permission denied")
	}

	return m.store.GetNetworkRoutersByNetID(ctx, store.LockingStrengthShare, accountID, networkID)
}

func (m *managerImpl) CreateRouter(ctx context.Context, userID string, router *types.NetworkRouter) (*types.NetworkRouter, error) {
	ok, err := m.permissionsManager.ValidateUserPermissions(ctx, router.AccountID, userID, permissions.Networks, permissions.Write)
	if err != nil {
		return nil, fmt.Errorf("failed to validate user permissions: %w", err)
	}
	if !ok {
		return nil, errors.New("permission denied")
	}

	router.ID = xid.New().String()

	return router, m.store.SaveNetworkRouter(ctx, store.LockingStrengthUpdate, router)
}

func (m *managerImpl) GetRouter(ctx context.Context, accountID, userID, networkID, routerID string) (*types.NetworkRouter, error) {
	ok, err := m.permissionsManager.ValidateUserPermissions(ctx, accountID, userID, permissions.Networks, permissions.Read)
	if err != nil {
		return nil, fmt.Errorf("failed to validate user permissions: %w", err)
	}
	if !ok {
		return nil, errors.New("permission denied")
	}

	router, err := m.store.GetNetworkRouterByID(ctx, store.LockingStrengthShare, accountID, routerID)
	if err != nil {
		return nil, fmt.Errorf("failed to get network router: %w", err)
	}

	if router.NetworkID != networkID {
		return nil, errors.New("router not part of network")
	}

	return router, nil
}

func (m *managerImpl) UpdateRouter(ctx context.Context, userID string, router *types.NetworkRouter) (*types.NetworkRouter, error) {
	ok, err := m.permissionsManager.ValidateUserPermissions(ctx, router.ID, userID, permissions.Networks, permissions.Write)
	if err != nil {
		return nil, fmt.Errorf("failed to validate user permissions: %w", err)
	}
	if !ok {
		return nil, errors.New("permission denied")
	}

	return router, m.store.SaveNetworkRouter(ctx, store.LockingStrengthUpdate, router)
}

func (m *managerImpl) DeleteRouter(ctx context.Context, accountID, userID, networkID, routerID string) error {
	ok, err := m.permissionsManager.ValidateUserPermissions(ctx, accountID, userID, permissions.Networks, permissions.Write)
	if err != nil {
		return fmt.Errorf("failed to validate user permissions: %w", err)
	}
	if !ok {
		return errors.New("permission denied")
	}

	return m.store.DeleteNetworkRouter(ctx, store.LockingStrengthUpdate, accountID, routerID)
}
