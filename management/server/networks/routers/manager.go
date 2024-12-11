package routers

import (
	"context"
	"errors"

	"github.com/netbirdio/netbird/management/server/networks/routers/types"
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
	store store.Store
}

func NewManager(store store.Store) Manager {
	return &managerImpl{
		store: store,
	}
}

func (m *managerImpl) GetAllRouters(ctx context.Context, accountID, userID, networkID string) ([]*types.NetworkRouter, error) {
	return nil, errors.New("not implemented")
}

func (m *managerImpl) CreateRouter(ctx context.Context, userID string, router *types.NetworkRouter) (*types.NetworkRouter, error) {
	return nil, errors.New("not implemented")
}

func (m *managerImpl) GetRouter(ctx context.Context, accountID, userID, networkID, routerID string) (*types.NetworkRouter, error) {
	return nil, errors.New("not implemented")
}

func (m *managerImpl) UpdateRouter(ctx context.Context, userID string, router *types.NetworkRouter) (*types.NetworkRouter, error) {
	return nil, errors.New("not implemented")
}

func (m *managerImpl) DeleteRouter(ctx context.Context, accountID, userID, networkID, routerID string) error {
	return errors.New("not implemented")
}
