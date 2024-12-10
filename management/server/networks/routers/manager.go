package routers

import (
	"context"

	"github.com/netbirdio/netbird/management/server/store"
)

type Manager interface {
	GetAllRouters(ctx context.Context, accountID, userID, networkID string) ([]*NetworkRouter, error)
	CreateRouter(ctx context.Context, userID string, router *NetworkRouter) (*NetworkRouter, error)
	GetRouter(ctx context.Context, accountID, userID, networkID, routerID string) (*NetworkRouter, error)
	UpdateRouter(ctx context.Context, userID string, router *NetworkRouter) (*NetworkRouter, error)
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

func (m *managerImpl) GetAllRouters(ctx context.Context, accountID, userID, networkID string) ([]*NetworkRouter, error) {
	return nil, nil
}

func (m *managerImpl) CreateRouter(ctx context.Context, userID string, router *NetworkRouter) (*NetworkRouter, error) {
	return nil, nil
}

func (m *managerImpl) GetRouter(ctx context.Context, accountID, userID, networkID, routerID string) (*NetworkRouter, error) {
	return nil, nil
}

func (m *managerImpl) UpdateRouter(ctx context.Context, userID string, router *NetworkRouter) (*NetworkRouter, error) {
	return nil, nil
}

func (m *managerImpl) DeleteRouter(ctx context.Context, accountID, userID, networkID, routerID string) error {
	return nil
}
