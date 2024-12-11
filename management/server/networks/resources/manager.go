package resources

import (
	"context"
	"errors"

	"github.com/netbirdio/netbird/management/server/networks/resources/types"
	"github.com/netbirdio/netbird/management/server/store"
)

type Manager interface {
	GetAllResources(ctx context.Context, accountID, userID, networkID string) ([]*types.NetworkResource, error)
	CreateResource(ctx context.Context, accountID string, resource *types.NetworkResource) (*types.NetworkResource, error)
	GetResource(ctx context.Context, accountID, userID, networkID, resourceID string) (*types.NetworkResource, error)
	UpdateResource(ctx context.Context, userID string, resource *types.NetworkResource) (*types.NetworkResource, error)
	DeleteResource(ctx context.Context, accountID, userID, networkID, resourceID string) error
}

type managerImpl struct {
	store store.Store
}

func NewManager(store store.Store) Manager {
	return &managerImpl{
		store: store,
	}
}

func (m *managerImpl) GetAllResources(ctx context.Context, accountID, userID, networkID string) ([]*types.NetworkResource, error) {
	return nil, errors.New("not implemented")
}

func (m *managerImpl) CreateResource(ctx context.Context, accountID string, resource *types.NetworkResource) (*types.NetworkResource, error) {
	return nil, errors.New("not implemented")
}

func (m *managerImpl) GetResource(ctx context.Context, accountID, userID, networkID, resourceID string) (*types.NetworkResource, error) {
	return nil, errors.New("not implemented")
}

func (m *managerImpl) UpdateResource(ctx context.Context, userID string, resource *types.NetworkResource) (*types.NetworkResource, error) {
	return nil, errors.New("not implemented")
}

func (m *managerImpl) DeleteResource(ctx context.Context, accountID, userID, networkID, resourceID string) error {
	return errors.New("not implemented")
}
