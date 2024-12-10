package resources

import (
	"context"

	"github.com/netbirdio/netbird/management/server/store"
)

type Manager interface {
	GetAllResources(ctx context.Context, accountID, userID, networkID string) ([]*NetworkResource, error)
	CreateResource(ctx context.Context, accountID string, resource *NetworkResource) (*NetworkResource, error)
	GetResource(ctx context.Context, accountID, userID, networkID, resourceID string) (*NetworkResource, error)
	UpdateResource(ctx context.Context, userID string, resource *NetworkResource) (*NetworkResource, error)
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

func (m *managerImpl) GetAllResources(ctx context.Context, accountID, userID, networkID string) ([]*NetworkResource, error) {
	return nil, nil
}

func (m *managerImpl) CreateResource(ctx context.Context, accountID string, resource *NetworkResource) (*NetworkResource, error) {
	return nil, nil
}

func (m *managerImpl) GetResource(ctx context.Context, accountID, userID, networkID, resourceID string) (*NetworkResource, error) {
	return nil, nil
}

func (m *managerImpl) UpdateResource(ctx context.Context, userID string, resource *NetworkResource) (*NetworkResource, error) {
	return nil, nil
}

func (m *managerImpl) DeleteResource(ctx context.Context, accountID, userID, networkID, resourceID string) error {
	return nil
}
