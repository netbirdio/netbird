package networks

import (
	"context"
	"errors"

	"github.com/netbirdio/netbird/management/server/networks/resources"
	"github.com/netbirdio/netbird/management/server/networks/routers"
	"github.com/netbirdio/netbird/management/server/networks/types"
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
	store            store.Store
	routersManager   routers.Manager
	resourcesManager resources.Manager
}

func NewManager(store store.Store) Manager {
	return &managerImpl{
		store:            store,
		routersManager:   routers.NewManager(store),
		resourcesManager: resources.NewManager(store),
	}
}

func (m *managerImpl) GetAllNetworks(ctx context.Context, accountID, userID string) ([]*types.Network, error) {
	return nil, errors.New("not implemented")
}

func (m *managerImpl) CreateNetwork(ctx context.Context, userID string, network *types.Network) (*types.Network, error) {
	return nil, errors.New("not implemented")
}

func (m *managerImpl) GetNetwork(ctx context.Context, accountID, userID, networkID string) (*types.Network, error) {
	return nil, errors.New("not implemented")
}

func (m *managerImpl) UpdateNetwork(ctx context.Context, userID string, network *types.Network) (*types.Network, error) {
	return nil, errors.New("not implemented")
}

func (m *managerImpl) DeleteNetwork(ctx context.Context, accountID, userID, networkID string) error {
	return errors.New("not implemented")
}

func (m *managerImpl) GetResourceManager() resources.Manager {
	return m.resourcesManager
}

func (m *managerImpl) GetRouterManager() routers.Manager {
	return m.routersManager
}
