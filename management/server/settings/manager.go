package settings

import (
	"context"

	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/management/server/types"
)

type Manager interface {
	GetSettings(ctx context.Context, accountID string, userID string) (*types.Settings, error)
}

type managerImpl struct {
	store store.Store
}

type managerMock struct {
}

func NewManager(store store.Store) Manager {
	return &managerImpl{
		store: store,
	}
}

func (m *managerImpl) GetSettings(ctx context.Context, accountID string, userID string) (*types.Settings, error) {
	return m.store.GetAccountSettings(ctx, store.LockingStrengthShare, accountID)
}

func NewManagerMock() Manager {
	return &managerMock{}
}

func (m *managerMock) GetSettings(ctx context.Context, accountID string, userID string) (*types.Settings, error) {
	return &types.Settings{}, nil
}
