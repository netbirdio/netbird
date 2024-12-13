package users

import (
	"context"

	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/management/server/types"
)

type Manager interface {
	GetUser(ctx context.Context, userID string) (*types.User, error)
}

type managerImpl struct {
	store store.Store
}

func NewManager(store store.Store) Manager {
	return &managerImpl{
		store: store,
	}
}

func (m *managerImpl) GetUser(ctx context.Context, userID string) (*types.User, error) {
	return m.store.GetUserByUserID(ctx, store.LockingStrengthShare, userID)
}
