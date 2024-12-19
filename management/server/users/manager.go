package users

import (
	"context"
	"errors"

	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/management/server/types"
)

type Manager interface {
	GetUser(ctx context.Context, userID string) (*types.User, error)
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

func (m *managerImpl) GetUser(ctx context.Context, userID string) (*types.User, error) {
	return m.store.GetUserByUserID(ctx, store.LockingStrengthShare, userID)
}

func NewManagerMock() Manager {
	return &managerMock{}
}

func (m *managerMock) GetUser(ctx context.Context, userID string) (*types.User, error) {
	switch userID {
	case "adminUser":
		return &types.User{Id: userID, Role: types.UserRoleAdmin}, nil
	case "regularUser":
		return &types.User{Id: userID, Role: types.UserRoleUser}, nil
	case "ownerUser":
		return &types.User{Id: userID, Role: types.UserRoleOwner}, nil
	case "billingUser":
		return &types.User{Id: userID, Role: types.UserRoleBillingAdmin}, nil
	default:
		return nil, errors.New("user not found")
	}
}
