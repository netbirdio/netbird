package users

import (
	"context"
	"errors"

	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/management/server/types"
)

type Manager interface {
	GetUser(ctx context.Context, userID string) (*types.User, error)
	GetUserWithGroups(ctx context.Context, userID string) (*types.User, []*types.Group, error)
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
	return m.store.GetUserByUserID(ctx, store.LockingStrengthNone, userID)
}

// GetUserWithGroups returns the user and the *types.Group records for the user's AutoGroups, in the same order as
// AutoGroups. Group ids that don't resolve to a stored group are skipped from the returned slice (the parallel id list is
// derivable from the returned User). Wraps two store calls today; can be optimised to a single JOIN later if needed.
// Any store error returns (nil, nil, err) so callers never receive a valid user alongside a non-nil error.
func (m *managerImpl) GetUserWithGroups(ctx context.Context, userID string) (*types.User, []*types.Group, error) {
	user, err := m.store.GetUserByUserID(ctx, store.LockingStrengthNone, userID)
	if err != nil {
		return nil, nil, err
	}
	if len(user.AutoGroups) == 0 {
		return user, nil, nil
	}
	groupsMap, err := m.store.GetGroupsByIDs(ctx, store.LockingStrengthNone, user.AccountID, user.AutoGroups)
	if err != nil {
		return nil, nil, err
	}
	groups := make([]*types.Group, 0, len(user.AutoGroups))
	for _, id := range user.AutoGroups {
		if g, ok := groupsMap[id]; ok && g != nil {
			groups = append(groups, g)
		}
	}
	return user, groups, nil
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

func (m *managerMock) GetUserWithGroups(ctx context.Context, userID string) (*types.User, []*types.Group, error) {
	user, err := m.GetUser(ctx, userID)
	if err != nil {
		return nil, nil, err
	}
	return user, nil, nil
}
