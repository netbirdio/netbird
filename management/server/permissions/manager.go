package permissions

import (
	"context"
	"errors"
	"fmt"

	"github.com/netbirdio/netbird/management/server/status"
	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/management/server/types"
)

type Module string

const (
	Networks Module = "networks"
	Peers    Module = "peers"
	Groups   Module = "groups"
	Settings Module = "settings"
	Accounts Module = "accounts"
)

type Operation string

const (
	Read  Operation = "read"
	Write Operation = "write"
)

type Manager interface {
	ValidateUserPermissions(ctx context.Context, accountID, userID string, module Module, operation Operation) (bool, error)
	ValidateAccountAccess(ctx context.Context, accountID string, user *types.User) error
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

func (m *managerImpl) ValidateUserPermissions(ctx context.Context, accountID, userID string, module Module, operation Operation) (bool, error) {
	user, err := m.store.GetUserByUserID(ctx, store.LockingStrengthShare, userID)
	if err != nil {
		return false, err
	}

	if user == nil {
		return false, status.NewUserNotFoundError(userID)
	}

	if err := m.ValidateAccountAccess(ctx, accountID, user); err != nil {
		return false, err
	}

	switch module {
	case Accounts:
		if operation == Write && user.Role != types.UserRoleOwner {
			return false, nil
		}
		return true, nil
	default:
	}

	switch user.Role {
	case types.UserRoleAdmin, types.UserRoleOwner:
		return true, nil
	case types.UserRoleUser:
		return m.validateRegularUserPermissions(ctx, accountID, module, operation)
	case types.UserRoleBillingAdmin:
		return false, nil
	default:
		return false, errors.New("invalid role")
	}
}

func (m *managerImpl) validateRegularUserPermissions(ctx context.Context, accountID string, module Module, operation Operation) (bool, error) {
	settings, err := m.store.GetAccountSettings(ctx, store.LockingStrengthShare, accountID)
	if err != nil {
		return false, fmt.Errorf("failed to get settings: %w", err)
	}
	if settings.RegularUsersViewBlocked {
		return false, nil
	}

	if operation == Write {
		return false, nil
	}

	if module == Peers {
		return true, nil
	}

	return false, nil
}

func (m *managerImpl) ValidateAccountAccess(ctx context.Context, accountID string, user *types.User) error {
	if user.AccountID != accountID {
		return status.NewUserNotPartOfAccountError()
	}
	return nil
}

func NewManagerMock() Manager {
	return &managerMock{}
}

func (m *managerMock) ValidateUserPermissions(ctx context.Context, accountID, userID string, module Module, operation Operation) (bool, error) {
	switch userID {
	case "a23efe53-63fb-11ec-90d6-0242ac120003", "allowedUser", "testingUser", "account_creator":
		return true, nil
	default:
		return false, nil
	}
}

func (m *managerMock) ValidateAccountAccess(ctx context.Context, accountID string, user *types.User) error {
	// @note managers explicitly checked this, so should the mock
	if user.AccountID != accountID {
		return status.NewUserNotPartOfAccountError()
	}
	return nil
}
