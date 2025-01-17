package permissions

import (
	"context"
	"errors"
	"fmt"

	"github.com/netbirdio/netbird/management/server/settings"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/management/server/users"
)

type Module string

const (
	Networks Module = "networks"
	Peers    Module = "peers"
	Groups   Module = "groups"
)

type Operation string

const (
	Read  Operation = "read"
	Write Operation = "write"
)

type Manager interface {
	ValidateUserPermissions(ctx context.Context, accountID, userID string, module Module, operation Operation) (bool, error)
}

type managerImpl struct {
	userManager     users.Manager
	settingsManager settings.Manager
}

type managerMock struct {
}

func NewManager(userManager users.Manager, settingsManager settings.Manager) Manager {
	return &managerImpl{
		userManager:     userManager,
		settingsManager: settingsManager,
	}
}

func (m *managerImpl) ValidateUserPermissions(ctx context.Context, accountID, userID string, module Module, operation Operation) (bool, error) {
	user, err := m.userManager.GetUser(ctx, userID)
	if err != nil {
		return false, err
	}

	if user == nil {
		return false, errors.New("user not found")
	}

	if user.AccountID != accountID {
		return false, errors.New("user does not belong to account")
	}

	switch user.Role {
	case types.UserRoleAdmin, types.UserRoleOwner:
		return true, nil
	case types.UserRoleUser:
		return m.validateRegularUserPermissions(ctx, accountID, userID, module, operation)
	case types.UserRoleBillingAdmin:
		return false, nil
	default:
		return false, errors.New("invalid role")
	}
}

func (m *managerImpl) validateRegularUserPermissions(ctx context.Context, accountID, userID string, module Module, operation Operation) (bool, error) {
	settings, err := m.settingsManager.GetSettings(ctx, accountID, userID)
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

func NewManagerMock() Manager {
	return &managerMock{}
}

func (m *managerMock) ValidateUserPermissions(ctx context.Context, accountID, userID string, module Module, operation Operation) (bool, error) {
	if userID == "allowedUser" {
		return true, nil
	}
	return false, nil
}
