package permissions

import (
	"context"
	"errors"
	"fmt"

	"github.com/netbirdio/netbird/management/server/activity"
	"github.com/netbirdio/netbird/management/server/settings"
	"github.com/netbirdio/netbird/management/server/status"
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
	ValidateAccountAccess(ctx context.Context, accountID string, user *types.User) error
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
		return false, status.NewUserNotFoundError(userID)
	}

	if err := m.ValidateAccountAccess(ctx, accountID, user); err != nil {
		return false, err
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
	settings, err := m.settingsManager.GetSettings(ctx, accountID, activity.SystemInitiator)
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
	if userID == "allowedUser" {
		return true, nil
	}
	return false, nil
}

func (m *managerMock) ValidateAccountAccess(ctx context.Context, accountID string, user *types.User) error {
	// @note managers explicitly checked this, so should the mock
	if user.AccountID != accountID {
		return status.NewUserNotPartOfAccountError()
	}
	return nil
}
