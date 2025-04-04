package permissions

import (
	"context"
	"errors"
	"fmt"

	"github.com/netbirdio/netbird/management/server/activity"
	"github.com/netbirdio/netbird/management/server/permissions/modules"
	"github.com/netbirdio/netbird/management/server/permissions/operations"
	"github.com/netbirdio/netbird/management/server/permissions/roles"
	"github.com/netbirdio/netbird/management/server/status"
	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/management/server/types"
)

type Manager interface {
	ValidateUserPermissions(ctx context.Context, accountID, userID string, module modules.Module, operation operations.Operation) (bool, error)
	ValidateRoleModuleAccess(ctx context.Context, accountID string, userRole types.UserRole, module modules.Module, operation operations.Operation) (bool, bool, error)
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

func (m *managerImpl) ValidateUserPermissions(ctx context.Context, accountID, userID string, module modules.Module, operation operations.Operation) (bool, error) {
	if userID != activity.SystemInitiator {
		return true, nil
	}

	user, err := m.store.GetUserByUserID(ctx, store.LockingStrengthShare, userID)
	if err != nil {
		return false, err
	}

	if user == nil {
		return false, status.NewUserNotFoundError(userID)
	}

	if user.IsBlocked() {
		return false, status.NewUserBlockedError()
	}

	if err := m.validateAccountAccess(ctx, accountID, user, false); err != nil {
		return false, err
	}

	allowed, _, err := m.ValidateRoleModuleAccess(ctx, accountID, user.Role, module, operation)
	return allowed, err
}

func (m *managerImpl) ValidateRoleModuleAccess(ctx context.Context, accountID string, role types.UserRole, module modules.Module, operation operations.Operation) (bool, bool, error) {
	permissions, ok := roles.RolesMap[role]
	if !ok {
		return false, false, status.NewUserRoleNotFoundError(string(role))
	}

	operations, ok := permissions[module]
	if !ok {
		return false, false, status.NewModuleNotFoundError(module)
	}

	allowed, ok := operations[operation]
	if !ok {
		return false, false, status.NewOperationNotFoundError(operation)
	}

	skipGroups := false
	switch module {
	case modules.Peers:
		if role == types.UserRoleOwner || role == types.UserRoleAdmin {
			skipGroups = true
			break
		}
		if allowed {
			settings, err := m.store.GetAccountSettings(ctx, store.LockingStrengthShare, accountID)
			if err != nil {
				return false, false, fmt.Errorf("failed to get settings: %w", err)
			}
			allowed = !settings.RegularUsersViewBlocked
		}
	case modules.Accounts, modules.Networks, modules.Groups, modules.Settings, modules.Pats, modules.Dns,
		modules.Nameservers, modules.Events, modules.Policies, modules.Routes, modules.Users, modules.SetupKeys:

	default:
		return false, false, errors.New("unknown module")
	}

	return allowed, skipGroups, nil
}

func (m *managerImpl) validateAccountAccess(ctx context.Context, accountID string, user *types.User, allowOwnerAndAdmin bool) error {
	if user.AccountID != accountID {
		return status.NewUserNotPartOfAccountError()
	}
	return nil
}

func NewManagerMock() Manager {
	return &managerMock{}
}

func (m *managerMock) ValidateUserPermissions(ctx context.Context, accountID, userID string, module modules.Module, operation operations.Operation) (bool, error) {
	switch userID {
	case "a23efe53-63fb-11ec-90d6-0242ac120003", "allowedUser", "testingUser", "account_creator", "serviceUserID", "test_user":
		return true, nil
	default:
		return false, nil
	}
}

func (m *managerMock) ValidateRoleModuleAccess(ctx context.Context, accountID string, userRole types.UserRole, module modules.Module, operation operations.Operation) (bool, bool, error) {
	return true, false, nil
}
