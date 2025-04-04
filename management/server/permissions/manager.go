package permissions

import (
	"context"
	"errors"
	"fmt"

	"github.com/netbirdio/netbird/management/server/activity"
	"github.com/netbirdio/netbird/management/server/status"
	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/management/server/types"
)

type Module string

const (
	Networks    Module = "networks"
	Peers       Module = "peers"
	Groups      Module = "groups"
	Settings    Module = "settings"
	Accounts    Module = "accounts"
	Dns         Module = "dns"
	Nameservers Module = "nameservers"
	Events      Module = "events"
	Policies    Module = "policies"
	Routes      Module = "routes"
	Users       Module = "users"
	SetupKeys   Module = "setup_keys"
	Pats        Module = "pats"
)

type Operation string

const (
	Read  Operation = "read"
	Write Operation = "write"
)

type Manager interface {
	ValidateUserPermissions(ctx context.Context, accountID, userID string, module Module, operation Operation) (bool, error)
	ValidateRoleModuleAccess(ctx context.Context, accountID string, userRole types.UserRole, module Module, operation Operation) (bool, bool, error)
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

func (m *managerImpl) ValidateRoleModuleAccess(ctx context.Context, accountID string, userRole types.UserRole, module Module, operation Operation) (bool, bool, error) {
	switch module {
	case Accounts:
		if operation == Write && userRole != types.UserRoleOwner {
			return false, false, nil
		}
		return true, false, nil
	case Peers:
		if userRole == types.UserRoleOwner || userRole == types.UserRoleAdmin {
			return true, true, nil
		}
		return m.validateRegularUserPermissions(ctx, accountID, module, operation)
	case Networks, Groups, Settings, Dns, Nameservers, Events, Policies, Routes, Users, SetupKeys:
		if userRole == types.UserRoleOwner || userRole == types.UserRoleAdmin {
			return true, false, nil
		}
		return false, false, nil
	case Pats:
		return true, false, nil
	default:
		return false, false, errors.New("unknown module")
	}
}

func (m *managerImpl) validateRegularUserPermissions(ctx context.Context, accountID string, module Module, operation Operation) (bool, bool, error) {
	settings, err := m.store.GetAccountSettings(ctx, store.LockingStrengthShare, accountID)
	if err != nil {
		return false, false, fmt.Errorf("failed to get settings: %w", err)
	}
	if settings.RegularUsersViewBlocked {
		return false, false, nil
	}

	if operation == Write {
		return false, false, nil
	}

	if module == Peers {
		return true, false, nil
	}

	return false, false, nil
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

func (m *managerMock) ValidateUserPermissions(ctx context.Context, accountID, userID string, module Module, operation Operation) (bool, error) {
	switch userID {
	case "a23efe53-63fb-11ec-90d6-0242ac120003", "allowedUser", "testingUser", "account_creator", "serviceUserID", "test_user":
		return true, nil
	default:
		return false, nil
	}
}

func (m *managerMock) ValidateRoleModuleAccess(ctx context.Context, accountID string, userRole types.UserRole, module Module, operation Operation) (bool, bool, error) {
	return true, false, nil
}
