package permissions

//go:generate go run github.com/golang/mock/mockgen -package permissions -destination=manager_mock.go -source=./manager.go -build_flags=-mod=mod

import (
	"context"
	"errors"
	"fmt"

	log "github.com/sirupsen/logrus"

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

func NewManager(store store.Store) Manager {
	return &managerImpl{
		store: store,
	}
}

func (m *managerImpl) ValidateUserPermissions(ctx context.Context, accountID, userID string, module modules.Module, operation operations.Operation) (bool, error) {
	if userID == activity.SystemInitiator {
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

	if operation == operations.Read && user.IsServiceUser {
		return true, nil // this should be replaced by proper granular access role
	}

	allowed, _, err := m.ValidateRoleModuleAccess(ctx, accountID, user.Role, module, operation)
	return allowed, err
}

func (m *managerImpl) ValidateRoleModuleAccess(ctx context.Context, accountID string, role types.UserRole, module modules.Module, operation operations.Operation) (bool, bool, error) {
	permissions, ok := roles.RolesMap[role]
	if !ok {
		return false, false, status.NewUserRoleNotFoundError(string(role))
	}

	var allowed bool
	operations, ok := permissions.Permissions[module]
	if ok {
		allowed, ok = operations[operation]
		if !ok {
			log.WithContext(ctx).Tracef("operation %s not found on module %s for role %s", operation, module, role)
			return false, false, nil
		}
	} else {
		if permissions.AutoAllowNew[operation] {
			allowed = true
		} else {
			log.WithContext(ctx).Tracef("permission %s is not allowed on module %s for role %s", operation, module, role)
			return false, false, nil
		}
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
