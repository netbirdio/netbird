package permissions

//go:generate go run github.com/golang/mock/mockgen -package permissions -destination=manager_mock.go -source=./manager.go -build_flags=-mod=mod

import (
	"context"
	"net/http"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/management/internals/modules/permissions/modules"
	"github.com/netbirdio/netbird/management/internals/modules/permissions/operations"
	"github.com/netbirdio/netbird/management/internals/modules/permissions/roles"
	"github.com/netbirdio/netbird/management/server/account"
	"github.com/netbirdio/netbird/management/server/activity"
	nbcontext "github.com/netbirdio/netbird/management/server/context"
	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/shared/auth"
	"github.com/netbirdio/netbird/shared/management/http/util"
	"github.com/netbirdio/netbird/shared/management/status"
)

// AuthErrorHandler is called when an auth error occurs during permission validation.
// If it returns true, the error is considered handled and the default error response is skipped.
type AuthErrorHandler func(w http.ResponseWriter, r *http.Request, userAuth *auth.UserAuth, err error) bool

type Manager interface {
	WithPermission(module modules.Module, operation operations.Operation, handlerFunc func(w http.ResponseWriter, r *http.Request, auth *auth.UserAuth), authErrHandler ...AuthErrorHandler) http.HandlerFunc
	ValidateUserPermissions(ctx context.Context, accountID, userID string, module modules.Module, operation operations.Operation) (bool, error)
	ValidateRoleModuleAccess(ctx context.Context, accountID string, role roles.RolePermissions, module modules.Module, operation operations.Operation) bool
	ValidateAccountAccess(ctx context.Context, accountID string, user *types.User, allowOwnerAndAdmin bool) error

	GetPermissionsByRole(ctx context.Context, role types.UserRole) (roles.Permissions, error)
	SetAccountManager(accountManager account.Manager)
}

type managerImpl struct {
	store store.Store
}

func NewManager(store store.Store) Manager {
	return &managerImpl{
		store: store,
	}
}

// WithPermission wraps an HTTP handler with permission checking logic.
// An optional AuthErrorHandler can be provided to intercept auth errors before the default response is written.
func (m *managerImpl) WithPermission(
	module modules.Module,
	operation operations.Operation,
	handlerFunc func(w http.ResponseWriter, r *http.Request, auth *auth.UserAuth),
	authErrHandler ...AuthErrorHandler,
) http.HandlerFunc {
	var onAuthErr AuthErrorHandler
	if len(authErrHandler) > 0 {
		onAuthErr = authErrHandler[0]
	}

	return func(w http.ResponseWriter, r *http.Request) {
		userAuth, err := nbcontext.GetUserAuthFromContext(r.Context())
		if err != nil {
			log.WithContext(r.Context()).Errorf("failed to get user auth from context: %v", err)
			util.WriteError(r.Context(), err, w)
			return
		}

		allowed, err := m.ValidateUserPermissions(r.Context(), userAuth.AccountId, userAuth.UserId, module, operation)
		if err != nil {
			if onAuthErr != nil && onAuthErr(w, r, &userAuth, err) {
				return
			}
			log.WithContext(r.Context()).Errorf("failed to validate permissions for user %s on account %s: %v", userAuth.UserId, userAuth.AccountId, err)
			util.WriteError(r.Context(), status.NewPermissionValidationError(err), w)
			return
		}

		if !allowed {
			permErr := status.NewPermissionDeniedError()
			if onAuthErr != nil && onAuthErr(w, r, &userAuth, permErr) {
				return
			}
			log.WithContext(r.Context()).Tracef("user %s on account %s is not allowed to %s in %s", userAuth.UserId, userAuth.AccountId, operation, module)
			util.WriteError(r.Context(), permErr, w)
			return
		}

		handlerFunc(w, r, &userAuth)
	}
}

func (m *managerImpl) ValidateUserPermissions(
	ctx context.Context,
	accountID string,
	userID string,
	module modules.Module,
	operation operations.Operation,
) (bool, error) {
	if userID == activity.SystemInitiator {
		return true, nil
	}

	user, err := m.store.GetUserByUserID(ctx, store.LockingStrengthNone, userID)
	if err != nil {
		return false, err
	}

	if user == nil {
		return false, status.NewUserNotFoundError(userID)
	}

	if user.IsBlocked() && !user.PendingApproval {
		return false, status.NewUserBlockedError()
	}

	if user.IsBlocked() && user.PendingApproval {
		return false, status.NewUserPendingApprovalError()
	}

	if err := m.ValidateAccountAccess(ctx, accountID, user, false); err != nil {
		return false, err
	}

	if operation == operations.Read && user.IsServiceUser {
		return true, nil // this should be replaced by proper granular access role
	}

	role, ok := roles.RolesMap[user.Role]
	if !ok {
		return false, status.NewUserRoleNotFoundError(string(user.Role))
	}

	return m.ValidateRoleModuleAccess(ctx, accountID, role, module, operation), nil
}

func (m *managerImpl) ValidateRoleModuleAccess(
	ctx context.Context,
	accountID string,
	role roles.RolePermissions,
	module modules.Module,
	operation operations.Operation,
) bool {
	if permissions, ok := role.Permissions[module]; ok {
		if allowed, exists := permissions[operation]; exists {
			return allowed
		}
		log.WithContext(ctx).Tracef("operation %s not found on module %s for role %s", operation, module, role.Role)
		return false
	}

	return role.AutoAllowNew[operation]
}

func (m *managerImpl) ValidateAccountAccess(ctx context.Context, accountID string, user *types.User, allowOwnerAndAdmin bool) error {
	if user.AccountID != accountID {
		return status.NewUserNotPartOfAccountError()
	}
	return nil
}

func (m *managerImpl) GetPermissionsByRole(ctx context.Context, role types.UserRole) (roles.Permissions, error) {
	roleMap, ok := roles.RolesMap[role]
	if !ok {
		return roles.Permissions{}, status.NewUserRoleNotFoundError(string(role))
	}

	permissions := roles.Permissions{}

	for k := range modules.All {
		if rolePermissions, ok := roleMap.Permissions[k]; ok {
			permissions[k] = rolePermissions
			continue
		}
		permissions[k] = roleMap.AutoAllowNew
	}

	return permissions, nil
}

func (m *managerImpl) SetAccountManager(accountManager account.Manager) {
	// no-op
}

// WrapHandler wraps a handler that expects UserAuth with context extraction.
// Unlike WithPermission, it does not perform any permission checks.
func WrapHandler(h func(w http.ResponseWriter, r *http.Request, userAuth *auth.UserAuth)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		userAuth, err := nbcontext.GetUserAuthFromContext(r.Context())
		if err != nil {
			log.WithContext(r.Context()).Errorf("failed to get user auth from context: %v", err)
			util.WriteError(r.Context(), err, w)
			return
		}
		h(w, r, &userAuth)
	}
}
