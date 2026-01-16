package manager

import (
	"context"
	"fmt"

	"github.com/netbirdio/netbird/management/internals/modules/services"
	"github.com/netbirdio/netbird/management/server/account"
	"github.com/netbirdio/netbird/management/server/activity"
	"github.com/netbirdio/netbird/management/server/permissions"
	"github.com/netbirdio/netbird/management/server/permissions/modules"
	"github.com/netbirdio/netbird/management/server/permissions/operations"
	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/shared/management/status"
)

type managerImpl struct {
	store              store.Store
	accountManager     account.Manager
	permissionsManager permissions.Manager
}

func NewManager(store store.Store, accountManager account.Manager, permissionsManager permissions.Manager) services.Manager {
	return &managerImpl{
		store:              store,
		accountManager:     accountManager,
		permissionsManager: permissionsManager,
	}
}

func (m *managerImpl) GetAllServices(ctx context.Context, accountID, userID string) ([]*services.Service, error) {
	ok, err := m.permissionsManager.ValidateUserPermissions(ctx, accountID, userID, modules.Services, operations.Read)
	if err != nil {
		return nil, status.NewPermissionValidationError(err)
	}
	if !ok {
		return nil, status.NewPermissionDeniedError()
	}

	return m.store.GetAccountServices(ctx, store.LockingStrengthNone, accountID)
}

func (m *managerImpl) GetService(ctx context.Context, accountID, userID, serviceID string) (*services.Service, error) {
	ok, err := m.permissionsManager.ValidateUserPermissions(ctx, accountID, userID, modules.Services, operations.Read)
	if err != nil {
		return nil, status.NewPermissionValidationError(err)
	}
	if !ok {
		return nil, status.NewPermissionDeniedError()
	}

	return m.store.GetServiceByID(ctx, store.LockingStrengthNone, accountID, serviceID)
}

func (m *managerImpl) CreateService(ctx context.Context, accountID, userID string, service *services.Service) (*services.Service, error) {
	ok, err := m.permissionsManager.ValidateUserPermissions(ctx, accountID, userID, modules.Services, operations.Create)
	if err != nil {
		return nil, status.NewPermissionValidationError(err)
	}
	if !ok {
		return nil, status.NewPermissionDeniedError()
	}

	// Store auth config before creating new service
	authType := service.AuthType
	authBasicUsername := service.AuthBasicUsername
	authBasicPassword := service.AuthBasicPassword
	authPINValue := service.AuthPINValue
	authPINHeader := service.AuthPINHeader
	authBearerEnabled := service.AuthBearerEnabled

	service = services.NewService(accountID, service.Name, service.Description, service.Domain, service.Targets, service.DistributionGroups, service.Enabled, service.Exposed)

	// Restore auth config
	service.AuthType = authType
	service.AuthBasicUsername = authBasicUsername
	service.AuthBasicPassword = authBasicPassword
	service.AuthPINValue = authPINValue
	service.AuthPINHeader = authPINHeader
	service.AuthBearerEnabled = authBearerEnabled

	err = m.store.ExecuteInTransaction(ctx, func(transaction store.Store) error {
		// Check for duplicate domain
		existingService, err := transaction.GetServiceByDomain(ctx, accountID, service.Domain)
		if err != nil {
			if sErr, ok := status.FromError(err); !ok || sErr.Type() != status.NotFound {
				return fmt.Errorf("failed to check existing service: %w", err)
			}
		}
		if existingService != nil {
			return status.Errorf(status.AlreadyExists, "service with domain %s already exists", service.Domain)
		}

		// Validate distribution groups exist
		for _, groupID := range service.DistributionGroups {
			_, err = transaction.GetGroupByID(ctx, store.LockingStrengthNone, accountID, groupID)
			if err != nil {
				return status.Errorf(status.InvalidArgument, "%s", err.Error())
			}
		}

		if err = transaction.CreateService(ctx, service); err != nil {
			return fmt.Errorf("failed to create service: %w", err)
		}

		return nil
	})
	if err != nil {
		return nil, err
	}

	m.accountManager.StoreEvent(ctx, userID, service.ID, accountID, activity.ServiceCreated, service.EventMeta())

	return service, nil
}

func (m *managerImpl) UpdateService(ctx context.Context, accountID, userID string, service *services.Service) (*services.Service, error) {
	ok, err := m.permissionsManager.ValidateUserPermissions(ctx, accountID, userID, modules.Services, operations.Update)
	if err != nil {
		return nil, status.NewPermissionValidationError(err)
	}
	if !ok {
		return nil, status.NewPermissionDeniedError()
	}

	err = m.store.ExecuteInTransaction(ctx, func(transaction store.Store) error {
		// Get existing service
		existingService, err := transaction.GetServiceByID(ctx, store.LockingStrengthUpdate, accountID, service.ID)
		if err != nil {
			return err
		}

		// Check if domain changed and if it conflicts
		if existingService.Domain != service.Domain {
			conflictService, err := transaction.GetServiceByDomain(ctx, accountID, service.Domain)
			if err != nil {
				if sErr, ok := status.FromError(err); !ok || sErr.Type() != status.NotFound {
					return fmt.Errorf("failed to check existing service: %w", err)
				}
			}
			if conflictService != nil && conflictService.ID != service.ID {
				return status.Errorf(status.AlreadyExists, "service with domain %s already exists", service.Domain)
			}
		}

		// Validate distribution groups exist
		for _, groupID := range service.DistributionGroups {
			_, err = transaction.GetGroupByID(ctx, store.LockingStrengthNone, accountID, groupID)
			if err != nil {
				return status.Errorf(status.InvalidArgument, "%s", err.Error())
			}
		}

		if err = transaction.UpdateService(ctx, service); err != nil {
			return fmt.Errorf("failed to update service: %w", err)
		}

		return nil
	})
	if err != nil {
		return nil, err
	}

	m.accountManager.StoreEvent(ctx, userID, service.ID, accountID, activity.ServiceUpdated, service.EventMeta())

	return service, nil
}

func (m *managerImpl) DeleteService(ctx context.Context, accountID, userID, serviceID string) error {
	ok, err := m.permissionsManager.ValidateUserPermissions(ctx, accountID, userID, modules.Services, operations.Delete)
	if err != nil {
		return status.NewPermissionValidationError(err)
	}
	if !ok {
		return status.NewPermissionDeniedError()
	}

	var service *services.Service
	err = m.store.ExecuteInTransaction(ctx, func(transaction store.Store) error {
		var err error
		service, err = transaction.GetServiceByID(ctx, store.LockingStrengthUpdate, accountID, serviceID)
		if err != nil {
			return err
		}

		if err = transaction.DeleteService(ctx, accountID, serviceID); err != nil {
			return fmt.Errorf("failed to delete service: %w", err)
		}

		return nil
	})
	if err != nil {
		return err
	}

	m.accountManager.StoreEvent(ctx, userID, serviceID, accountID, activity.ServiceDeleted, service.EventMeta())

	return nil
}
