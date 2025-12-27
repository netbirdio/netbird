package server

import (
	"context"

	"github.com/netbirdio/netbird/management/server/permissions/modules"
	"github.com/netbirdio/netbird/management/server/permissions/operations"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/shared/management/status"
)

// GetIdentityProviders returns all identity providers for an account
// TODO: Implement with Dex integration
func (am *DefaultAccountManager) GetIdentityProviders(ctx context.Context, accountID, userID string) ([]*types.IdentityProvider, error) {
	ok, err := am.permissionsManager.ValidateUserPermissions(ctx, accountID, userID, modules.Settings, operations.Read)
	if err != nil {
		return nil, status.NewPermissionValidationError(err)
	}
	if !ok {
		return nil, status.NewPermissionDeniedError()
	}

	// TODO: Replace with Dex integration
	return []*types.IdentityProvider{}, nil
}

// GetIdentityProvider returns a specific identity provider by ID
// TODO: Implement with Dex integration
func (am *DefaultAccountManager) GetIdentityProvider(ctx context.Context, accountID, idpID, userID string) (*types.IdentityProvider, error) {
	ok, err := am.permissionsManager.ValidateUserPermissions(ctx, accountID, userID, modules.Settings, operations.Read)
	if err != nil {
		return nil, status.NewPermissionValidationError(err)
	}
	if !ok {
		return nil, status.NewPermissionDeniedError()
	}

	// TODO: Replace with Dex integration
	return nil, status.Errorf(status.NotFound, "identity provider not found")
}

// CreateIdentityProvider creates a new identity provider
// TODO: Implement with Dex integration
func (am *DefaultAccountManager) CreateIdentityProvider(ctx context.Context, accountID, userID string, idp *types.IdentityProvider) (*types.IdentityProvider, error) {
	ok, err := am.permissionsManager.ValidateUserPermissions(ctx, accountID, userID, modules.Settings, operations.Create)
	if err != nil {
		return nil, status.NewPermissionValidationError(err)
	}
	if !ok {
		return nil, status.NewPermissionDeniedError()
	}

	if err := validateIdentityProvider(idp); err != nil {
		return nil, err
	}

	// TODO: Replace with Dex integration
	return nil, status.Errorf(status.Internal, "identity provider creation not yet implemented")
}

// UpdateIdentityProvider updates an existing identity provider
// TODO: Implement with Dex integration
func (am *DefaultAccountManager) UpdateIdentityProvider(ctx context.Context, accountID, idpID, userID string, idp *types.IdentityProvider) (*types.IdentityProvider, error) {
	ok, err := am.permissionsManager.ValidateUserPermissions(ctx, accountID, userID, modules.Settings, operations.Update)
	if err != nil {
		return nil, status.NewPermissionValidationError(err)
	}
	if !ok {
		return nil, status.NewPermissionDeniedError()
	}

	if err := validateIdentityProvider(idp); err != nil {
		return nil, err
	}

	// TODO: Replace with Dex integration
	return nil, status.Errorf(status.Internal, "identity provider update not yet implemented")
}

// DeleteIdentityProvider deletes an identity provider
// TODO: Implement with Dex integration
func (am *DefaultAccountManager) DeleteIdentityProvider(ctx context.Context, accountID, idpID, userID string) error {
	ok, err := am.permissionsManager.ValidateUserPermissions(ctx, accountID, userID, modules.Settings, operations.Delete)
	if err != nil {
		return status.NewPermissionValidationError(err)
	}
	if !ok {
		return status.NewPermissionDeniedError()
	}

	// TODO: Replace with Dex integration
	return status.Errorf(status.Internal, "identity provider deletion not yet implemented")
}

func validateIdentityProvider(idp *types.IdentityProvider) error {
	if idp.Name == "" {
		return status.Errorf(status.InvalidArgument, "identity provider name is required")
	}
	if idp.Type == "" {
		return status.Errorf(status.InvalidArgument, "identity provider type is required")
	}
	if idp.Issuer == "" {
		return status.Errorf(status.InvalidArgument, "identity provider issuer is required")
	}
	if idp.ClientID == "" {
		return status.Errorf(status.InvalidArgument, "identity provider client ID is required")
	}
	return nil
}
