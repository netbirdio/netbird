package server

import (
	"context"
	"errors"

	"github.com/dexidp/dex/storage"
	"github.com/rs/xid"
	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/idp/dex"
	"github.com/netbirdio/netbird/management/server/idp"
	"github.com/netbirdio/netbird/management/server/permissions/modules"
	"github.com/netbirdio/netbird/management/server/permissions/operations"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/shared/management/status"
)

// GetIdentityProviders returns all identity providers for an account
func (am *DefaultAccountManager) GetIdentityProviders(ctx context.Context, accountID, userID string) ([]*types.IdentityProvider, error) {
	ok, err := am.permissionsManager.ValidateUserPermissions(ctx, accountID, userID, modules.Settings, operations.Read)
	if err != nil {
		return nil, status.NewPermissionValidationError(err)
	}
	if !ok {
		return nil, status.NewPermissionDeniedError()
	}

	embeddedManager, ok := am.idpManager.(*idp.EmbeddedIdPManager)
	if !ok {
		log.Warn("identity provider management requires embedded IdP")
		return []*types.IdentityProvider{}, nil
	}

	connectors, err := embeddedManager.ListConnectors(ctx)
	if err != nil {
		return nil, status.Errorf(status.Internal, "failed to list identity providers: %v", err)
	}

	result := make([]*types.IdentityProvider, 0, len(connectors))
	for _, conn := range connectors {
		result = append(result, connectorConfigToIdentityProvider(conn, accountID))
	}

	return result, nil
}

// GetIdentityProvider returns a specific identity provider by ID
func (am *DefaultAccountManager) GetIdentityProvider(ctx context.Context, accountID, idpID, userID string) (*types.IdentityProvider, error) {
	ok, err := am.permissionsManager.ValidateUserPermissions(ctx, accountID, userID, modules.Settings, operations.Read)
	if err != nil {
		return nil, status.NewPermissionValidationError(err)
	}
	if !ok {
		return nil, status.NewPermissionDeniedError()
	}

	embeddedManager, ok := am.idpManager.(*idp.EmbeddedIdPManager)
	if !ok {
		return nil, status.Errorf(status.Internal, "identity provider management requires embedded IdP")
	}

	conn, err := embeddedManager.GetConnector(ctx, idpID)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return nil, status.Errorf(status.NotFound, "identity provider not found")
		}
		return nil, status.Errorf(status.Internal, "failed to get identity provider: %v", err)
	}

	return connectorConfigToIdentityProvider(conn, accountID), nil
}

// CreateIdentityProvider creates a new identity provider
func (am *DefaultAccountManager) CreateIdentityProvider(ctx context.Context, accountID, userID string, idpConfig *types.IdentityProvider) (*types.IdentityProvider, error) {
	ok, err := am.permissionsManager.ValidateUserPermissions(ctx, accountID, userID, modules.Settings, operations.Create)
	if err != nil {
		return nil, status.NewPermissionValidationError(err)
	}
	if !ok {
		return nil, status.NewPermissionDeniedError()
	}

	if err := validateIdentityProvider(idpConfig); err != nil {
		return nil, err
	}

	embeddedManager, ok := am.idpManager.(*idp.EmbeddedIdPManager)
	if !ok {
		return nil, status.Errorf(status.Internal, "identity provider management requires embedded IdP")
	}

	// Generate ID if not provided
	if idpConfig.ID == "" {
		idpConfig.ID = xid.New().String()
	}
	idpConfig.AccountID = accountID

	connCfg := identityProviderToConnectorConfig(idpConfig)

	if err := embeddedManager.CreateConnector(ctx, connCfg); err != nil {
		return nil, status.Errorf(status.Internal, "failed to create identity provider: %v", err)
	}

	return idpConfig, nil
}

// UpdateIdentityProvider updates an existing identity provider
func (am *DefaultAccountManager) UpdateIdentityProvider(ctx context.Context, accountID, idpID, userID string, idpConfig *types.IdentityProvider) (*types.IdentityProvider, error) {
	ok, err := am.permissionsManager.ValidateUserPermissions(ctx, accountID, userID, modules.Settings, operations.Update)
	if err != nil {
		return nil, status.NewPermissionValidationError(err)
	}
	if !ok {
		return nil, status.NewPermissionDeniedError()
	}

	if err := validateIdentityProvider(idpConfig); err != nil {
		return nil, err
	}

	embeddedManager, ok := am.idpManager.(*idp.EmbeddedIdPManager)
	if !ok {
		return nil, status.Errorf(status.Internal, "identity provider management requires embedded IdP")
	}

	// Verify the connector exists
	_, err = embeddedManager.GetConnector(ctx, idpID)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return nil, status.Errorf(status.NotFound, "identity provider not found")
		}
		return nil, status.Errorf(status.Internal, "failed to get identity provider: %v", err)
	}

	idpConfig.ID = idpID
	idpConfig.AccountID = accountID

	connCfg := identityProviderToConnectorConfig(idpConfig)

	if err := embeddedManager.UpdateConnector(ctx, connCfg); err != nil {
		return nil, status.Errorf(status.Internal, "failed to update identity provider: %v", err)
	}

	return idpConfig, nil
}

// DeleteIdentityProvider deletes an identity provider
func (am *DefaultAccountManager) DeleteIdentityProvider(ctx context.Context, accountID, idpID, userID string) error {
	ok, err := am.permissionsManager.ValidateUserPermissions(ctx, accountID, userID, modules.Settings, operations.Delete)
	if err != nil {
		return status.NewPermissionValidationError(err)
	}
	if !ok {
		return status.NewPermissionDeniedError()
	}

	embeddedManager, ok := am.idpManager.(*idp.EmbeddedIdPManager)
	if !ok {
		return status.Errorf(status.Internal, "identity provider management requires embedded IdP")
	}

	if err := embeddedManager.DeleteConnector(ctx, idpID); err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return status.Errorf(status.NotFound, "identity provider not found")
		}
		return status.Errorf(status.Internal, "failed to delete identity provider: %v", err)
	}

	return nil
}

func validateIdentityProvider(idpConfig *types.IdentityProvider) error {
	if idpConfig.Name == "" {
		return status.Errorf(status.InvalidArgument, "identity provider name is required")
	}
	if idpConfig.Type == "" {
		return status.Errorf(status.InvalidArgument, "identity provider type is required")
	}
	// Validate type is supported
	switch idpConfig.Type {
	case types.IdentityProviderTypeOIDC,
		types.IdentityProviderTypeZitadel,
		types.IdentityProviderTypeEntra,
		types.IdentityProviderTypeGoogle,
		types.IdentityProviderTypeOkta,
		types.IdentityProviderTypePocketID,
		types.IdentityProviderTypeMicrosoft:
		// Valid types
	default:
		return status.Errorf(status.InvalidArgument, "unsupported identity provider type: %s", idpConfig.Type)
	}
	// Issuer is required for OIDC-based types
	if idpConfig.Type != types.IdentityProviderTypeGoogle && idpConfig.Type != types.IdentityProviderTypeMicrosoft {
		if idpConfig.Issuer == "" {
			return status.Errorf(status.InvalidArgument, "identity provider issuer is required")
		}
	}
	if idpConfig.ClientID == "" {
		return status.Errorf(status.InvalidArgument, "identity provider client ID is required")
	}
	return nil
}

// connectorConfigToIdentityProvider converts a dex.ConnectorConfig to types.IdentityProvider
func connectorConfigToIdentityProvider(conn *dex.ConnectorConfig, accountID string) *types.IdentityProvider {
	return &types.IdentityProvider{
		ID:           conn.ID,
		AccountID:    accountID,
		Type:         types.IdentityProviderType(conn.Type),
		Name:         conn.Name,
		Issuer:       conn.Issuer,
		ClientID:     conn.ClientID,
		ClientSecret: conn.ClientSecret,
	}
}

// identityProviderToConnectorConfig converts a types.IdentityProvider to dex.ConnectorConfig
func identityProviderToConnectorConfig(idpConfig *types.IdentityProvider) *dex.ConnectorConfig {
	return &dex.ConnectorConfig{
		ID:           idpConfig.ID,
		Name:         idpConfig.Name,
		Type:         string(idpConfig.Type),
		Issuer:       idpConfig.Issuer,
		ClientID:     idpConfig.ClientID,
		ClientSecret: idpConfig.ClientSecret,
	}
}
