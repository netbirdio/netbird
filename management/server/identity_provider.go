package server

import (
	"context"
	"errors"

	"github.com/dexidp/dex/storage"
	"github.com/rs/xid"
	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/idp/dex"
	"github.com/netbirdio/netbird/management/server/activity"
	"github.com/netbirdio/netbird/management/server/idp"
	"github.com/netbirdio/netbird/management/server/permissions/modules"
	"github.com/netbirdio/netbird/management/server/permissions/operations"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/shared/management/status"
)

// GetIdentityProviders returns all identity providers for an account
func (am *DefaultAccountManager) GetIdentityProviders(ctx context.Context, accountID, userID string) ([]*types.IdentityProvider, error) {
	ok, err := am.permissionsManager.ValidateUserPermissions(ctx, accountID, userID, modules.IdentityProviders, operations.Read)
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
	ok, err := am.permissionsManager.ValidateUserPermissions(ctx, accountID, userID, modules.IdentityProviders, operations.Read)
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
	ok, err := am.permissionsManager.ValidateUserPermissions(ctx, accountID, userID, modules.IdentityProviders, operations.Create)
	if err != nil {
		return nil, status.NewPermissionValidationError(err)
	}
	if !ok {
		return nil, status.NewPermissionDeniedError()
	}

	if err := idpConfig.Validate(); err != nil {
		return nil, status.Errorf(status.InvalidArgument, "%s", err.Error())
	}

	embeddedManager, ok := am.idpManager.(*idp.EmbeddedIdPManager)
	if !ok {
		return nil, status.Errorf(status.Internal, "identity provider management requires embedded IdP")
	}

	// Generate ID if not provided
	if idpConfig.ID == "" {
		idpConfig.ID = generateIdentityProviderID(idpConfig.Type)
	}
	idpConfig.AccountID = accountID

	connCfg := identityProviderToConnectorConfig(idpConfig)

	_, err = embeddedManager.CreateConnector(ctx, connCfg)
	if err != nil {
		return nil, status.Errorf(status.Internal, "failed to create identity provider: %v", err)
	}

	am.StoreEvent(ctx, userID, idpConfig.ID, accountID, activity.IdentityProviderCreated, idpConfig.EventMeta())

	return idpConfig, nil
}

// UpdateIdentityProvider updates an existing identity provider
func (am *DefaultAccountManager) UpdateIdentityProvider(ctx context.Context, accountID, idpID, userID string, idpConfig *types.IdentityProvider) (*types.IdentityProvider, error) {
	ok, err := am.permissionsManager.ValidateUserPermissions(ctx, accountID, userID, modules.IdentityProviders, operations.Update)
	if err != nil {
		return nil, status.NewPermissionValidationError(err)
	}
	if !ok {
		return nil, status.NewPermissionDeniedError()
	}

	if err := idpConfig.Validate(); err != nil {
		return nil, status.Errorf(status.InvalidArgument, "%s", err.Error())
	}

	embeddedManager, ok := am.idpManager.(*idp.EmbeddedIdPManager)
	if !ok {
		return nil, status.Errorf(status.Internal, "identity provider management requires embedded IdP")
	}

	idpConfig.ID = idpID
	idpConfig.AccountID = accountID

	connCfg := identityProviderToConnectorConfig(idpConfig)

	if err := embeddedManager.UpdateConnector(ctx, connCfg); err != nil {
		return nil, status.Errorf(status.Internal, "failed to update identity provider: %v", err)
	}

	am.StoreEvent(ctx, userID, idpConfig.ID, accountID, activity.IdentityProviderUpdated, idpConfig.EventMeta())

	return idpConfig, nil
}

// DeleteIdentityProvider deletes an identity provider
func (am *DefaultAccountManager) DeleteIdentityProvider(ctx context.Context, accountID, idpID, userID string) error {
	ok, err := am.permissionsManager.ValidateUserPermissions(ctx, accountID, userID, modules.IdentityProviders, operations.Delete)
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

	// Get the IDP info before deleting for the activity event
	conn, err := embeddedManager.GetConnector(ctx, idpID)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return status.Errorf(status.NotFound, "identity provider not found")
		}
		return status.Errorf(status.Internal, "failed to get identity provider: %v", err)
	}
	idpConfig := connectorConfigToIdentityProvider(conn, accountID)

	if err := embeddedManager.DeleteConnector(ctx, idpID); err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return status.Errorf(status.NotFound, "identity provider not found")
		}
		return status.Errorf(status.Internal, "failed to delete identity provider: %v", err)
	}

	am.StoreEvent(ctx, userID, idpID, accountID, activity.IdentityProviderDeleted, idpConfig.EventMeta())

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

// generateIdentityProviderID generates a unique ID for an identity provider.
// For specific provider types (okta, zitadel, entra, google, pocketid, microsoft),
// the ID is prefixed with the type name. Generic OIDC providers get no prefix.
func generateIdentityProviderID(idpType types.IdentityProviderType) string {
	id := xid.New().String()

	switch idpType {
	case types.IdentityProviderTypeOkta:
		return "okta-" + id
	case types.IdentityProviderTypeZitadel:
		return "zitadel-" + id
	case types.IdentityProviderTypeEntra:
		return "entra-" + id
	case types.IdentityProviderTypeGoogle:
		return "google-" + id
	case types.IdentityProviderTypePocketID:
		return "pocketid-" + id
	case types.IdentityProviderTypeMicrosoft:
		return "microsoft-" + id
	case types.IdentityProviderTypeAuthentik:
		return "authentik-" + id
	case types.IdentityProviderTypeKeycloak:
		return "keycloak-" + id
	default:
		// Generic OIDC - no prefix
		return id
	}
}
