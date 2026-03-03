// Package dex provides an embedded Dex OIDC identity provider.
package dex

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/dexidp/dex/storage"
)

// ConnectorConfig represents the configuration for an identity provider connector
type ConnectorConfig struct {
	// ID is the unique identifier for the connector
	ID string
	// Name is a human-readable name for the connector
	Name string
	// Type is the connector type (oidc, google, microsoft)
	Type string
	// Issuer is the OIDC issuer URL (for OIDC-based connectors)
	Issuer string
	// ClientID is the OAuth2 client ID
	ClientID string
	// ClientSecret is the OAuth2 client secret
	ClientSecret string
	// RedirectURI is the OAuth2 redirect URI
	RedirectURI string
}

// CreateConnector creates a new connector in Dex storage.
// It maps the connector config to the appropriate Dex connector type and configuration.
func (p *Provider) CreateConnector(ctx context.Context, cfg *ConnectorConfig) (*ConnectorConfig, error) {
	// Fill in the redirect URI if not provided
	if cfg.RedirectURI == "" {
		cfg.RedirectURI = p.GetRedirectURI()
	}

	storageConn, err := p.buildStorageConnector(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to build connector: %w", err)
	}

	if err := p.storage.CreateConnector(ctx, storageConn); err != nil {
		return nil, fmt.Errorf("failed to create connector: %w", err)
	}

	p.logger.Info("connector created", "id", cfg.ID, "type", cfg.Type)
	return cfg, nil
}

// GetConnector retrieves a connector by ID from Dex storage.
func (p *Provider) GetConnector(ctx context.Context, id string) (*ConnectorConfig, error) {
	conn, err := p.storage.GetConnector(ctx, id)
	if err != nil {
		if err == storage.ErrNotFound {
			return nil, err
		}
		return nil, fmt.Errorf("failed to get connector: %w", err)
	}

	return p.parseStorageConnector(conn)
}

// ListConnectors returns all connectors from Dex storage (excluding the local connector).
func (p *Provider) ListConnectors(ctx context.Context) ([]*ConnectorConfig, error) {
	connectors, err := p.storage.ListConnectors(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to list connectors: %w", err)
	}

	result := make([]*ConnectorConfig, 0, len(connectors))
	for _, conn := range connectors {
		// Skip the local password connector
		if conn.ID == "local" && conn.Type == "local" {
			continue
		}

		cfg, err := p.parseStorageConnector(conn)
		if err != nil {
			p.logger.Warn("failed to parse connector", "id", conn.ID, "error", err)
			continue
		}
		result = append(result, cfg)
	}

	return result, nil
}

// UpdateConnector updates an existing connector in Dex storage.
// It merges incoming updates with existing values to prevent data loss on partial updates.
func (p *Provider) UpdateConnector(ctx context.Context, cfg *ConnectorConfig) error {
	if err := p.storage.UpdateConnector(ctx, cfg.ID, func(old storage.Connector) (storage.Connector, error) {
		oldCfg, err := p.parseStorageConnector(old)
		if err != nil {
			return storage.Connector{}, fmt.Errorf("failed to parse existing connector: %w", err)
		}

		mergeConnectorConfig(cfg, oldCfg)

		storageConn, err := p.buildStorageConnector(cfg)
		if err != nil {
			return storage.Connector{}, fmt.Errorf("failed to build connector: %w", err)
		}
		return storageConn, nil
	}); err != nil {
		return fmt.Errorf("failed to update connector: %w", err)
	}

	p.logger.Info("connector updated", "id", cfg.ID, "type", cfg.Type)
	return nil
}

// mergeConnectorConfig preserves existing values for empty fields in the update.
func mergeConnectorConfig(cfg, oldCfg *ConnectorConfig) {
	if cfg.ClientSecret == "" {
		cfg.ClientSecret = oldCfg.ClientSecret
	}
	if cfg.RedirectURI == "" {
		cfg.RedirectURI = oldCfg.RedirectURI
	}
	if cfg.Issuer == "" && cfg.Type == oldCfg.Type {
		cfg.Issuer = oldCfg.Issuer
	}
	if cfg.ClientID == "" {
		cfg.ClientID = oldCfg.ClientID
	}
	if cfg.Name == "" {
		cfg.Name = oldCfg.Name
	}
}

// DeleteConnector removes a connector from Dex storage.
func (p *Provider) DeleteConnector(ctx context.Context, id string) error {
	// Prevent deletion of the local connector
	if id == "local" {
		return fmt.Errorf("cannot delete the local password connector")
	}

	if err := p.storage.DeleteConnector(ctx, id); err != nil {
		return fmt.Errorf("failed to delete connector: %w", err)
	}

	p.logger.Info("connector deleted", "id", id)
	return nil
}

// GetRedirectURI returns the default redirect URI for connectors.
func (p *Provider) GetRedirectURI() string {
	if p.config == nil {
		return ""
	}
	issuer := strings.TrimSuffix(p.config.Issuer, "/")
	if !strings.HasSuffix(issuer, "/oauth2") {
		issuer += "/oauth2"
	}
	return issuer + "/callback"
}

// buildStorageConnector creates a storage.Connector from ConnectorConfig.
// It handles the type-specific configuration for each connector type.
func (p *Provider) buildStorageConnector(cfg *ConnectorConfig) (storage.Connector, error) {
	redirectURI := p.resolveRedirectURI(cfg.RedirectURI)

	var dexType string
	var configData []byte
	var err error

	switch cfg.Type {
	case "oidc", "zitadel", "entra", "okta", "pocketid", "authentik", "keycloak":
		dexType = "oidc"
		configData, err = buildOIDCConnectorConfig(cfg, redirectURI)
	case "google":
		dexType = "google"
		configData, err = buildOAuth2ConnectorConfig(cfg, redirectURI)
	case "microsoft":
		dexType = "microsoft"
		configData, err = buildOAuth2ConnectorConfig(cfg, redirectURI)
	default:
		return storage.Connector{}, fmt.Errorf("unsupported connector type: %s", cfg.Type)
	}
	if err != nil {
		return storage.Connector{}, err
	}

	return storage.Connector{ID: cfg.ID, Type: dexType, Name: cfg.Name, Config: configData}, nil
}

// resolveRedirectURI returns the redirect URI, using a default if not provided
func (p *Provider) resolveRedirectURI(redirectURI string) string {
	if redirectURI != "" || p.config == nil {
		return redirectURI
	}
	issuer := strings.TrimSuffix(p.config.Issuer, "/")
	if !strings.HasSuffix(issuer, "/oauth2") {
		issuer += "/oauth2"
	}
	return issuer + "/callback"
}

// buildOIDCConnectorConfig creates config for OIDC-based connectors
func buildOIDCConnectorConfig(cfg *ConnectorConfig, redirectURI string) ([]byte, error) {
	oidcConfig := map[string]interface{}{
		"issuer":               cfg.Issuer,
		"clientID":             cfg.ClientID,
		"clientSecret":         cfg.ClientSecret,
		"redirectURI":          redirectURI,
		"scopes":               []string{"openid", "profile", "email"},
		"insecureEnableGroups": true,
		//some providers don't return email verified, so we need to skip it if not present (e.g., Entra, Okta, Duo)
		"insecureSkipEmailVerified": true,
	}
	switch cfg.Type {
	case "zitadel":
		oidcConfig["getUserInfo"] = true
	case "entra":
		oidcConfig["claimMapping"] = map[string]string{"email": "preferred_username"}
	case "okta":
		oidcConfig["scopes"] = []string{"openid", "profile", "email", "groups"}
	case "pocketid":
		oidcConfig["scopes"] = []string{"openid", "profile", "email", "groups"}
	}
	return encodeConnectorConfig(oidcConfig)
}

// buildOAuth2ConnectorConfig creates config for OAuth2 connectors (google, microsoft)
func buildOAuth2ConnectorConfig(cfg *ConnectorConfig, redirectURI string) ([]byte, error) {
	return encodeConnectorConfig(map[string]interface{}{
		"clientID":     cfg.ClientID,
		"clientSecret": cfg.ClientSecret,
		"redirectURI":  redirectURI,
	})
}

// parseStorageConnector converts a storage.Connector back to ConnectorConfig.
// It infers the original identity provider type from the Dex connector type and ID.
func (p *Provider) parseStorageConnector(conn storage.Connector) (*ConnectorConfig, error) {
	cfg := &ConnectorConfig{
		ID:   conn.ID,
		Name: conn.Name,
	}

	if len(conn.Config) == 0 {
		cfg.Type = conn.Type
		return cfg, nil
	}

	var configMap map[string]interface{}
	if err := decodeConnectorConfig(conn.Config, &configMap); err != nil {
		return nil, fmt.Errorf("failed to parse connector config: %w", err)
	}

	// Extract common fields
	if v, ok := configMap["clientID"].(string); ok {
		cfg.ClientID = v
	}
	if v, ok := configMap["clientSecret"].(string); ok {
		cfg.ClientSecret = v
	}
	if v, ok := configMap["redirectURI"].(string); ok {
		cfg.RedirectURI = v
	}
	if v, ok := configMap["issuer"].(string); ok {
		cfg.Issuer = v
	}

	// Infer the original identity provider type from Dex connector type and ID
	cfg.Type = inferIdentityProviderType(conn.Type, conn.ID, configMap)

	return cfg, nil
}

// inferIdentityProviderType determines the original identity provider type
// based on the Dex connector type, connector ID, and configuration.
func inferIdentityProviderType(dexType, connectorID string, _ map[string]interface{}) string {
	if dexType != "oidc" {
		return dexType
	}
	return inferOIDCProviderType(connectorID)
}

// inferOIDCProviderType infers the specific OIDC provider from connector ID
func inferOIDCProviderType(connectorID string) string {
	connectorIDLower := strings.ToLower(connectorID)
	for _, provider := range []string{"pocketid", "zitadel", "entra", "okta", "authentik", "keycloak"} {
		if strings.Contains(connectorIDLower, provider) {
			return provider
		}
	}
	return "oidc"
}

// encodeConnectorConfig serializes connector config to JSON bytes.
func encodeConnectorConfig(config map[string]interface{}) ([]byte, error) {
	return json.Marshal(config)
}

// decodeConnectorConfig deserializes connector config from JSON bytes.
func decodeConnectorConfig(data []byte, v interface{}) error {
	return json.Unmarshal(data, v)
}

// ensureLocalConnector creates a local (password) connector if it doesn't exist
func ensureLocalConnector(ctx context.Context, stor storage.Storage) error {
	// Check specifically for the local connector
	_, err := stor.GetConnector(ctx, "local")
	if err == nil {
		// Local connector already exists
		return nil
	}
	if !errors.Is(err, storage.ErrNotFound) {
		return fmt.Errorf("failed to get local connector: %w", err)
	}

	// Create a local connector for password authentication
	localConnector := storage.Connector{
		ID:   "local",
		Type: "local",
		Name: "Email",
	}

	if err := stor.CreateConnector(ctx, localConnector); err != nil {
		return fmt.Errorf("failed to create local connector: %w", err)
	}

	return nil
}

// HasNonLocalConnectors checks if there are any connectors other than the local connector.
func (p *Provider) HasNonLocalConnectors(ctx context.Context) (bool, error) {
	connectors, err := p.storage.ListConnectors(ctx)
	if err != nil {
		return false, fmt.Errorf("failed to list connectors: %w", err)
	}

	p.logger.Info("checking for non-local connectors", "total_connectors", len(connectors))
	for _, conn := range connectors {
		p.logger.Info("found connector in storage", "id", conn.ID, "type", conn.Type, "name", conn.Name)
		if conn.ID != "local" || conn.Type != "local" {
			p.logger.Info("found non-local connector", "id", conn.ID)
			return true, nil
		}
	}
	p.logger.Info("no non-local connectors found")
	return false, nil
}

// DisableLocalAuth removes the local (password) connector.
// Returns an error if no other connectors are configured.
func (p *Provider) DisableLocalAuth(ctx context.Context) error {
	hasOthers, err := p.HasNonLocalConnectors(ctx)
	if err != nil {
		return err
	}
	if !hasOthers {
		return fmt.Errorf("cannot disable local authentication: no other identity providers configured")
	}

	// Check if local connector exists
	_, err = p.storage.GetConnector(ctx, "local")
	if errors.Is(err, storage.ErrNotFound) {
		// Already disabled
		return nil
	}
	if err != nil {
		return fmt.Errorf("failed to check local connector: %w", err)
	}

	// Delete the local connector
	if err := p.storage.DeleteConnector(ctx, "local"); err != nil {
		return fmt.Errorf("failed to delete local connector: %w", err)
	}

	p.logger.Info("local authentication disabled")
	return nil
}

// EnableLocalAuth creates the local (password) connector if it doesn't exist.
func (p *Provider) EnableLocalAuth(ctx context.Context) error {
	return ensureLocalConnector(ctx, p.storage)
}

// ensureStaticConnectors creates or updates static connectors in storage
func ensureStaticConnectors(ctx context.Context, stor storage.Storage, connectors []Connector) error {
	for _, conn := range connectors {
		storConn, err := conn.ToStorageConnector()
		if err != nil {
			return fmt.Errorf("failed to convert connector %s: %w", conn.ID, err)
		}
		_, err = stor.GetConnector(ctx, conn.ID)
		if err == storage.ErrNotFound {
			if err := stor.CreateConnector(ctx, storConn); err != nil {
				return fmt.Errorf("failed to create connector %s: %w", conn.ID, err)
			}
			continue
		}
		if err != nil {
			return fmt.Errorf("failed to get connector %s: %w", conn.ID, err)
		}
		if err := stor.UpdateConnector(ctx, conn.ID, func(old storage.Connector) (storage.Connector, error) {
			old.Name = storConn.Name
			old.Config = storConn.Config
			return old, nil
		}); err != nil {
			return fmt.Errorf("failed to update connector %s: %w", conn.ID, err)
		}
	}
	return nil
}
