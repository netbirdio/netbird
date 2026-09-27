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

// ErrIncompatibleClaimMapping prevents a groups mapping from changing the
// precedence of an existing claim mapping in Dex.
var ErrIncompatibleClaimMapping = errors.New("cannot enable groups claim override with an existing claim mapping")

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
	// AdditionalScopes and GroupsClaim apply only to generic OIDC connectors.
	// Nil values leave existing settings unchanged on update.
	AdditionalScopes []string
	GroupsClaim      *string
	GetUserInfo      *bool
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
// It overlays user-mutable config fields (issuer, clientID, clientSecret,
// redirectURI) onto the stored connector config, and updates the connector name
// when cfg.Name is set. Empty fields on cfg leave stored values unchanged, so
// partial updates preserve create-time defaults such as scopes, claimMapping,
// and userIDKey.
func (p *Provider) UpdateConnector(ctx context.Context, cfg *ConnectorConfig) error {
	if err := p.storage.UpdateConnector(ctx, cfg.ID, func(old storage.Connector) (storage.Connector, error) {
		providerType := inferIdentityProviderType(old.Type, cfg.ID, nil)
		if cfg.Type != "" && cfg.Type != providerType {
			return storage.Connector{}, errors.New("connector type change not allowed")
		}
		if providerType != "oidc" && (len(cfg.AdditionalScopes) > 0 || (cfg.GroupsClaim != nil && *cfg.GroupsClaim != "") || (cfg.GetUserInfo != nil && *cfg.GetUserInfo)) {
			return storage.Connector{}, errors.New("custom OIDC options require a generic OIDC connector")
		}

		configData, err := overlayConnectorConfig(old.Config, cfg, providerType)
		if err != nil {
			return storage.Connector{}, fmt.Errorf("failed to overlay connector config: %w", err)
		}

		name := cfg.Name
		if name == "" {
			name = old.Name
		}

		return storage.Connector{
			ID:     cfg.ID,
			Type:   old.Type,
			Name:   name,
			Config: configData,
		}, nil
	}); err != nil {
		return fmt.Errorf("failed to update connector: %w", err)
	}

	p.logger.Info("connector updated", "id", cfg.ID, "type", cfg.Type)
	return nil
}

// overlayConnectorConfig writes only the user-mutable fields onto the existing
// stored config, preserving every other field (scopes, claimMapping, userIDKey,
// insecure flags, etc.). Empty fields on cfg leave the existing value alone.
func overlayConnectorConfig(oldConfig []byte, cfg *ConnectorConfig, providerType string) ([]byte, error) {
	var m map[string]any
	if err := decodeConnectorConfig(oldConfig, &m); err != nil {
		return nil, err
	}
	if cfg.Issuer != "" {
		m["issuer"] = cfg.Issuer
	}
	if cfg.ClientID != "" {
		m["clientID"] = cfg.ClientID
	}
	if cfg.ClientSecret != "" {
		m["clientSecret"] = cfg.ClientSecret
	}
	if cfg.RedirectURI != "" {
		m["redirectURI"] = cfg.RedirectURI
	}
	if providerType == "oidc" && cfg.AdditionalScopes != nil {
		m["scopes"] = oidcScopes(cfg.AdditionalScopes)
	}
	if providerType == "oidc" && cfg.GetUserInfo != nil {
		m["getUserInfo"] = *cfg.GetUserInfo
	}
	if providerType == "oidc" && cfg.GroupsClaim != nil {
		mapping, _ := m["claimMapping"].(map[string]any)
		if mapping == nil {
			mapping = make(map[string]any)
		}
		if *cfg.GroupsClaim == "" {
			delete(mapping, "groups")
		} else {
			if override, _ := m["overrideClaimMapping"].(bool); !override {
				for key := range mapping {
					if key != "groups" {
						return nil, fmt.Errorf("%w: %q", ErrIncompatibleClaimMapping, key)
					}
				}
			}
			mapping["groups"] = *cfg.GroupsClaim
			// Dex otherwise prefers a standard groups claim over the configured one.
			m["overrideClaimMapping"] = true
		}
		if len(mapping) == 0 {
			delete(m, "claimMapping")
			delete(m, "overrideClaimMapping")
		} else {
			m["claimMapping"] = mapping
		}
	}
	return encodeConnectorConfig(m)
}

func oidcScopes(additional []string) []string {
	scopes := []string{"openid", "profile", "email"}
	seen := map[string]bool{"openid": true, "profile": true, "email": true}
	for _, scope := range additional {
		if !seen[scope] {
			scopes = append(scopes, scope)
			seen[scope] = true
		}
	}
	return scopes
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
	if cfg.Type != "oidc" && (len(cfg.AdditionalScopes) > 0 || (cfg.GroupsClaim != nil && *cfg.GroupsClaim != "") || (cfg.GetUserInfo != nil && *cfg.GetUserInfo)) {
		return storage.Connector{}, errors.New("custom OIDC options require a generic OIDC connector")
	}
	redirectURI := p.resolveRedirectURI(cfg.RedirectURI)

	var dexType string
	var configData []byte
	var err error

	switch cfg.Type {
	case "oidc", "zitadel", "entra", "okta", "pocketid", "authentik", "keycloak", "adfs":
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
	case "oidc":
		oidcConfig["scopes"] = oidcScopes(cfg.AdditionalScopes)
		if cfg.GetUserInfo != nil {
			oidcConfig["getUserInfo"] = *cfg.GetUserInfo
		}
		if cfg.GroupsClaim != nil && *cfg.GroupsClaim != "" {
			oidcConfig["claimMapping"] = map[string]string{"groups": *cfg.GroupsClaim}
			// Honor the explicit mapping even if the upstream also sends groups.
			oidcConfig["overrideClaimMapping"] = true
		}
	case "zitadel":
		oidcConfig["getUserInfo"] = true
	case "entra":
		oidcConfig["claimMapping"] = map[string]string{"email": "preferred_username"}
		// Use the Entra Object ID (oid) instead of the default OIDC sub claim.
		// Entra issues sub as a per-app pairwise identifier that does not match
		// the stable Object ID.
		oidcConfig["userIDKey"] = "oid"
	case "okta":
		oidcConfig["scopes"] = []string{"openid", "profile", "email", "groups"}
	case "pocketid":
		oidcConfig["scopes"] = []string{"openid", "profile", "email", "groups"}
	case "adfs":
		oidcConfig["scopes"] = []string{"openid", "profile", "email", "allatclaims"}
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
	if cfg.Type == "oidc" {
		if getUserInfo, ok := configMap["getUserInfo"].(bool); ok {
			cfg.GetUserInfo = &getUserInfo
		}
		if scopes, ok := configMap["scopes"].([]any); ok {
			for _, scope := range scopes {
				name, ok := scope.(string)
				if ok && name != "openid" && name != "profile" && name != "email" {
					cfg.AdditionalScopes = append(cfg.AdditionalScopes, name)
				}
			}
		}
		if mapping, ok := configMap["claimMapping"].(map[string]any); ok {
			if claim, ok := mapping["groups"].(string); ok {
				cfg.GroupsClaim = &claim
			}
		}
	}

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
	for _, provider := range []string{"pocketid", "zitadel", "entra", "okta", "authentik", "keycloak", "adfs"} {
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
