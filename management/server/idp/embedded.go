package idp

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/dexidp/dex/storage"
	"github.com/google/uuid"
	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/idp/dex"
	"github.com/netbirdio/netbird/management/server/telemetry"
)

const (
	staticClientDashboard  = "netbird-dashboard"
	staticClientCLI        = "netbird-cli"
	defaultCLIRedirectURL1 = "http://localhost:53000/"
	defaultCLIRedirectURL2 = "http://localhost:54000/"
	defaultScopes          = "openid profile email groups"
	defaultUserIDClaim     = "sub"
)

// EmbeddedIdPConfig contains configuration for the embedded Dex OIDC identity provider
type EmbeddedIdPConfig struct {
	// Enabled indicates whether the embedded IDP is enabled
	Enabled bool
	// Issuer is the OIDC issuer URL (e.g., "https://management.netbird.io/oauth2")
	Issuer string
	// LocalAddress is the management server's local listen address (e.g., ":8080" or "localhost:8080")
	// Used for internal JWT validation to avoid external network calls
	LocalAddress string
	// Storage configuration for the IdP database
	Storage EmbeddedStorageConfig
	// DashboardRedirectURIs are the OAuth2 redirect URIs for the dashboard client
	DashboardRedirectURIs []string
	// DashboardRedirectURIs are the OAuth2 redirect URIs for the dashboard client
	CLIRedirectURIs []string
	// Owner is the initial owner/admin user (optional, can be nil)
	Owner *OwnerConfig
	// SignKeyRefreshEnabled enables automatic key rotation for signing keys
	SignKeyRefreshEnabled bool
	// LocalAuthDisabled disables the local (email/password) authentication connector.
	// When true, users cannot authenticate via email/password, only via external identity providers.
	// Existing local users are preserved and will be able to login again if re-enabled.
	// Cannot be enabled if no external identity provider connectors are configured.
	LocalAuthDisabled bool
}

// EmbeddedStorageConfig holds storage configuration for the embedded IdP.
type EmbeddedStorageConfig struct {
	// Type is the storage type: "sqlite3" (default) or "postgres"
	Type string
	// Config contains type-specific configuration
	Config EmbeddedStorageTypeConfig
}

// EmbeddedStorageTypeConfig contains type-specific storage configuration.
type EmbeddedStorageTypeConfig struct {
	// File is the path to the SQLite database file (for sqlite3 type)
	File string
	// DSN is the connection string for postgres
	DSN string
}

// OwnerConfig represents the initial owner/admin user for the embedded IdP.
type OwnerConfig struct {
	// Email is the user's email address (required)
	Email string
	// Hash is the bcrypt hash of the user's password (required)
	Hash string
	// Username is the display name for the user (optional, defaults to email)
	Username string
}

// buildIdpStorageConfig builds the Dex storage config map based on the storage type.
func buildIdpStorageConfig(storageType string, cfg EmbeddedStorageTypeConfig) (map[string]interface{}, error) {
	switch storageType {
	case "sqlite3":
		return map[string]interface{}{
			"file": cfg.File,
		}, nil
	case "postgres":
		return map[string]interface{}{
			"dsn": cfg.DSN,
		}, nil
	default:
		return nil, fmt.Errorf("unsupported IdP storage type: %s", storageType)
	}
}

// ToYAMLConfig converts EmbeddedIdPConfig to dex.YAMLConfig.
func (c *EmbeddedIdPConfig) ToYAMLConfig() (*dex.YAMLConfig, error) {
	if c.Issuer == "" {
		return nil, fmt.Errorf("issuer is required")
	}
	if c.Storage.Type == "" {
		c.Storage.Type = "sqlite3"
	}
	if c.Storage.Type == "sqlite3" && c.Storage.Config.File == "" {
		return nil, fmt.Errorf("storage file is required for sqlite3")
	}
	if c.Storage.Type == "postgres" && c.Storage.Config.DSN == "" {
		return nil, fmt.Errorf("storage DSN is required for postgres")
	}

	storageConfig, err := buildIdpStorageConfig(c.Storage.Type, c.Storage.Config)
	if err != nil {
		return nil, fmt.Errorf("invalid IdP storage config: %w", err)
	}

	// Build CLI redirect URIs including the device callback (both relative and absolute)
	cliRedirectURIs := c.CLIRedirectURIs
	cliRedirectURIs = append(cliRedirectURIs, "/device/callback")
	cliRedirectURIs = append(cliRedirectURIs, c.Issuer+"/device/callback")

	// Build dashboard redirect URIs including the OAuth callback for proxy authentication
	dashboardRedirectURIs := c.DashboardRedirectURIs
	baseURL := strings.TrimSuffix(c.Issuer, "/oauth2")
	// todo: resolve import cycle
	dashboardRedirectURIs = append(dashboardRedirectURIs, baseURL+"/api/reverse-proxy/callback")

	cfg := &dex.YAMLConfig{
		Issuer: c.Issuer,
		Storage: dex.Storage{
			Type:   c.Storage.Type,
			Config: storageConfig,
		},
		Web: dex.Web{
			AllowedOrigins: []string{"*"},
			AllowedHeaders: []string{"Authorization", "Content-Type"},
		},
		OAuth2: dex.OAuth2{
			SkipApprovalScreen: true,
		},
		Frontend: dex.Frontend{
			Issuer: "NetBird",
			Theme:  "light",
		},
		// Always enable password DB initially - we disable the local connector after startup if needed.
		// This ensures Dex has at least one connector during initialization.
		EnablePasswordDB: true,
		StaticClients: []storage.Client{
			{
				ID:           staticClientDashboard,
				Name:         "NetBird Dashboard",
				Public:       true,
				RedirectURIs: dashboardRedirectURIs,
			},
			{
				ID:           staticClientCLI,
				Name:         "NetBird CLI",
				Public:       true,
				RedirectURIs: cliRedirectURIs,
			},
		},
	}

	// Add owner user if provided
	if c.Owner != nil && c.Owner.Email != "" && c.Owner.Hash != "" {
		username := c.Owner.Username
		if username == "" {
			username = c.Owner.Email
		}
		cfg.StaticPasswords = []dex.Password{
			{
				Email:    c.Owner.Email,
				Hash:     []byte(c.Owner.Hash),
				Username: username,
				UserID:   uuid.New().String(),
			},
		}
	}

	return cfg, nil
}

// Compile-time check that EmbeddedIdPManager implements Manager interface
var _ Manager = (*EmbeddedIdPManager)(nil)

// Compile-time check that EmbeddedIdPManager implements OAuthConfigProvider interface
var _ OAuthConfigProvider = (*EmbeddedIdPManager)(nil)

// OAuthConfigProvider defines the interface for OAuth configuration needed by auth flows.
type OAuthConfigProvider interface {
	GetIssuer() string
	// GetKeysLocation returns the public JWKS endpoint URL (uses external issuer URL)
	GetKeysLocation() string
	// GetLocalKeysLocation returns the localhost JWKS endpoint URL for internal use.
	// Management server has embedded Dex and can validate tokens via localhost,
	// avoiding external network calls and DNS resolution issues during startup.
	GetLocalKeysLocation() string
	GetClientIDs() []string
	GetUserIDClaim() string
	GetTokenEndpoint() string
	GetDeviceAuthEndpoint() string
	GetAuthorizationEndpoint() string
	GetDefaultScopes() string
	GetCLIClientID() string
	GetCLIRedirectURLs() []string
}

// EmbeddedIdPManager implements the Manager interface using the embedded Dex IdP.
type EmbeddedIdPManager struct {
	provider   *dex.Provider
	appMetrics telemetry.AppMetrics
	config     EmbeddedIdPConfig
}

// NewEmbeddedIdPManager creates a new instance of EmbeddedIdPManager from a configuration.
// It instantiates the underlying Dex provider internally.
// Note: Storage defaults are applied in config loading (applyEmbeddedIdPConfig) based on Datadir.
func NewEmbeddedIdPManager(ctx context.Context, config *EmbeddedIdPConfig, appMetrics telemetry.AppMetrics) (*EmbeddedIdPManager, error) {
	if config == nil {
		return nil, fmt.Errorf("embedded IdP config is required")
	}

	// Apply defaults for CLI redirect URIs
	if len(config.CLIRedirectURIs) == 0 {
		config.CLIRedirectURIs = []string{defaultCLIRedirectURL1, defaultCLIRedirectURL2}
	}

	// there are some properties create when creating YAML config (e.g., auth clients)
	yamlConfig, err := config.ToYAMLConfig()
	if err != nil {
		return nil, err
	}

	log.WithContext(ctx).Debugf("initializing embedded Dex IDP with config: %+v", config)

	provider, err := dex.NewProviderFromYAML(ctx, yamlConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create embedded IdP provider: %w", err)
	}

	// If local auth is disabled, validate that other connectors exist
	if config.LocalAuthDisabled {
		hasOthers, err := provider.HasNonLocalConnectors(ctx)
		if err != nil {
			_ = provider.Stop(ctx)
			return nil, fmt.Errorf("failed to check connectors: %w", err)
		}
		if !hasOthers {
			_ = provider.Stop(ctx)
			return nil, fmt.Errorf("cannot disable local authentication: no other identity providers configured")
		}
		// Ensure local connector is removed (it might exist from a previous run)
		if err := provider.DisableLocalAuth(ctx); err != nil {
			_ = provider.Stop(ctx)
			return nil, fmt.Errorf("failed to disable local auth: %w", err)
		}
		log.WithContext(ctx).Info("local authentication disabled - only external identity providers can be used")
	}

	log.WithContext(ctx).Infof("embedded Dex IDP initialized with issuer: %s", yamlConfig.Issuer)

	return &EmbeddedIdPManager{
		provider:   provider,
		appMetrics: appMetrics,
		config:     *config,
	}, nil
}

// Handler returns the HTTP handler for serving OIDC requests.
func (m *EmbeddedIdPManager) Handler() http.Handler {
	return m.provider.Handler()
}

// Stop gracefully shuts down the embedded IdP provider.
func (m *EmbeddedIdPManager) Stop(ctx context.Context) error {
	return m.provider.Stop(ctx)
}

// UpdateUserAppMetadata updates user app metadata based on userID and metadata map.
func (m *EmbeddedIdPManager) UpdateUserAppMetadata(ctx context.Context, userID string, appMetadata AppMetadata) error {
	// TODO: implement
	return nil
}

// GetUserDataByID requests user data from the embedded IdP via user ID.
func (m *EmbeddedIdPManager) GetUserDataByID(ctx context.Context, userID string, appMetadata AppMetadata) (*UserData, error) {
	user, err := m.provider.GetUserByID(ctx, userID)
	if err != nil {
		if m.appMetrics != nil {
			m.appMetrics.IDPMetrics().CountRequestError()
		}
		return nil, fmt.Errorf("failed to get user by ID: %w", err)
	}

	return &UserData{
		Email:       user.Email,
		Name:        user.Username,
		ID:          user.UserID,
		AppMetadata: appMetadata,
	}, nil
}

// GetAccount returns all the users for a given account.
// Note: Embedded dex doesn't store account metadata, so this returns all users.
func (m *EmbeddedIdPManager) GetAccount(ctx context.Context, accountID string) ([]*UserData, error) {
	users, err := m.provider.ListUsers(ctx)
	if err != nil {
		if m.appMetrics != nil {
			m.appMetrics.IDPMetrics().CountRequestError()
		}
		return nil, fmt.Errorf("failed to list users: %w", err)
	}

	result := make([]*UserData, 0, len(users))
	for _, user := range users {
		result = append(result, &UserData{
			Email: user.Email,
			Name:  user.Username,
			ID:    user.UserID,
			AppMetadata: AppMetadata{
				WTAccountID: accountID,
			},
		})
	}

	return result, nil
}

// GetAllAccounts gets all registered accounts with corresponding user data.
// Note: Embedded dex doesn't store account metadata, so all users are indexed under UnsetAccountID.
func (m *EmbeddedIdPManager) GetAllAccounts(ctx context.Context) (map[string][]*UserData, error) {
	if m.appMetrics != nil {
		m.appMetrics.IDPMetrics().CountGetAllAccounts()
	}

	users, err := m.provider.ListUsers(ctx)
	if err != nil {
		if m.appMetrics != nil {
			m.appMetrics.IDPMetrics().CountRequestError()
		}
		return nil, fmt.Errorf("failed to list users: %w", err)
	}

	log.WithContext(ctx).Debugf("retrieved %d users from embedded IdP", len(users))

	indexedUsers := make(map[string][]*UserData)
	for _, user := range users {
		indexedUsers[UnsetAccountID] = append(indexedUsers[UnsetAccountID], &UserData{
			Email: user.Email,
			Name:  user.Username,
			ID:    user.UserID,
		})
	}

	log.WithContext(ctx).Debugf("retrieved %d users from embedded IdP", len(indexedUsers[UnsetAccountID]))

	return indexedUsers, nil
}

// CreateUser creates a new user in the embedded IdP.
func (m *EmbeddedIdPManager) CreateUser(ctx context.Context, email, name, accountID, invitedByEmail string) (*UserData, error) {
	if m.config.LocalAuthDisabled {
		return nil, fmt.Errorf("local user creation is disabled")
	}

	if m.appMetrics != nil {
		m.appMetrics.IDPMetrics().CountCreateUser()
	}

	// Check if user already exists
	_, err := m.provider.GetUser(ctx, email)
	if err == nil {
		return nil, fmt.Errorf("user with email %s already exists", email)
	}
	if !errors.Is(err, storage.ErrNotFound) {
		if m.appMetrics != nil {
			m.appMetrics.IDPMetrics().CountRequestError()
		}
		return nil, fmt.Errorf("failed to check existing user: %w", err)
	}

	// Generate a random password for the new user
	password := GeneratePassword(16, 2, 2, 2)

	// Create the user via provider (handles hashing and ID generation)
	// The provider returns an encoded user ID in Dex's format (base64 protobuf with connector ID)
	userID, err := m.provider.CreateUser(ctx, email, name, password)
	if err != nil {
		if m.appMetrics != nil {
			m.appMetrics.IDPMetrics().CountRequestError()
		}
		return nil, fmt.Errorf("failed to create user in embedded IdP: %w", err)
	}

	log.WithContext(ctx).Debugf("created user %s in embedded IdP", email)

	return &UserData{
		Email:    email,
		Name:     name,
		ID:       userID,
		Password: password,
		AppMetadata: AppMetadata{
			WTAccountID: accountID,
			WTInvitedBy: invitedByEmail,
		},
	}, nil
}

// GetUserByEmail searches users with a given email.
func (m *EmbeddedIdPManager) GetUserByEmail(ctx context.Context, email string) ([]*UserData, error) {
	user, err := m.provider.GetUser(ctx, email)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return nil, nil // Return empty slice for not found
		}
		if m.appMetrics != nil {
			m.appMetrics.IDPMetrics().CountRequestError()
		}
		return nil, fmt.Errorf("failed to get user by email: %w", err)
	}

	return []*UserData{
		{
			Email: user.Email,
			Name:  user.Username,
			ID:    user.UserID,
		},
	}, nil
}

// CreateUserWithPassword creates a new user in the embedded IdP with a provided password.
// Unlike CreateUser which auto-generates a password, this method uses the provided password.
// This is useful for instance setup where the user provides their own password.
func (m *EmbeddedIdPManager) CreateUserWithPassword(ctx context.Context, email, password, name string) (*UserData, error) {
	if m.config.LocalAuthDisabled {
		return nil, fmt.Errorf("local user creation is disabled")
	}

	if m.appMetrics != nil {
		m.appMetrics.IDPMetrics().CountCreateUser()
	}

	// Check if user already exists
	_, err := m.provider.GetUser(ctx, email)
	if err == nil {
		return nil, fmt.Errorf("user with email %s already exists", email)
	}
	if !errors.Is(err, storage.ErrNotFound) {
		if m.appMetrics != nil {
			m.appMetrics.IDPMetrics().CountRequestError()
		}
		return nil, fmt.Errorf("failed to check existing user: %w", err)
	}

	// Create the user via provider with the provided password
	userID, err := m.provider.CreateUser(ctx, email, name, password)
	if err != nil {
		if m.appMetrics != nil {
			m.appMetrics.IDPMetrics().CountRequestError()
		}
		return nil, fmt.Errorf("failed to create user in embedded IdP: %w", err)
	}

	log.WithContext(ctx).Debugf("created user %s in embedded IdP with provided password", email)

	return &UserData{
		Email: email,
		Name:  name,
		ID:    userID,
	}, nil
}

// InviteUserByID resends an invitation to a user.
func (m *EmbeddedIdPManager) InviteUserByID(ctx context.Context, userID string) error {
	return fmt.Errorf("not implemented")
}

// DeleteUser deletes a user from the embedded IdP by user ID.
func (m *EmbeddedIdPManager) DeleteUser(ctx context.Context, userID string) error {
	if m.appMetrics != nil {
		m.appMetrics.IDPMetrics().CountDeleteUser()
	}

	// Get user by ID to retrieve email (provider.DeleteUser requires email)
	user, err := m.provider.GetUserByID(ctx, userID)
	if err != nil {
		if m.appMetrics != nil {
			m.appMetrics.IDPMetrics().CountRequestError()
		}
		return fmt.Errorf("failed to get user for deletion: %w", err)
	}

	err = m.provider.DeleteUser(ctx, user.Email)
	if err != nil {
		if m.appMetrics != nil {
			m.appMetrics.IDPMetrics().CountRequestError()
		}
		return fmt.Errorf("failed to delete user from embedded IdP: %w", err)
	}

	log.WithContext(ctx).Debugf("deleted user %s from embedded IdP", user.Email)

	return nil
}

// UpdateUserPassword updates the password for a user in the embedded IdP.
// It verifies that the current user is changing their own password and
// validates the current password before updating to the new password.
func (m *EmbeddedIdPManager) UpdateUserPassword(ctx context.Context, currentUserID, targetUserID string, oldPassword, newPassword string) error {
	// Verify the user is changing their own password
	if currentUserID != targetUserID {
		return fmt.Errorf("users can only change their own password")
	}

	// Verify the new password is different from the old password
	if oldPassword == newPassword {
		return fmt.Errorf("new password must be different from current password")
	}

	err := m.provider.UpdateUserPassword(ctx, targetUserID, oldPassword, newPassword)
	if err != nil {
		if m.appMetrics != nil {
			m.appMetrics.IDPMetrics().CountRequestError()
		}
		return err
	}

	log.WithContext(ctx).Debugf("updated password for user %s in embedded IdP", targetUserID)

	return nil
}

// CreateConnector creates a new identity provider connector in Dex.
// Returns the created connector config with the redirect URL populated.
func (m *EmbeddedIdPManager) CreateConnector(ctx context.Context, cfg *dex.ConnectorConfig) (*dex.ConnectorConfig, error) {
	return m.provider.CreateConnector(ctx, cfg)
}

// GetConnector retrieves an identity provider connector by ID.
func (m *EmbeddedIdPManager) GetConnector(ctx context.Context, id string) (*dex.ConnectorConfig, error) {
	return m.provider.GetConnector(ctx, id)
}

// ListConnectors returns all identity provider connectors.
func (m *EmbeddedIdPManager) ListConnectors(ctx context.Context) ([]*dex.ConnectorConfig, error) {
	return m.provider.ListConnectors(ctx)
}

// UpdateConnector updates an existing identity provider connector.
// Field preservation for partial updates is handled by Provider.UpdateConnector.
func (m *EmbeddedIdPManager) UpdateConnector(ctx context.Context, cfg *dex.ConnectorConfig) error {
	return m.provider.UpdateConnector(ctx, cfg)
}

// DeleteConnector removes an identity provider connector.
func (m *EmbeddedIdPManager) DeleteConnector(ctx context.Context, id string) error {
	return m.provider.DeleteConnector(ctx, id)
}

// GetIssuer returns the OIDC issuer URL.
func (m *EmbeddedIdPManager) GetIssuer() string {
	return m.provider.GetIssuer()
}

// GetTokenEndpoint returns the OAuth2 token endpoint URL.
func (m *EmbeddedIdPManager) GetTokenEndpoint() string {
	return m.provider.GetTokenEndpoint()
}

// GetDeviceAuthEndpoint returns the OAuth2 device authorization endpoint URL.
func (m *EmbeddedIdPManager) GetDeviceAuthEndpoint() string {
	return m.provider.GetDeviceAuthEndpoint()
}

// GetAuthorizationEndpoint returns the OAuth2 authorization endpoint URL.
func (m *EmbeddedIdPManager) GetAuthorizationEndpoint() string {
	return m.provider.GetAuthorizationEndpoint()
}

// GetDefaultScopes returns the default OAuth2 scopes for authentication.
func (m *EmbeddedIdPManager) GetDefaultScopes() string {
	return defaultScopes
}

// GetCLIClientID returns the client ID for CLI authentication.
func (m *EmbeddedIdPManager) GetCLIClientID() string {
	return staticClientCLI
}

// GetCLIRedirectURLs returns the redirect URLs configured for the CLI client.
func (m *EmbeddedIdPManager) GetCLIRedirectURLs() []string {
	if len(m.config.CLIRedirectURIs) == 0 {
		return []string{defaultCLIRedirectURL1, defaultCLIRedirectURL2}
	}
	return m.config.CLIRedirectURIs
}

// GetKeysLocation returns the JWKS endpoint URL for token validation.
func (m *EmbeddedIdPManager) GetKeysLocation() string {
	return m.provider.GetKeysLocation()
}

// GetLocalKeysLocation returns the localhost JWKS endpoint URL for internal token validation.
// Uses the LocalAddress from config (management server's listen address) since embedded Dex
// is served by the management HTTP server, not a standalone Dex server.
func (m *EmbeddedIdPManager) GetLocalKeysLocation() string {
	addr := m.config.LocalAddress
	if addr == "" {
		return ""
	}
	// Construct localhost URL from listen address
	// addr is in format ":port" or "host:port" or "localhost:port"
	if strings.HasPrefix(addr, ":") {
		return fmt.Sprintf("http://localhost%s/oauth2/keys", addr)
	}
	return fmt.Sprintf("http://%s/oauth2/keys", addr)
}

// GetClientIDs returns the OAuth2 client IDs configured for this provider.
func (m *EmbeddedIdPManager) GetClientIDs() []string {
	return []string{staticClientDashboard, staticClientCLI}
}

// GetUserIDClaim returns the JWT claim name used for user identification.
func (m *EmbeddedIdPManager) GetUserIDClaim() string {
	return defaultUserIDClaim
}

// IsLocalAuthDisabled returns whether local authentication is disabled based on configuration.
func (m *EmbeddedIdPManager) IsLocalAuthDisabled() bool {
	return m.config.LocalAuthDisabled
}

// HasNonLocalConnectors checks if there are any identity provider connectors other than local.
func (m *EmbeddedIdPManager) HasNonLocalConnectors(ctx context.Context) (bool, error) {
	return m.provider.HasNonLocalConnectors(ctx)
}
