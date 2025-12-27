// Package dex provides an embedded Dex OIDC identity provider.
package dex

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	dexapi "github.com/dexidp/dex/api/v2"
	"github.com/dexidp/dex/server"
	"github.com/dexidp/dex/storage"
	"github.com/dexidp/dex/storage/sql"
	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus"
	"golang.org/x/crypto/bcrypt"
	"google.golang.org/grpc"
)

// Config matches what management/internals/server/server.go expects
type Config struct {
	Issuer  string
	Port    int
	DataDir string
	DevMode bool

	// GRPCAddr is the address for the gRPC API (e.g., ":5557"). Empty disables gRPC.
	GRPCAddr string
}

// Provider wraps a Dex server
type Provider struct {
	config       *Config
	yamlConfig   *YAMLConfig
	dexServer    *server.Server
	httpServer   *http.Server
	listener     net.Listener
	grpcServer   *grpc.Server
	grpcListener net.Listener
	storage      storage.Storage
	logger       *slog.Logger
	mu           sync.Mutex
	running      bool
}

// NewProvider creates and initializes the Dex server
func NewProvider(ctx context.Context, config *Config) (*Provider, error) {
	if config.Issuer == "" {
		return nil, fmt.Errorf("issuer is required")
	}
	if config.Port <= 0 {
		return nil, fmt.Errorf("invalid port")
	}
	if config.DataDir == "" {
		return nil, fmt.Errorf("data directory is required")
	}

	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))

	// Ensure data directory exists
	if err := os.MkdirAll(config.DataDir, 0700); err != nil {
		return nil, fmt.Errorf("failed to create data directory: %w", err)
	}

	// Initialize SQLite storage
	dbPath := filepath.Join(config.DataDir, "oidc.db")
	sqliteConfig := &sql.SQLite3{File: dbPath}
	stor, err := sqliteConfig.Open(logger)
	if err != nil {
		return nil, fmt.Errorf("failed to open storage: %w", err)
	}

	// Ensure a local connector exists (for password authentication)
	if err := ensureLocalConnector(ctx, stor); err != nil {
		stor.Close()
		return nil, fmt.Errorf("failed to ensure local connector: %w", err)
	}

	// Ensure issuer ends with /dex for proper path mounting
	issuer := strings.TrimSuffix(config.Issuer, "/")
	if !strings.HasSuffix(issuer, "/dex") {
		issuer = issuer + "/dex"
	}

	// Build refresh token policy (required to avoid nil pointer panics)
	refreshPolicy, err := server.NewRefreshTokenPolicy(logger, false, "", "", "")
	if err != nil {
		stor.Close()
		return nil, fmt.Errorf("failed to create refresh token policy: %w", err)
	}

	// Build Dex server config - use Dex's types directly
	dexConfig := server.Config{
		Issuer:                 issuer,
		Storage:                stor,
		SkipApprovalScreen:     true,
		SupportedResponseTypes: []string{"code"},
		Logger:                 logger,
		PrometheusRegistry:     prometheus.NewRegistry(),
		RotateKeysAfter:        6 * time.Hour,
		IDTokensValidFor:       24 * time.Hour,
		RefreshTokenPolicy:     refreshPolicy,
		Web: server.WebConfig{
			Issuer: "NetBird",
		},
	}

	dexSrv, err := server.NewServer(ctx, dexConfig)
	if err != nil {
		stor.Close()
		return nil, fmt.Errorf("failed to create dex server: %w", err)
	}

	return &Provider{
		config:    config,
		dexServer: dexSrv,
		storage:   stor,
		logger:    logger,
	}, nil
}

// NewProviderFromYAML creates and initializes the Dex server from a YAMLConfig
func NewProviderFromYAML(ctx context.Context, yamlConfig *YAMLConfig) (*Provider, error) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))

	// Open storage based on config
	stor, err := yamlConfig.Storage.OpenStorage(logger)
	if err != nil {
		return nil, fmt.Errorf("failed to open storage: %w", err)
	}

	// Ensure a local connector exists if password DB is enabled
	if yamlConfig.EnablePasswordDB {
		if err := ensureLocalConnector(ctx, stor); err != nil {
			stor.Close()
			return nil, fmt.Errorf("failed to ensure local connector: %w", err)
		}
	}

	// Create static passwords if provided
	for _, pw := range yamlConfig.StaticPasswords {
		existing, err := stor.GetPassword(ctx, pw.Email)
		if err == storage.ErrNotFound {
			if err := stor.CreatePassword(ctx, storage.Password(pw)); err != nil {
				stor.Close()
				return nil, fmt.Errorf("failed to create password for %s: %w", pw.Email, err)
			}
			continue
		}
		if err != nil {
			stor.Close()
			return nil, fmt.Errorf("failed to get password for %s: %w", pw.Email, err)
		}
		// Update existing user if hash changed
		if string(existing.Hash) != string(pw.Hash) {
			if err := stor.UpdatePassword(ctx, pw.Email, func(old storage.Password) (storage.Password, error) {
				old.Hash = pw.Hash
				old.Username = pw.Username
				return old, nil
			}); err != nil {
				stor.Close()
				return nil, fmt.Errorf("failed to update password for %s: %w", pw.Email, err)
			}
		}
	}

	// Create static clients if provided
	for _, client := range yamlConfig.StaticClients {
		_, err := stor.GetClient(ctx, client.ID)
		if err == storage.ErrNotFound {
			if err := stor.CreateClient(ctx, client); err != nil {
				stor.Close()
				return nil, fmt.Errorf("failed to create client %s: %w", client.ID, err)
			}
			continue
		}
		if err != nil {
			stor.Close()
			return nil, fmt.Errorf("failed to get client %s: %w", client.ID, err)
		}
		// Update if exists
		if err := stor.UpdateClient(ctx, client.ID, func(old storage.Client) (storage.Client, error) {
			old.RedirectURIs = client.RedirectURIs
			old.Name = client.Name
			old.Public = client.Public
			return old, nil
		}); err != nil {
			stor.Close()
			return nil, fmt.Errorf("failed to update client %s: %w", client.ID, err)
		}
	}

	// Create connectors if provided
	for _, conn := range yamlConfig.StaticConnectors {
		storConn, err := conn.ToStorageConnector()
		if err != nil {
			stor.Close()
			return nil, fmt.Errorf("failed to convert connector %s: %w", conn.ID, err)
		}
		_, err = stor.GetConnector(ctx, conn.ID)
		if err == storage.ErrNotFound {
			if err := stor.CreateConnector(ctx, storConn); err != nil {
				stor.Close()
				return nil, fmt.Errorf("failed to create connector %s: %w", conn.ID, err)
			}
			continue
		}
		if err != nil {
			stor.Close()
			return nil, fmt.Errorf("failed to get connector %s: %w", conn.ID, err)
		}
		// Update if exists
		if err := stor.UpdateConnector(ctx, conn.ID, func(old storage.Connector) (storage.Connector, error) {
			old.Name = storConn.Name
			old.Config = storConn.Config
			return old, nil
		}); err != nil {
			stor.Close()
			return nil, fmt.Errorf("failed to update connector %s: %w", conn.ID, err)
		}
	}

	// Build Dex server config
	dexConfig := yamlConfig.ToServerConfig(stor, logger)
	dexConfig.PrometheusRegistry = prometheus.NewRegistry()
	dexConfig.RotateKeysAfter = 6 * time.Hour
	dexConfig.IDTokensValidFor = 24 * time.Hour
	if dexConfig.Web.Issuer == "" {
		dexConfig.Web.Issuer = "NetBird"
	}
	if len(dexConfig.SupportedResponseTypes) == 0 {
		dexConfig.SupportedResponseTypes = []string{"code"}
	}

	// Ensure RefreshTokenPolicy is set (required to avoid nil pointer panics)
	if dexConfig.RefreshTokenPolicy == nil {
		refreshPolicy, err := server.NewRefreshTokenPolicy(logger, false, "", "", "")
		if err != nil {
			stor.Close()
			return nil, fmt.Errorf("failed to create refresh token policy: %w", err)
		}
		dexConfig.RefreshTokenPolicy = refreshPolicy
	}

	dexSrv, err := server.NewServer(ctx, dexConfig)
	if err != nil {
		stor.Close()
		return nil, fmt.Errorf("failed to create dex server: %w", err)
	}

	// Convert YAMLConfig to Config for internal use
	config := &Config{
		Issuer:   yamlConfig.Issuer,
		GRPCAddr: yamlConfig.GRPC.Addr,
	}

	return &Provider{
		config:     config,
		yamlConfig: yamlConfig,
		dexServer:  dexSrv,
		storage:    stor,
		logger:     logger,
	}, nil
}

// Start starts the HTTP server and optionally the gRPC API server
func (p *Provider) Start(_ context.Context) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.running {
		return fmt.Errorf("already running")
	}

	// Determine listen address from config
	var addr string
	if p.yamlConfig != nil {
		addr = p.yamlConfig.Web.HTTP
		if addr == "" {
			addr = p.yamlConfig.Web.HTTPS
		}
	} else if p.config != nil && p.config.Port > 0 {
		addr = fmt.Sprintf(":%d", p.config.Port)
	}
	if addr == "" {
		return fmt.Errorf("no listen address configured")
	}

	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", addr, err)
	}
	p.listener = listener

	// Mount Dex at /dex/ path for reverse proxy compatibility
	// Don't strip the prefix - Dex's issuer includes /dex so it expects the full path
	mux := http.NewServeMux()
	mux.Handle("/dex/", p.dexServer)

	p.httpServer = &http.Server{Handler: mux}
	p.running = true

	go func() {
		if err := p.httpServer.Serve(listener); err != nil && err != http.ErrServerClosed {
			p.logger.Error("http server error", "error", err)
		}
	}()

	// Start gRPC API server if configured
	if p.config.GRPCAddr != "" {
		if err := p.startGRPCServer(); err != nil {
			// Clean up HTTP server on failure
			_ = p.httpServer.Close()
			_ = p.listener.Close()
			return fmt.Errorf("failed to start gRPC server: %w", err)
		}
	}

	p.logger.Info("HTTP server started", "addr", addr)
	return nil
}

// startGRPCServer starts the gRPC API server using Dex's built-in API
func (p *Provider) startGRPCServer() error {
	grpcListener, err := net.Listen("tcp", p.config.GRPCAddr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", p.config.GRPCAddr, err)
	}
	p.grpcListener = grpcListener

	p.grpcServer = grpc.NewServer()
	// Use Dex's built-in API server implementation
	// server.NewAPI(storage, logger, version, dexServer)
	dexapi.RegisterDexServer(p.grpcServer, server.NewAPI(p.storage, p.logger, "netbird-dex", p.dexServer))

	go func() {
		if err := p.grpcServer.Serve(grpcListener); err != nil {
			p.logger.Error("grpc server error", "error", err)
		}
	}()

	p.logger.Info("gRPC API server started", "addr", p.config.GRPCAddr)
	return nil
}

// Stop gracefully shuts down
func (p *Provider) Stop(ctx context.Context) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if !p.running {
		return nil
	}

	var errs []error

	// Stop gRPC server first
	if p.grpcServer != nil {
		p.grpcServer.GracefulStop()
		p.grpcServer = nil
	}
	if p.grpcListener != nil {
		p.grpcListener.Close()
		p.grpcListener = nil
	}

	if p.httpServer != nil {
		if err := p.httpServer.Shutdown(ctx); err != nil {
			errs = append(errs, err)
		}
	}

	// Explicitly close listener as fallback (Shutdown should do this, but be safe)
	if p.listener != nil {
		if err := p.listener.Close(); err != nil {
			// Ignore "use of closed network connection" - expected after Shutdown
			if !strings.Contains(err.Error(), "use of closed") {
				errs = append(errs, err)
			}
		}
		p.listener = nil
	}

	if p.storage != nil {
		if err := p.storage.Close(); err != nil {
			errs = append(errs, err)
		}
	}

	p.httpServer = nil
	p.running = false

	if len(errs) > 0 {
		return fmt.Errorf("shutdown errors: %v", errs)
	}
	return nil
}

// EnsureDefaultClients creates dashboard and CLI OAuth clients
// Uses Dex's storage.Client directly - no custom wrappers
func (p *Provider) EnsureDefaultClients(ctx context.Context, dashboardURIs, cliURIs []string) error {
	clients := []storage.Client{
		{
			ID:           "netbird-dashboard",
			Name:         "NetBird Dashboard",
			RedirectURIs: dashboardURIs,
			Public:       true,
		},
		{
			ID:           "netbird-cli",
			Name:         "NetBird CLI",
			RedirectURIs: cliURIs,
			Public:       true,
		},
	}

	for _, client := range clients {
		_, err := p.storage.GetClient(ctx, client.ID)
		if err == storage.ErrNotFound {
			if err := p.storage.CreateClient(ctx, client); err != nil {
				return fmt.Errorf("failed to create client %s: %w", client.ID, err)
			}
			continue
		}
		if err != nil {
			return fmt.Errorf("failed to get client %s: %w", client.ID, err)
		}
		// Update if exists
		if err := p.storage.UpdateClient(ctx, client.ID, func(old storage.Client) (storage.Client, error) {
			old.RedirectURIs = client.RedirectURIs
			return old, nil
		}); err != nil {
			return fmt.Errorf("failed to update client %s: %w", client.ID, err)
		}
	}

	p.logger.Info("default OIDC clients ensured")
	return nil
}

// Storage returns the underlying Dex storage for direct access
// Users can use storage.Client, storage.Password, storage.Connector directly
func (p *Provider) Storage() storage.Storage {
	return p.storage
}

// Handler returns the Dex server as an http.Handler for embedding in another server.
// The handler expects requests with path prefix "/dex/".
func (p *Provider) Handler() http.Handler {
	return p.dexServer
}

// CreateUser creates a new user with the given email, username, and password.
// Returns the encoded user ID in Dex's format (base64-encoded protobuf with connector ID).
func (p *Provider) CreateUser(ctx context.Context, email, username, password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", fmt.Errorf("failed to hash password: %w", err)
	}

	userID := uuid.New().String()
	err = p.storage.CreatePassword(ctx, storage.Password{
		Email:    email,
		Username: username,
		UserID:   userID,
		Hash:     hash,
	})
	if err != nil {
		return "", err
	}

	// Encode the user ID in Dex's format: base64(protobuf{user_id, connector_id})
	// This matches the format Dex uses in JWT tokens
	encodedID := EncodeDexUserID(userID, "local")
	return encodedID, nil
}

// EncodeDexUserID encodes user ID and connector ID into Dex's base64-encoded protobuf format.
// Dex uses this format for the 'sub' claim in JWT tokens.
// Format: base64(protobuf message with field 1 = user_id, field 2 = connector_id)
func EncodeDexUserID(userID, connectorID string) string {
	// Manually encode protobuf: field 1 (user_id) and field 2 (connector_id)
	// Wire type 2 (length-delimited) for strings
	var buf []byte

	// Field 1: user_id (tag = 0x0a = field 1, wire type 2)
	buf = append(buf, 0x0a)
	buf = append(buf, byte(len(userID)))
	buf = append(buf, []byte(userID)...)

	// Field 2: connector_id (tag = 0x12 = field 2, wire type 2)
	buf = append(buf, 0x12)
	buf = append(buf, byte(len(connectorID)))
	buf = append(buf, []byte(connectorID)...)

	return base64.RawStdEncoding.EncodeToString(buf)
}

// DecodeDexUserID decodes Dex's base64-encoded user ID back to the raw user ID and connector ID.
func DecodeDexUserID(encodedID string) (userID, connectorID string, err error) {
	// Try RawStdEncoding first, then StdEncoding (with padding)
	buf, err := base64.RawStdEncoding.DecodeString(encodedID)
	if err != nil {
		buf, err = base64.StdEncoding.DecodeString(encodedID)
		if err != nil {
			return "", "", fmt.Errorf("failed to decode base64: %w", err)
		}
	}

	// Parse protobuf manually
	i := 0
	for i < len(buf) {
		if i >= len(buf) {
			break
		}
		tag := buf[i]
		i++

		fieldNum := tag >> 3
		wireType := tag & 0x07

		if wireType != 2 { // We only expect length-delimited strings
			return "", "", fmt.Errorf("unexpected wire type %d", wireType)
		}

		if i >= len(buf) {
			return "", "", fmt.Errorf("truncated message")
		}
		length := int(buf[i])
		i++

		if i+length > len(buf) {
			return "", "", fmt.Errorf("truncated string field")
		}
		value := string(buf[i : i+length])
		i += length

		switch fieldNum {
		case 1:
			userID = value
		case 2:
			connectorID = value
		}
	}

	return userID, connectorID, nil
}

// GetUser returns a user by email
func (p *Provider) GetUser(ctx context.Context, email string) (storage.Password, error) {
	return p.storage.GetPassword(ctx, email)
}

// GetUserByID returns a user by user ID.
// The userID can be either an encoded Dex ID (base64 protobuf) or a raw UUID.
// Note: This requires iterating through all users since dex storage doesn't index by userID.
func (p *Provider) GetUserByID(ctx context.Context, userID string) (storage.Password, error) {
	// Try to decode the user ID in case it's encoded
	rawUserID, _, err := DecodeDexUserID(userID)
	if err != nil {
		// If decoding fails, assume it's already a raw UUID
		rawUserID = userID
	}

	users, err := p.storage.ListPasswords(ctx)
	if err != nil {
		return storage.Password{}, fmt.Errorf("failed to list users: %w", err)
	}
	for _, user := range users {
		if user.UserID == rawUserID {
			return user, nil
		}
	}
	return storage.Password{}, storage.ErrNotFound
}

// DeleteUser removes a user by email
func (p *Provider) DeleteUser(ctx context.Context, email string) error {
	return p.storage.DeletePassword(ctx, email)
}

// ListUsers returns all users
func (p *Provider) ListUsers(ctx context.Context) ([]storage.Password, error) {
	return p.storage.ListPasswords(ctx)
}

// ensureLocalConnector creates a local (password) connector if none exists
func ensureLocalConnector(ctx context.Context, stor storage.Storage) error {
	connectors, err := stor.ListConnectors(ctx)
	if err != nil {
		return fmt.Errorf("failed to list connectors: %w", err)
	}

	// If any connector exists, we're good
	if len(connectors) > 0 {
		return nil
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
func (p *Provider) CreateConnector(ctx context.Context, cfg *ConnectorConfig) error {
	storageConn, err := p.buildStorageConnector(cfg)
	if err != nil {
		return fmt.Errorf("failed to build connector: %w", err)
	}

	if err := p.storage.CreateConnector(ctx, storageConn); err != nil {
		return fmt.Errorf("failed to create connector: %w", err)
	}

	p.logger.Info("connector created", "id", cfg.ID, "type", cfg.Type)
	return nil
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
func (p *Provider) UpdateConnector(ctx context.Context, cfg *ConnectorConfig) error {
	storageConn, err := p.buildStorageConnector(cfg)
	if err != nil {
		return fmt.Errorf("failed to build connector: %w", err)
	}

	if err := p.storage.UpdateConnector(ctx, cfg.ID, func(old storage.Connector) (storage.Connector, error) {
		return storageConn, nil
	}); err != nil {
		return fmt.Errorf("failed to update connector: %w", err)
	}

	p.logger.Info("connector updated", "id", cfg.ID, "type", cfg.Type)
	return nil
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

// buildStorageConnector creates a storage.Connector from ConnectorConfig.
// It handles the type-specific configuration for each connector type.
func (p *Provider) buildStorageConnector(cfg *ConnectorConfig) (storage.Connector, error) {
	var configData []byte
	var dexType string

	// Determine the redirect URI - default to Dex callback
	redirectURI := cfg.RedirectURI
	if redirectURI == "" && p.config != nil {
		issuer := strings.TrimSuffix(p.config.Issuer, "/")
		if !strings.HasSuffix(issuer, "/dex") {
			issuer = issuer + "/dex"
		}
		redirectURI = issuer + "/callback"
	}

	switch cfg.Type {
	case "oidc", "zitadel", "entra", "okta", "pocketid":
		// All these types use the OIDC connector in Dex
		dexType = "oidc"
		oidcConfig := map[string]interface{}{
			"issuer":       cfg.Issuer,
			"clientID":     cfg.ClientID,
			"clientSecret": cfg.ClientSecret,
			"redirectURI":  redirectURI,
			"scopes":       []string{"openid", "profile", "email"},
		}
		// Type-specific configurations
		switch cfg.Type {
		case "zitadel":
			oidcConfig["getUserInfo"] = true
		case "entra":
			oidcConfig["insecureSkipEmailVerified"] = true
			oidcConfig["claimMapping"] = map[string]string{
				"email": "preferred_username",
			}
		case "okta":
			oidcConfig["insecureSkipEmailVerified"] = true
		}
		var err error
		configData, err = encodeConnectorConfig(oidcConfig)
		if err != nil {
			return storage.Connector{}, err
		}

	case "google":
		dexType = "google"
		googleConfig := map[string]interface{}{
			"clientID":     cfg.ClientID,
			"clientSecret": cfg.ClientSecret,
			"redirectURI":  redirectURI,
		}
		var err error
		configData, err = encodeConnectorConfig(googleConfig)
		if err != nil {
			return storage.Connector{}, err
		}

	case "microsoft":
		dexType = "microsoft"
		msConfig := map[string]interface{}{
			"clientID":     cfg.ClientID,
			"clientSecret": cfg.ClientSecret,
			"redirectURI":  redirectURI,
		}
		var err error
		configData, err = encodeConnectorConfig(msConfig)
		if err != nil {
			return storage.Connector{}, err
		}

	default:
		return storage.Connector{}, fmt.Errorf("unsupported connector type: %s", cfg.Type)
	}

	return storage.Connector{
		ID:     cfg.ID,
		Type:   dexType,
		Name:   cfg.Name,
		Config: configData,
	}, nil
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
func inferIdentityProviderType(dexType, connectorID string, config map[string]interface{}) string {
	connectorIDLower := strings.ToLower(connectorID)

	switch dexType {
	case "oidc":
		// Check connector ID for specific provider hints
		switch {
		case strings.Contains(connectorIDLower, "pocketid"):
			return "pocketid"
		case strings.Contains(connectorIDLower, "zitadel"):
			return "zitadel"
		case strings.Contains(connectorIDLower, "entra"):
			return "entra"
		case strings.Contains(connectorIDLower, "okta"):
			return "okta"
		default:
			return "oidc"
		}
	case "google":
		return "google"
	case "microsoft":
		return "microsoft"
	default:
		return dexType
	}
}

// encodeConnectorConfig serializes connector config to JSON bytes.
func encodeConnectorConfig(config map[string]interface{}) ([]byte, error) {
	return json.Marshal(config)
}

// decodeConnectorConfig deserializes connector config from JSON bytes.
func decodeConnectorConfig(data []byte, v interface{}) error {
	return json.Unmarshal(data, v)
}

// GetRedirectURI returns the default redirect URI for connectors.
func (p *Provider) GetRedirectURI() string {
	if p.config == nil {
		return ""
	}
	issuer := strings.TrimSuffix(p.config.Issuer, "/")
	if !strings.HasSuffix(issuer, "/dex") {
		issuer = issuer + "/dex"
	}
	return issuer + "/callback"
}
