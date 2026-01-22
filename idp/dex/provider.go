// Package dex provides an embedded Dex OIDC identity provider.
package dex

import (
	"context"
	"encoding/base64"
	"errors"
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

	// Ensure issuer ends with /oauth2 for proper path mounting
	issuer := strings.TrimSuffix(config.Issuer, "/")
	if !strings.HasSuffix(issuer, "/oauth2") {
		issuer += "/oauth2"
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
	// Configure log level from config, default to WARN to avoid logging sensitive data (emails)
	logLevel := slog.LevelWarn
	if yamlConfig.Logger.Level != "" {
		switch strings.ToLower(yamlConfig.Logger.Level) {
		case "debug":
			logLevel = slog.LevelDebug
		case "info":
			logLevel = slog.LevelInfo
		case "warn", "warning":
			logLevel = slog.LevelWarn
		case "error":
			logLevel = slog.LevelError
		}
	}
	logger := slog.New(NewLogrusHandler(logLevel))

	stor, err := yamlConfig.Storage.OpenStorage(logger)
	if err != nil {
		return nil, fmt.Errorf("failed to open storage: %w", err)
	}

	if err := initializeStorage(ctx, stor, yamlConfig); err != nil {
		stor.Close()
		return nil, err
	}

	dexConfig := buildDexConfig(yamlConfig, stor, logger)
	dexConfig.RefreshTokenPolicy, err = yamlConfig.GetRefreshTokenPolicy(logger)
	if err != nil {
		stor.Close()
		return nil, fmt.Errorf("failed to create refresh token policy: %w", err)
	}

	dexSrv, err := server.NewServer(ctx, dexConfig)
	if err != nil {
		stor.Close()
		return nil, fmt.Errorf("failed to create dex server: %w", err)
	}

	return &Provider{
		config:     &Config{Issuer: yamlConfig.Issuer, GRPCAddr: yamlConfig.GRPC.Addr},
		yamlConfig: yamlConfig,
		dexServer:  dexSrv,
		storage:    stor,
		logger:     logger,
	}, nil
}

// initializeStorage sets up connectors, passwords, and clients in storage
func initializeStorage(ctx context.Context, stor storage.Storage, cfg *YAMLConfig) error {
	if cfg.EnablePasswordDB {
		if err := ensureLocalConnector(ctx, stor); err != nil {
			return fmt.Errorf("failed to ensure local connector: %w", err)
		}
	}
	if err := ensureStaticPasswords(ctx, stor, cfg.StaticPasswords); err != nil {
		return err
	}
	if err := ensureStaticClients(ctx, stor, cfg.StaticClients); err != nil {
		return err
	}
	return ensureStaticConnectors(ctx, stor, cfg.StaticConnectors)
}

// ensureStaticPasswords creates or updates static passwords in storage
func ensureStaticPasswords(ctx context.Context, stor storage.Storage, passwords []Password) error {
	for _, pw := range passwords {
		existing, err := stor.GetPassword(ctx, pw.Email)
		if errors.Is(err, storage.ErrNotFound) {
			if err := stor.CreatePassword(ctx, storage.Password(pw)); err != nil {
				return fmt.Errorf("failed to create password for %s: %w", pw.Email, err)
			}
			continue
		}
		if err != nil {
			return fmt.Errorf("failed to get password for %s: %w", pw.Email, err)
		}
		if string(existing.Hash) != string(pw.Hash) {
			if err := stor.UpdatePassword(ctx, pw.Email, func(old storage.Password) (storage.Password, error) {
				old.Hash = pw.Hash
				old.Username = pw.Username
				return old, nil
			}); err != nil {
				return fmt.Errorf("failed to update password for %s: %w", pw.Email, err)
			}
		}
	}
	return nil
}

// ensureStaticClients creates or updates static clients in storage
func ensureStaticClients(ctx context.Context, stor storage.Storage, clients []storage.Client) error {
	for _, client := range clients {
		_, err := stor.GetClient(ctx, client.ID)
		if errors.Is(err, storage.ErrNotFound) {
			if err := stor.CreateClient(ctx, client); err != nil {
				return fmt.Errorf("failed to create client %s: %w", client.ID, err)
			}
			continue
		}
		if err != nil {
			return fmt.Errorf("failed to get client %s: %w", client.ID, err)
		}
		if err := stor.UpdateClient(ctx, client.ID, func(old storage.Client) (storage.Client, error) {
			old.RedirectURIs = client.RedirectURIs
			old.Name = client.Name
			old.Public = client.Public
			return old, nil
		}); err != nil {
			return fmt.Errorf("failed to update client %s: %w", client.ID, err)
		}
	}
	return nil
}

// buildDexConfig creates a server.Config with defaults applied
func buildDexConfig(yamlConfig *YAMLConfig, stor storage.Storage, logger *slog.Logger) server.Config {
	cfg := yamlConfig.ToServerConfig(stor, logger)
	cfg.PrometheusRegistry = prometheus.NewRegistry()
	if cfg.RotateKeysAfter == 0 {
		cfg.RotateKeysAfter = 24 * 30 * time.Hour
	}
	if cfg.IDTokensValidFor == 0 {
		cfg.IDTokensValidFor = 24 * time.Hour
	}
	if cfg.Web.Issuer == "" {
		cfg.Web.Issuer = "NetBird"
	}
	if len(cfg.SupportedResponseTypes) == 0 {
		cfg.SupportedResponseTypes = []string{"code"}
	}
	return cfg
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

	// Mount Dex at /oauth2/ path for reverse proxy compatibility
	// Don't strip the prefix - Dex's issuer includes /oauth2 so it expects the full path
	mux := http.NewServeMux()
	mux.Handle("/oauth2/", p.dexServer)

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
// The handler expects requests with path prefix "/oauth2/".
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

// UpdateUserPassword updates the password for a user identified by userID.
// The userID can be either an encoded Dex ID (base64 protobuf) or a raw UUID.
// It verifies the current password before updating.
func (p *Provider) UpdateUserPassword(ctx context.Context, userID string, oldPassword, newPassword string) error {
	// Get the user by ID to find their email
	user, err := p.GetUserByID(ctx, userID)
	if err != nil {
		return fmt.Errorf("failed to get user: %w", err)
	}

	// Verify old password
	if err := bcrypt.CompareHashAndPassword(user.Hash, []byte(oldPassword)); err != nil {
		return fmt.Errorf("current password is incorrect")
	}

	// Hash the new password
	newHash, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("failed to hash new password: %w", err)
	}

	// Update the password in storage
	err = p.storage.UpdatePassword(ctx, user.Email, func(old storage.Password) (storage.Password, error) {
		old.Hash = newHash
		return old, nil
	})
	if err != nil {
		return fmt.Errorf("failed to update password: %w", err)
	}

	return nil
}

// GetIssuer returns the OIDC issuer URL.
func (p *Provider) GetIssuer() string {
	if p.config == nil {
		return ""
	}
	issuer := strings.TrimSuffix(p.config.Issuer, "/")
	if !strings.HasSuffix(issuer, "/oauth2") {
		issuer += "/oauth2"
	}
	return issuer
}

// GetKeysLocation returns the JWKS endpoint URL for token validation.
func (p *Provider) GetKeysLocation() string {
	issuer := p.GetIssuer()
	if issuer == "" {
		return ""
	}
	return issuer + "/keys"
}

// GetTokenEndpoint returns the OAuth2 token endpoint URL.
func (p *Provider) GetTokenEndpoint() string {
	issuer := p.GetIssuer()
	if issuer == "" {
		return ""
	}
	return issuer + "/token"
}

// GetDeviceAuthEndpoint returns the OAuth2 device authorization endpoint URL.
func (p *Provider) GetDeviceAuthEndpoint() string {
	issuer := p.GetIssuer()
	if issuer == "" {
		return ""
	}
	return issuer + "/device/code"
}

// GetAuthorizationEndpoint returns the OAuth2 authorization endpoint URL.
func (p *Provider) GetAuthorizationEndpoint() string {
	issuer := p.GetIssuer()
	if issuer == "" {
		return ""
	}
	return issuer + "/auth"
}
