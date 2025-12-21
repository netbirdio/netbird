// Package dex provides an embedded Dex OIDC identity provider.
package dex

import (
	"context"
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

// CreateUser creates a new user with the given email, username, and password
func (p *Provider) CreateUser(ctx context.Context, email, username, password string) error {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("failed to hash password: %w", err)
	}

	return p.storage.CreatePassword(ctx, storage.Password{
		Email:    email,
		Username: username,
		UserID:   uuid.New().String(),
		Hash:     hash,
	})
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
