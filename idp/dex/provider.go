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

// Start starts the HTTP server and optionally the gRPC API server
func (p *Provider) Start(ctx context.Context) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.running {
		return fmt.Errorf("already running")
	}

	addr := fmt.Sprintf(":%d", p.config.Port)
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
			p.httpServer.Close()
			p.listener.Close()
			return fmt.Errorf("failed to start gRPC server: %w", err)
		}
	}

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
