package oidcprovider

import (
	"context"
	"crypto/sha256"
	"fmt"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	log "github.com/sirupsen/logrus"
	"github.com/zitadel/oidc/v3/pkg/op"
)

// Config holds the configuration for the OIDC provider
type Config struct {
	// Issuer is the OIDC issuer URL (e.g., "https://idp.example.com")
	Issuer string
	// Port is the port to listen on
	Port int
	// DataDir is the directory to store OIDC data (SQLite database)
	DataDir string
	// DevMode enables development mode (allows HTTP, localhost)
	DevMode bool
}

// Provider represents the embedded OIDC provider
type Provider struct {
	config     *Config
	store      *Store
	storage    *OIDCStorage
	provider   op.OpenIDProvider
	router     chi.Router
	httpServer *http.Server
}

// NewProvider creates a new OIDC provider
func NewProvider(ctx context.Context, config *Config) (*Provider, error) {
	// Create the SQLite store
	store, err := NewStore(ctx, config.DataDir)
	if err != nil {
		return nil, fmt.Errorf("failed to create OIDC store: %w", err)
	}

	// Create the OIDC storage adapter
	storage := NewOIDCStorage(store, config.Issuer)

	p := &Provider{
		config:  config,
		store:   store,
		storage: storage,
	}

	return p, nil
}

// Start starts the OIDC provider server
func (p *Provider) Start(ctx context.Context) error {
	// Create the router
	router := chi.NewRouter()
	router.Use(middleware.Logger)
	router.Use(middleware.Recoverer)
	router.Use(middleware.RequestID)

	// Create the OIDC provider
	key := sha256.Sum256([]byte(p.config.Issuer + "encryption-key"))

	opConfig := &op.Config{
		CryptoKey:                key,
		DefaultLogoutRedirectURI: "/logged-out",
		CodeMethodS256:           true,
		AuthMethodPost:           true,
		AuthMethodPrivateKeyJWT:  true,
		GrantTypeRefreshToken:    true,
		RequestObjectSupported:   true,
		DeviceAuthorization: op.DeviceAuthorizationConfig{
			Lifetime:     5 * time.Minute,
			PollInterval: 5 * time.Second,
			UserFormPath: "/device",
			UserCode:     op.UserCodeBase20,
		},
	}

	// Set the login URL generator
	p.storage.SetLoginURL(func(authRequestID string) string {
		return fmt.Sprintf("/login?authRequestID=%s", authRequestID)
	})

	// Create the provider with options
	var opts []op.Option
	if p.config.DevMode {
		opts = append(opts, op.WithAllowInsecure())
	}

	provider, err := op.NewProvider(opConfig, p.storage, op.StaticIssuer(p.config.Issuer), opts...)
	if err != nil {
		return fmt.Errorf("failed to create OIDC provider: %w", err)
	}
	p.provider = provider

	// Set up login handler
	loginHandler, err := NewLoginHandler(p.storage, func(authRequestID string) string {
		return provider.AuthorizationEndpoint().Absolute("/authorize/callback") + "?id=" + authRequestID
	})
	if err != nil {
		return fmt.Errorf("failed to create login handler: %w", err)
	}

	// Set up device handler
	deviceHandler, err := NewDeviceHandler(p.storage)
	if err != nil {
		return fmt.Errorf("failed to create device handler: %w", err)
	}

	// Mount routes
	router.Mount("/login", loginHandler.Router())
	router.Mount("/device", deviceHandler.Router())
	router.Get("/logged-out", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`<!DOCTYPE html><html><head><title>Logged Out</title></head><body><h1>You have been logged out</h1><p>You can close this window.</p></body></html>`))
	})

	// Mount the OIDC provider at root
	router.Mount("/", provider)

	p.router = router

	// Create HTTP server
	addr := fmt.Sprintf(":%d", p.config.Port)
	p.httpServer = &http.Server{
		Addr:    addr,
		Handler: router,
	}

	// Start server in goroutine
	go func() {
		log.Infof("Starting OIDC provider on %s (issuer: %s)", addr, p.config.Issuer)
		if err := p.httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Errorf("OIDC provider server error: %v", err)
		}
	}()

	// Start cleanup goroutine
	go p.cleanupLoop(ctx)

	return nil
}

// Stop stops the OIDC provider server
func (p *Provider) Stop(ctx context.Context) error {
	if p.httpServer != nil {
		if err := p.httpServer.Shutdown(ctx); err != nil {
			return fmt.Errorf("failed to shutdown OIDC server: %w", err)
		}
	}
	if p.store != nil {
		if err := p.store.Close(); err != nil {
			return fmt.Errorf("failed to close OIDC store: %w", err)
		}
	}
	return nil
}

// cleanupLoop periodically cleans up expired tokens
func (p *Provider) cleanupLoop(ctx context.Context) {
	ticker := time.NewTicker(15 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := p.store.CleanupExpired(ctx); err != nil {
				log.Warnf("OIDC cleanup error: %v", err)
			}
		}
	}
}

// Store returns the underlying store for user/client management
func (p *Provider) Store() *Store {
	return p.store
}

// GetIssuer returns the issuer URL
func (p *Provider) GetIssuer() string {
	return p.config.Issuer
}

// GetDiscoveryEndpoint returns the OpenID Connect discovery endpoint
func (p *Provider) GetDiscoveryEndpoint() string {
	return p.config.Issuer + "/.well-known/openid-configuration"
}

// GetTokenEndpoint returns the token endpoint
func (p *Provider) GetTokenEndpoint() string {
	return p.config.Issuer + "/oauth/token"
}

// GetAuthorizationEndpoint returns the authorization endpoint
func (p *Provider) GetAuthorizationEndpoint() string {
	return p.config.Issuer + "/authorize"
}

// GetDeviceAuthorizationEndpoint returns the device authorization endpoint
func (p *Provider) GetDeviceAuthorizationEndpoint() string {
	return p.config.Issuer + "/device_authorization"
}

// GetJWKSEndpoint returns the JWKS endpoint
func (p *Provider) GetJWKSEndpoint() string {
	return p.config.Issuer + "/keys"
}

// GetUserInfoEndpoint returns the userinfo endpoint
func (p *Provider) GetUserInfoEndpoint() string {
	return p.config.Issuer + "/userinfo"
}

// EnsureDefaultClients ensures the default NetBird clients exist
func (p *Provider) EnsureDefaultClients(ctx context.Context, dashboardRedirectURIs, cliRedirectURIs []string) error {
	// Check if CLI client exists
	_, err := p.store.GetClientByID(ctx, "netbird-client")
	if err != nil {
		// Create CLI client (native, public, supports PKCE and device flow)
		cliClient := CreateNativeClient("netbird-client", "NetBird CLI", cliRedirectURIs)
		if err := p.store.CreateClient(ctx, cliClient); err != nil {
			return fmt.Errorf("failed to create CLI client: %w", err)
		}
		log.Info("Created default NetBird CLI client")
	}

	// Check if dashboard client exists
	_, err = p.store.GetClientByID(ctx, "netbird-dashboard")
	if err != nil {
		// Create dashboard client (SPA, public, supports PKCE)
		dashboardClient := CreateSPAClient("netbird-dashboard", "NetBird Dashboard", dashboardRedirectURIs)
		if err := p.store.CreateClient(ctx, dashboardClient); err != nil {
			return fmt.Errorf("failed to create dashboard client: %w", err)
		}
		log.Info("Created default NetBird Dashboard client")
	}

	return nil
}

// CreateUser creates a new user (convenience method)
func (p *Provider) CreateUser(ctx context.Context, username, password, email, firstName, lastName string) (*User, error) {
	user := &User{
		Username:      username,
		Password:      password, // Will be hashed by store
		Email:         email,
		EmailVerified: false,
		FirstName:     firstName,
		LastName:      lastName,
	}

	if err := p.store.CreateUser(ctx, user); err != nil {
		return nil, err
	}

	return user, nil
}
