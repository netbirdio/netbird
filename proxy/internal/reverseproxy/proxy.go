package reverseproxy

import (
	"fmt"
	"net/http"
	"sync"

	"golang.org/x/crypto/acme/autocert"

	"github.com/netbirdio/netbird/proxy/internal/auth/oidc"
)

// Proxy wraps a reverse proxy with dynamic routing
type Proxy struct {
	config          Config
	mu              sync.RWMutex
	routes          map[string]*RouteConfig // key is host/domain (for fast O(1) lookup)
	server          *http.Server
	httpServer      *http.Server
	autocertManager *autocert.Manager
	isRunning       bool
	requestCallback RequestDataCallback
	oidcHandler     *oidc.Handler
}

// New creates a new reverse proxy
func New(config Config) (*Proxy, error) {
	// Set defaults
	if config.ListenAddress == "" {
		config.ListenAddress = ":443"
	}
	if config.HTTPListenAddress == "" {
		config.HTTPListenAddress = ":80"
	}
	if config.CertCacheDir == "" {
		config.CertCacheDir = "./certs"
	}

	// Validate HTTPS config
	if config.EnableHTTPS {
		if config.TLSEmail == "" {
			return nil, fmt.Errorf("TLSEmail is required when EnableHTTPS is true")
		}
	}

	// Set default OIDC session cookie name if not provided
	if config.OIDCConfig != nil && config.OIDCConfig.SessionCookieName == "" {
		config.OIDCConfig.SessionCookieName = "auth_session"
	}

	p := &Proxy{
		config:    config,
		routes:    make(map[string]*RouteConfig),
		isRunning: false,
	}

	// Initialize OIDC handler if OIDC is configured
	// The handler internally creates and manages its own state store
	if config.OIDCConfig != nil {
		stateStore := oidc.NewStateStore()
		p.oidcHandler = oidc.NewHandler(config.OIDCConfig, stateStore)
	}

	return p, nil
}

// SetRequestCallback sets the callback for request metrics
func (p *Proxy) SetRequestCallback(callback RequestDataCallback) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.requestCallback = callback
}

// GetConfig returns the proxy configuration
func (p *Proxy) GetConfig() Config {
	return p.config
}
