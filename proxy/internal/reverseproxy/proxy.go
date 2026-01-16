package reverseproxy

import (
	"context"
	"fmt"
	"net/http"
	"sync"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/proxy/internal/auth/oidc"
	"github.com/netbirdio/netbird/proxy/internal/reverseproxy/certmanager"
)

// Proxy wraps a reverse proxy with dynamic routing
type Proxy struct {
	config          Config
	mu              sync.RWMutex
	routes          map[string]*RouteConfig // key is host/domain (for fast O(1) lookup)
	server          *http.Server
	httpServer      *http.Server
	certManager     certmanager.Manager
	isRunning       bool
	requestCallback RequestDataCallback
	oidcHandler     *oidc.Handler
}

// New creates a new reverse proxy
func New(config Config) (*Proxy, error) {
	if config.ListenAddress == "" {
		config.ListenAddress = ":443"
	}
	if config.HTTPListenAddress == "" {
		config.HTTPListenAddress = ":80"
	}
	if config.CertCacheDir == "" {
		config.CertCacheDir = "./certs"
	}

	if config.CertMode == "" {
		config.CertMode = "letsencrypt"
	}

	if config.CertMode == "letsencrypt" && config.TLSEmail == "" {
		return nil, fmt.Errorf("TLSEmail is required for letsencrypt mode")
	}

	if config.OIDCConfig != nil && config.OIDCConfig.SessionCookieName == "" {
		config.OIDCConfig.SessionCookieName = "auth_session"
	}

	var certMgr certmanager.Manager
	if config.CertMode == "selfsigned" {
		// HTTPS with self-signed certificates (for local testing)
		certMgr = certmanager.NewSelfSigned()
	} else {
		// HTTPS with Let's Encrypt (for production)
		certMgr = certmanager.NewLetsEncrypt(certmanager.LetsEncryptConfig{
			Email:        config.TLSEmail,
			CertCacheDir: config.CertCacheDir,
		})
	}

	p := &Proxy{
		config:      config,
		routes:      make(map[string]*RouteConfig),
		certManager: certMgr,
		isRunning:   false,
	}

	if config.OIDCConfig != nil {
		stateStore := oidc.NewStateStore()
		p.oidcHandler = oidc.NewHandler(config.OIDCConfig, stateStore)
	}

	return p, nil
}

// Start starts the reverse proxy server (non-blocking)
func (p *Proxy) Start() error {
	p.mu.Lock()
	if p.isRunning {
		p.mu.Unlock()
		return fmt.Errorf("reverse proxy already running")
	}
	p.isRunning = true
	p.mu.Unlock()

	handler := p.buildHandler()

	return p.startHTTPS(handler)
}

// startHTTPS starts the proxy with HTTPS
func (p *Proxy) startHTTPS(handler http.Handler) error {
	p.httpServer = &http.Server{
		Addr:    p.config.HTTPListenAddress,
		Handler: p.certManager.HTTPHandler(nil),
	}

	go func() {
		log.Infof("Starting HTTP server on %s", p.config.HTTPListenAddress)
		if err := p.httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Errorf("HTTP server error: %v", err)
		}
	}()

	p.server = &http.Server{
		Addr:      p.config.ListenAddress,
		Handler:   handler,
		TLSConfig: p.certManager.TLSConfig(),
	}

	go func() {
		log.Infof("Starting HTTPS reverse proxy server on %s", p.config.ListenAddress)
		if err := p.server.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
			log.Errorf("HTTPS server failed: %v", err)
		}
	}()

	return nil
}

// Stop gracefully stops the reverse proxy server
func (p *Proxy) Stop(ctx context.Context) error {
	p.mu.Lock()
	if !p.isRunning {
		p.mu.Unlock()
		return fmt.Errorf("reverse proxy not running")
	}
	p.isRunning = false
	p.mu.Unlock()

	log.Info("Stopping reverse proxy server...")

	if p.httpServer != nil {
		if err := p.httpServer.Shutdown(ctx); err != nil {
			log.Errorf("Error shutting down HTTP server: %v", err)
		}
	}

	if p.server != nil {
		if err := p.server.Shutdown(ctx); err != nil {
			return fmt.Errorf("error shutting down server: %w", err)
		}
	}

	log.Info("Reverse proxy server stopped")
	return nil
}

// IsRunning returns whether the proxy is running
func (p *Proxy) IsRunning() bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.isRunning
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
