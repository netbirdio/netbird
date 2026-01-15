package reverseproxy

import (
	"context"
	"fmt"
	"net/http"

	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/acme/autocert"
)

// Start starts the reverse proxy server (non-blocking)
func (p *Proxy) Start() error {
	p.mu.Lock()
	if p.isRunning {
		p.mu.Unlock()
		return fmt.Errorf("reverse proxy already running")
	}
	p.isRunning = true
	p.mu.Unlock()

	// Build the main HTTP handler
	handler := p.buildHandler()

	if p.config.EnableHTTPS {
		return p.startHTTPS(handler)
	}

	return p.startHTTP(handler)
}

// startHTTPS starts the proxy with HTTPS and Let's Encrypt (non-blocking)
func (p *Proxy) startHTTPS(handler http.Handler) error {
	// Setup autocert manager with dynamic host policy
	p.autocertManager = &autocert.Manager{
		Prompt:      autocert.AcceptTOS,
		HostPolicy:  p.dynamicHostPolicy,
		Cache:       autocert.DirCache(p.config.CertCacheDir),
		Email:       p.config.TLSEmail,
		RenewBefore: 0, // Use default
	}

	// Start HTTP server for ACME challenges
	p.httpServer = &http.Server{
		Addr:    p.config.HTTPListenAddress,
		Handler: p.autocertManager.HTTPHandler(nil),
	}

	go func() {
		log.Infof("Starting HTTP server for ACME challenges on %s", p.config.HTTPListenAddress)
		if err := p.httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Errorf("HTTP server error: %v", err)
		}
	}()

	// Start HTTPS server in background
	p.server = &http.Server{
		Addr:      p.config.ListenAddress,
		Handler:   handler,
		TLSConfig: p.autocertManager.TLSConfig(),
	}

	go func() {
		log.Infof("Starting HTTPS reverse proxy server on %s", p.config.ListenAddress)
		if err := p.server.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
			log.Errorf("HTTPS server failed: %v", err)
		}
	}()

	return nil
}

// startHTTP starts the proxy with HTTP only (non-blocking)
func (p *Proxy) startHTTP(handler http.Handler) error {
	p.server = &http.Server{
		Addr:    p.config.HTTPListenAddress,
		Handler: handler,
	}

	go func() {
		log.Infof("Starting HTTP reverse proxy server on %s (HTTPS disabled)", p.config.HTTPListenAddress)
		if err := p.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Errorf("HTTP server failed: %w", err)
		}
	}()

	return nil
}

// dynamicHostPolicy validates that a requested host has a configured route
func (p *Proxy) dynamicHostPolicy(ctx context.Context, host string) error {
	p.mu.RLock()
	defer p.mu.RUnlock()

	// Check if we have a route for this host
	if _, exists := p.routes[host]; exists {
		log.Infof("ACME challenge accepted for configured host: %s", host)
		return nil
	}

	log.Warnf("ACME challenge rejected for unconfigured host: %s", host)
	return fmt.Errorf("host %s not configured", host)
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

	// Stop HTTP server (for ACME challenges)
	if p.httpServer != nil {
		if err := p.httpServer.Shutdown(ctx); err != nil {
			log.Errorf("Error shutting down HTTP server: %v", err)
		}
	}

	// Stop main server
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
