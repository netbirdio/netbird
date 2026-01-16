package certmanager

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/acme/autocert"
)

// LetsEncryptManager handles TLS certificate issuance via Let's Encrypt
type LetsEncryptManager struct {
	autocertManager *autocert.Manager
	allowedHosts    map[string]bool
	mu              sync.RWMutex
}

// LetsEncryptConfig holds Let's Encrypt certificate manager configuration
type LetsEncryptConfig struct {
	// Email for Let's Encrypt registration (required)
	Email string

	// CertCacheDir is the directory to cache certificates
	CertCacheDir string
}

// NewLetsEncrypt creates a new Let's Encrypt certificate manager
func NewLetsEncrypt(config LetsEncryptConfig) *LetsEncryptManager {
	m := &LetsEncryptManager{
		allowedHosts: make(map[string]bool),
	}

	m.autocertManager = &autocert.Manager{
		Prompt:      autocert.AcceptTOS,
		HostPolicy:  m.hostPolicy,
		Cache:       autocert.DirCache(config.CertCacheDir),
		Email:       config.Email,
		RenewBefore: 0, // Use default 30 days prior to expiration
	}

	log.Info("Let's Encrypt certificate manager initialized")
	return m
}

// IsEnabled returns whether certificate management is enabled
func (m *LetsEncryptManager) IsEnabled() bool {
	return true
}

// AddDomain adds a domain to the allowed hosts list
func (m *LetsEncryptManager) AddDomain(domain string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.allowedHosts[domain] = true
	log.Infof("Added domain to Let's Encrypt manager: %s", domain)
}

// RemoveDomain removes a domain from the allowed hosts list
func (m *LetsEncryptManager) RemoveDomain(domain string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.allowedHosts, domain)
	log.Infof("Removed domain from Let's Encrypt manager: %s", domain)
}

// IssueCertificate eagerly issues a Let's Encrypt certificate for a domain
func (m *LetsEncryptManager) IssueCertificate(ctx context.Context, domain string) error {
	log.Infof("Issuing Let's Encrypt certificate for domain: %s", domain)

	hello := &tls.ClientHelloInfo{
		ServerName: domain,
	}

	cert, err := m.autocertManager.GetCertificate(hello)
	if err != nil {
		return fmt.Errorf("failed to issue certificate for domain %s: %w", domain, err)
	}

	log.Infof("Successfully issued Let's Encrypt certificate for domain: %s (expires: %s)",
		domain, cert.Leaf.NotAfter.Format(time.RFC3339))

	return nil
}

// TLSConfig returns the TLS configuration for the HTTPS server
func (m *LetsEncryptManager) TLSConfig() *tls.Config {
	return m.autocertManager.TLSConfig()
}

// HTTPHandler returns the HTTP handler for ACME challenges
func (m *LetsEncryptManager) HTTPHandler(fallback http.Handler) http.Handler {
	return m.autocertManager.HTTPHandler(fallback)
}

// hostPolicy validates that a requested host is in the allowed hosts list
func (m *LetsEncryptManager) hostPolicy(ctx context.Context, host string) error {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.allowedHosts[host] {
		log.Debugf("ACME challenge accepted for domain: %s", host)
		return nil
	}

	log.Warnf("ACME challenge rejected for unconfigured domain: %s", host)
	return fmt.Errorf("host %s not configured", host)
}
