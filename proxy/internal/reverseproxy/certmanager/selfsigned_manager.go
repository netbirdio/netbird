package certmanager

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net/http"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
)

// SelfSignedManager handles self-signed certificate generation for local testing
type SelfSignedManager struct {
	certificates map[string]*tls.Certificate // domain -> certificate cache
	mu           sync.RWMutex
}

// NewSelfSigned creates a new self-signed certificate manager
func NewSelfSigned() *SelfSignedManager {
	log.Info("Self-signed certificate manager initialized")
	return &SelfSignedManager{
		certificates: make(map[string]*tls.Certificate),
	}
}

// IsEnabled returns whether certificate management is enabled
func (m *SelfSignedManager) IsEnabled() bool {
	return true
}

// AddDomain adds a domain to the manager (no-op for self-signed, but maintains interface)
func (m *SelfSignedManager) AddDomain(domain string) {
	log.Infof("Added domain to self-signed manager: %s", domain)
}

// RemoveDomain removes a domain from the manager
func (m *SelfSignedManager) RemoveDomain(domain string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.certificates, domain)
	log.Infof("Removed domain from self-signed manager: %s", domain)
}

// IssueCertificate generates and caches a self-signed certificate for a domain
func (m *SelfSignedManager) IssueCertificate(ctx context.Context, domain string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.certificates[domain]; exists {
		log.Debugf("Self-signed certificate already exists for domain: %s", domain)
		return nil
	}

	cert, err := m.generateCertificate(domain)
	if err != nil {
		return err
	}

	m.certificates[domain] = cert

	return nil
}

// TLSConfig returns the TLS configuration for the HTTPS server
func (m *SelfSignedManager) TLSConfig() *tls.Config {
	return &tls.Config{
		GetCertificate: m.getCertificate,
	}
}

// HTTPHandler returns the fallback handler (no ACME challenges for self-signed)
func (m *SelfSignedManager) HTTPHandler(fallback http.Handler) http.Handler {
	return fallback
}

// getCertificate returns a self-signed certificate for the requested domain
func (m *SelfSignedManager) getCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	m.mu.RLock()
	cert, exists := m.certificates[hello.ServerName]
	m.mu.RUnlock()

	if exists {
		return cert, nil
	}

	log.Infof("Generating self-signed certificate on-demand for: %s", hello.ServerName)

	newCert, err := m.generateCertificate(hello.ServerName)
	if err != nil {
		return nil, err
	}

	m.mu.Lock()
	m.certificates[hello.ServerName] = newCert
	m.mu.Unlock()

	return newCert, nil
}

// generateCertificate generates a self-signed certificate for a domain
func (m *SelfSignedManager) generateCertificate(domain string) (*tls.Certificate, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate private key: %w", err)
	}

	notBefore := time.Now()
	notAfter := notBefore.Add(365 * 24 * time.Hour) // Valid for 1 year

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("failed to generate serial number: %w", err)
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"NetBird Local Development"},
			CommonName:   domain,
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{domain},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate: %w", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	tlsCert := &tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  priv,
		Leaf:        cert,
	}

	log.Infof("Generated self-signed certificate for domain: %s (expires: %s)",
		domain, cert.NotAfter.Format(time.RFC3339))

	return tlsCert, nil
}
