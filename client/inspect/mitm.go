package inspect

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	mrand "math/rand/v2"
	"sync"
	"time"
)

const (
	// certCacheSize is the maximum number of cached leaf certificates.
	certCacheSize = 1024
	// certTTL is how long generated certificates remain valid.
	certTTL = 24 * time.Hour
)

// certCache is a bounded LRU cache for generated TLS certificates.
type certCache struct {
	mu      sync.Mutex
	entries map[string]*certEntry
	// order tracks LRU eviction, most recent at end.
	order   []string
	maxSize int
}

type certEntry struct {
	cert      *tls.Certificate
	expiresAt time.Time
}

func newCertCache(maxSize int) *certCache {
	return &certCache{
		entries: make(map[string]*certEntry, maxSize),
		order:   make([]string, 0, maxSize),
		maxSize: maxSize,
	}
}

func (c *certCache) get(hostname string) (*tls.Certificate, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	entry, ok := c.entries[hostname]
	if !ok {
		return nil, false
	}

	if time.Now().After(entry.expiresAt) {
		c.removeLocked(hostname)
		return nil, false
	}

	// Move to end (most recently used)
	c.touchLocked(hostname)
	return entry.cert, true
}

func (c *certCache) put(hostname string, cert *tls.Certificate) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Jitter the TTL by +/- 20% to prevent thundering herd on expiry.
	jitter := time.Duration(float64(certTTL) * (0.8 + 0.4*mrand.Float64()))

	if _, exists := c.entries[hostname]; exists {
		c.entries[hostname] = &certEntry{
			cert:      cert,
			expiresAt: time.Now().Add(jitter),
		}
		c.touchLocked(hostname)
		return
	}

	// Evict oldest if at capacity
	for len(c.entries) >= c.maxSize && len(c.order) > 0 {
		c.removeLocked(c.order[0])
	}

	c.entries[hostname] = &certEntry{
		cert:      cert,
		expiresAt: time.Now().Add(jitter),
	}
	c.order = append(c.order, hostname)
}

func (c *certCache) touchLocked(hostname string) {
	for i, h := range c.order {
		if h == hostname {
			c.order = append(c.order[:i], c.order[i+1:]...)
			c.order = append(c.order, hostname)
			return
		}
	}
}

func (c *certCache) removeLocked(hostname string) {
	delete(c.entries, hostname)
	for i, h := range c.order {
		if h == hostname {
			c.order = append(c.order[:i], c.order[i+1:]...)
			return
		}
	}
}

// CertProvider generates TLS certificates on the fly, signed by a CA.
// Generated certificates are cached in an LRU cache.
type CertProvider struct {
	ca    *x509.Certificate
	caKey crypto.PrivateKey
	cache *certCache
}

// NewCertProvider creates a certificate provider using the given CA.
func NewCertProvider(ca *x509.Certificate, caKey crypto.PrivateKey) *CertProvider {
	return &CertProvider{
		ca:    ca,
		caKey: caKey,
		cache: newCertCache(certCacheSize),
	}
}

// GetCertificate returns a TLS certificate for the given hostname,
// generating and caching one if necessary.
func (p *CertProvider) GetCertificate(hostname string) (*tls.Certificate, error) {
	if cert, ok := p.cache.get(hostname); ok {
		return cert, nil
	}

	cert, err := p.generateCert(hostname)
	if err != nil {
		return nil, fmt.Errorf("generate cert for %s: %w", hostname, err)
	}

	p.cache.put(hostname, cert)
	return cert, nil
}

// GetTLSConfig returns a tls.Config that dynamically provides certificates
// for any hostname using the MITM CA.
func (p *CertProvider) GetTLSConfig() *tls.Config {
	return &tls.Config{
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			return p.GetCertificate(hello.ServerName)
		},
		NextProtos: []string{"h2", "http/1.1"},
		MinVersion: tls.VersionTLS12,
	}
}

func (p *CertProvider) generateCert(hostname string) (*tls.Certificate, error) {
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("generate serial number: %w", err)
	}

	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: hostname,
		},
		NotBefore: now.Add(-5 * time.Minute),
		NotAfter:  now.Add(certTTL),
		KeyUsage:  x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
		},
		DNSNames: []string{hostname},
	}

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate leaf key: %w", err)
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, p.ca, &leafKey.PublicKey, p.caKey)
	if err != nil {
		return nil, fmt.Errorf("sign leaf certificate: %w", err)
	}

	leafCert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("parse generated certificate: %w", err)
	}

	return &tls.Certificate{
		Certificate: [][]byte{certDER, p.ca.Raw},
		PrivateKey:  leafKey,
		Leaf:        leafCert,
	}, nil
}
