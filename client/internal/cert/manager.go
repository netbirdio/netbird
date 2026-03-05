package cert

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const (
	certFileName  = "cert.pem"
	keyFileName   = "key.pem"
	chainFileName = "chain.pem"
	caFileName    = "ca.pem"
)

// Manager handles client-side certificate lifecycle: key generation, CSR creation,
// certificate storage, and renewal detection.
type Manager struct {
	certDir string
	mu      sync.RWMutex
}

// NewManager creates a new certificate manager that stores files in certDir.
func NewManager(certDir string) (*Manager, error) {
	if err := os.MkdirAll(certDir, 0700); err != nil {
		return nil, fmt.Errorf("create cert directory: %w", err)
	}
	return &Manager{certDir: certDir}, nil
}

// GenerateKey creates a new ECDSA P-256 private key suitable for TLS certificates.
func (m *Manager) GenerateKey() (crypto.Signer, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate ECDSA key: %w", err)
	}
	return key, nil
}

// CreateCSR creates a DER-encoded certificate signing request for the given FQDN.
// If wildcard is true, a wildcard SAN (*.fqdn) is included alongside the base FQDN.
func (m *Manager) CreateCSR(key crypto.Signer, fqdn string, wildcard bool) ([]byte, error) {
	if fqdn == "" {
		return nil, fmt.Errorf("FQDN is required for CSR creation")
	}

	dnsNames := []string{fqdn}
	if wildcard {
		dnsNames = append(dnsNames, "*."+fqdn)
	}

	template := &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: fqdn},
		DNSNames: dnsNames,
	}

	csrDER, err := x509.CreateCertificateRequest(rand.Reader, template, key)
	if err != nil {
		return nil, fmt.Errorf("create CSR: %w", err)
	}
	return csrDER, nil
}

// StoreCert writes the leaf certificate, CA chain, and private key to disk.
// All three files are written to temp files first, then renamed atomically
// to avoid leaving inconsistent state on partial failure.
// The private key file is restricted to owner-only read/write (0600).
func (m *Manager) StoreCert(certPEM, chainPEM, keyPEM []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	type pendingFile struct {
		path string
		data []byte
		perm os.FileMode
	}
	files := []pendingFile{
		{filepath.Join(m.certDir, certFileName), certPEM, 0644},
		{filepath.Join(m.certDir, chainFileName), chainPEM, 0644},
		{filepath.Join(m.certDir, keyFileName), keyPEM, 0600},
	}

	// Phase 1: write all temp files
	var tmpPaths []string
	for _, f := range files {
		tmp := f.path + ".tmp"
		if err := os.WriteFile(tmp, f.data, f.perm); err != nil {
			// Clean up any temp files written so far
			for _, t := range tmpPaths {
				_ = os.Remove(t)
			}
			return fmt.Errorf("write %s: %w", filepath.Base(f.path), err)
		}
		tmpPaths = append(tmpPaths, tmp)
	}

	// Phase 2: rename all (atomic on most filesystems)
	for i, f := range files {
		if err := os.Rename(tmpPaths[i], f.path); err != nil {
			// Clean up the failed and remaining temp files
			for j := i; j < len(tmpPaths); j++ {
				_ = os.Remove(tmpPaths[j])
			}
			return fmt.Errorf("rename %s: %w", filepath.Base(f.path), err)
		}
	}

	return nil
}

// StoreCA writes the active CA certificates to disk, concatenated into a single file.
func (m *Manager) StoreCA(caPEMs [][]byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	var combined []byte
	for _, p := range caPEMs {
		combined = append(combined, p...)
		if len(p) > 0 && p[len(p)-1] != '\n' {
			combined = append(combined, '\n')
		}
	}

	return atomicWrite(filepath.Join(m.certDir, caFileName), combined, 0644)
}

// LoadCert reads and parses the stored leaf certificate.
func (m *Manager) LoadCert() (*x509.Certificate, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	return m.loadCert()
}

// HasCert returns true if a certificate file exists on disk.
func (m *Manager) HasCert() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()

	_, err := os.Stat(filepath.Join(m.certDir, certFileName))
	return err == nil
}

// NeedsRenewal returns true if the stored certificate expires within the given threshold,
// or if the certificate cannot be loaded.
func (m *Manager) NeedsRenewal(threshold time.Duration) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()

	cert, err := m.loadCert()
	if err != nil {
		return true
	}
	return time.Until(cert.NotAfter) < threshold
}

// IsExpired returns true if the stored certificate has expired.
func (m *Manager) IsExpired() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()

	cert, err := m.loadCert()
	if err != nil {
		return false
	}
	return time.Now().After(cert.NotAfter)
}

// FQDNChanged returns true if the stored certificate's primary DNS name
// differs from the given FQDN, indicating the peer was renamed.
func (m *Manager) FQDNChanged(currentFQDN string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()

	cert, err := m.loadCert()
	if err != nil {
		return false
	}
	if len(cert.DNSNames) == 0 {
		return true
	}
	for _, name := range cert.DNSNames {
		if name == currentFQDN {
			return false
		}
	}
	return true
}

// loadCert is the internal unlocked version of LoadCert. Callers must hold mu.
func (m *Manager) loadCert() (*x509.Certificate, error) {
	data, err := os.ReadFile(filepath.Join(m.certDir, certFileName))
	if err != nil {
		return nil, fmt.Errorf("read cert: %w", err)
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found in cert file")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse cert: %w", err)
	}
	return cert, nil
}

// CertPath returns the path to the leaf certificate file.
func (m *Manager) CertPath() string {
	return filepath.Join(m.certDir, certFileName)
}

// KeyPath returns the path to the private key file.
func (m *Manager) KeyPath() string {
	return filepath.Join(m.certDir, keyFileName)
}

// ChainPath returns the path to the CA chain file.
func (m *Manager) ChainPath() string {
	return filepath.Join(m.certDir, chainFileName)
}

// CAPath returns the path to the combined CA certificates file.
func (m *Manager) CAPath() string {
	return filepath.Join(m.certDir, caFileName)
}

// atomicWrite writes data to a temporary file and renames it to the target path.
func atomicWrite(path string, data []byte, perm os.FileMode) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, perm); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
