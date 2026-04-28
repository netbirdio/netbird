package acme

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"path/filepath"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/proxy/internal/acme/legoclient"
)

// LegoBackendConfig configures a LegoBackend.
type LegoBackendConfig struct {
	// CertDir is the parent directory for cert storage. The backend
	// uses a `<CertDir>/lego` subdir to keep its files separate from
	// autocert's DirCache layout, allowing the two backends to coexist
	// during the autocert→Lego transition.
	CertDir string
	// ACMEDirectoryURL is the ACME directory URL.
	ACMEDirectoryURL string
	// AccountEmail is the ACME account email (Lego requires one).
	AccountEmail string
	// DNSProvider names the DNS-01 provider (e.g., "cloudflare").
	DNSProvider string
	// DNSCredentials is the provider-specific credential string.
	DNSCredentials string
	// Logger is optional; defaults to logrus.StandardLogger().
	Logger *log.Logger
}

// LegoBackend implements CertBackend using go-acme/lego with a DNS-01
// challenge solver. Issuance is lazy: GetCertificate loads from the
// on-disk cache when present, otherwise calls Lego to obtain a fresh
// cert and persists it before returning.
type LegoBackend struct {
	cfg     LegoBackendConfig
	storage string
	logger  *log.Logger
}

// NewLegoBackend constructs a LegoBackend, validating its configuration
// and creating the storage subdir. It does NOT register an ACME account
// or invoke Lego eagerly — both happen lazily on the first
// GetCertificate call for a domain not already cached on disk.
func NewLegoBackend(cfg LegoBackendConfig) (*LegoBackend, error) {
	if cfg.CertDir == "" {
		return nil, fmt.Errorf("cert dir is required")
	}
	if cfg.ACMEDirectoryURL == "" {
		return nil, fmt.Errorf("ACME directory URL is required")
	}
	if cfg.AccountEmail == "" {
		return nil, fmt.Errorf("account email is required")
	}
	if cfg.DNSProvider == "" {
		return nil, fmt.Errorf("DNS provider is required")
	}
	if cfg.DNSCredentials == "" {
		return nil, fmt.Errorf("DNS credentials are required")
	}
	logger := cfg.Logger
	if logger == nil {
		logger = log.StandardLogger()
	}
	storage := filepath.Join(cfg.CertDir, "lego")
	if err := os.MkdirAll(storage, 0o700); err != nil {
		return nil, fmt.Errorf("create lego storage dir %q: %w", storage, err)
	}
	return &LegoBackend{cfg: cfg, storage: storage, logger: logger}, nil
}

// GetCertificate returns the TLS certificate for hello.ServerName,
// loading from the on-disk cache if present or issuing fresh via Lego
// if not. The orchestrator (Manager) wraps calls in its distributed
// lock to prevent duplicate issuance across replicas.
func (b *LegoBackend) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	host := hello.ServerName
	if host == "" {
		return nil, fmt.Errorf("missing SNI server name")
	}
	if cert, err := b.loadCert(host); err == nil {
		return cert, nil
	}

	b.logger.Infof("[lego-backend] no cached cert for %q, issuing via DNS-01", host)
	cli, err := legoclient.New(legoclient.Config{
		StorageDir:       b.storage,
		ACMEDirectoryURL: b.cfg.ACMEDirectoryURL,
		AccountEmail:     b.cfg.AccountEmail,
		DNSProvider:      b.cfg.DNSProvider,
		DNSCredentials:   b.cfg.DNSCredentials,
		Logger:           b.logger,
	})
	if err != nil {
		return nil, fmt.Errorf("build lego client: %w", err)
	}
	if err := cli.IssueCertificate(context.Background(), host); err != nil {
		return nil, fmt.Errorf("issue cert for %q: %w", host, err)
	}
	cert, err := b.loadCert(host)
	if err != nil {
		return nil, fmt.Errorf("reload cert from disk after issuance: %w", err)
	}
	return cert, nil
}

// ReadCertFromDisk satisfies CertBackend by loading an already-issued
// cert from the on-disk cache without invoking Lego. Used by the
// orchestrator's prefetch loop to detect when another replica has
// written the cert.
func (b *LegoBackend) ReadCertFromDisk(_ context.Context, name string) (*tls.Certificate, error) {
	return b.loadCert(name)
}

// DeleteCert satisfies CertBackend by removing the cached cert chain
// and key. Idempotent: missing files are not an error.
func (b *LegoBackend) DeleteCert(_ context.Context, name string) error {
	certPath := filepath.Join(b.storage, name+".crt")
	keyPath := filepath.Join(b.storage, name+".key")
	for _, path := range []string{certPath, keyPath} {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("delete %q: %w", path, err)
		}
	}
	return nil
}

// loadCert reads and validates the cert + key pair for the given host.
// Returns an error if either file is missing, if the pair fails to
// parse, or if the leaf has expired.
func (b *LegoBackend) loadCert(host string) (*tls.Certificate, error) {
	certPath := filepath.Join(b.storage, host+".crt")
	keyPath := filepath.Join(b.storage, host+".key")

	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, err
	}
	if len(cert.Certificate) > 0 {
		leaf, err := x509.ParseCertificate(cert.Certificate[0])
		if err != nil {
			return nil, fmt.Errorf("parse leaf for %q: %w", host, err)
		}
		if time.Now().After(leaf.NotAfter) {
			return nil, fmt.Errorf("cached certificate for %q expired at %s", host, leaf.NotAfter)
		}
		cert.Leaf = leaf
	}
	return &cert, nil
}

// Compile-time assertion that LegoBackend satisfies CertBackend.
var _ CertBackend = (*LegoBackend)(nil)
