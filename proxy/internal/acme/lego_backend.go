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
//
// Per-issuance fields (DNS provider, account email, plaintext credentials)
// are NOT in this struct; they are passed to Issue per call. This lets
// the manager resolve credentials from the encrypted store at issuance
// time and apply rotation without restarting the proxy.
type LegoBackendConfig struct {
	// CertDir is the parent directory for cert storage. The backend
	// uses a `<CertDir>/lego` subdir to keep its files separate from
	// autocert's DirCache layout, allowing the two backends to coexist
	// during the autocert→Lego transition.
	CertDir string
	// Logger is optional; defaults to logrus.StandardLogger().
	Logger *log.Logger
}

// LegoBackend implements CertBackend using go-acme/lego with a DNS-01
// challenge solver.
//
// Issuance is eager-via-prefetch: the orchestrator (Manager) calls Issue
// with the resolved credentials. GetCertificate then serves the cached
// certificate. Unlike AutocertBackend, GetCertificate does NOT lazy-issue
// on cache miss — it returns an error so the TLS handshake fails fast.
// The asymmetry vs. autocert is deliberate: dns-01 issuance requires
// per-service credentials that aren't available in a TLS handshake.
type LegoBackend struct {
	cfg     LegoBackendConfig
	storage string
	logger  *log.Logger
}

// NewLegoBackend constructs a LegoBackend, validating its configuration
// and creating the storage subdir.
func NewLegoBackend(cfg LegoBackendConfig) (*LegoBackend, error) {
	if cfg.CertDir == "" {
		return nil, fmt.Errorf("cert dir is required")
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

// Issue obtains a fresh certificate via Lego DNS-01 with the given
// per-issuance credentials, persisting the cert and key under the
// backend's storage directory. Idempotent: if a valid cert already
// exists on disk, returns nil without re-issuing.
//
// A fresh legoclient.Client is constructed per call. ACME account state
// (account.key + account.json) is cached on disk in the storage dir,
// so re-registration is a no-op after the first call.
func (b *LegoBackend) Issue(ctx context.Context, domain, providerName, accountEmail, acmeDirectoryURL, plaintextSecret string) error {
	if domain == "" {
		return fmt.Errorf("domain is required")
	}
	if providerName == "" {
		return fmt.Errorf("provider name is required")
	}
	if accountEmail == "" {
		return fmt.Errorf("account email is required")
	}
	if acmeDirectoryURL == "" {
		return fmt.Errorf("ACME directory URL is required")
	}
	if plaintextSecret == "" {
		return fmt.Errorf("plaintext secret is required")
	}

	cli, err := legoclient.New(legoclient.Config{
		StorageDir:       b.storage,
		ACMEDirectoryURL: acmeDirectoryURL,
		AccountEmail:     accountEmail,
		DNSProvider:      providerName,
		DNSCredentials:   plaintextSecret,
		Logger:           b.logger,
	})
	if err != nil {
		return fmt.Errorf("build lego client: %w", err)
	}
	if err := cli.IssueCertificate(ctx, domain); err != nil {
		return fmt.Errorf("issue cert for %q: %w", domain, err)
	}
	return nil
}

// GetCertificate returns the cached certificate for hello.ServerName.
// Returns an error if no valid cert is on disk; this method does NOT
// trigger fresh issuance. Issuance flows exclusively through Issue
// (called by the manager's prefetch path with resolved credentials).
func (b *LegoBackend) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	host := hello.ServerName
	if host == "" {
		return nil, fmt.Errorf("missing SNI server name")
	}
	cert, err := b.loadCert(host)
	if err != nil {
		return nil, fmt.Errorf("no cached lego cert for %q (prefetch must run first): %w", host, err)
	}
	return cert, nil
}

// ReadCertFromDisk satisfies CertBackend by loading an already-issued
// cert from the on-disk cache. Used by the orchestrator's prefetch
// loop to detect when another replica has written the cert.
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
