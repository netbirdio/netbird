package acme

import (
	"context"
	"crypto/tls"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/proxy/internal/acme/legoclient"
	"github.com/netbirdio/netbird/proxy/internal/types"
	"github.com/netbirdio/netbird/shared/management/domain"
)

// LegoBackendConfig configures the spike-grade Lego backend.
//
// SPIKE NOTE: in production (p1-plan.md Wave 2), provider configuration
// will come from per-account encrypted credentials in the management
// server, not from a struct passed in at construction time. This shape
// exists only to demonstrate the architecture.
type LegoBackendConfig struct {
	// CertDir is the parent directory for cert storage. The backend uses a
	// `<CertDir>/lego` subdir to keep its files separate from autocert's
	// DirCache layout — both can coexist during the transition.
	CertDir string
	// ACMEDirectoryURL is the ACME directory URL.
	ACMEDirectoryURL string
	// AccountEmail is the ACME account email.
	AccountEmail string
	// CloudflareAPIToken is a scoped Cloudflare API token (Zone:DNS:Edit).
	CloudflareAPIToken string
}

// LegoBackend issues certificates via Lego using the DNS-01 challenge.
//
// SPIKE NOTE: this is a vertical-slice sketch. It compiles and demonstrates
// the architecture from p1-plan.md (task 2.2) but is NOT wired into the
// running Server. Production work will add: encrypted credential lookups
// via the management server, the existing distributed locker, per-service
// challenge-type selection, renewal lifecycle, observability, multi-replica
// coordination, and the rest of the Phase 1 surface.
type LegoBackend struct {
	cfg     LegoBackendConfig
	storage string
	mu      sync.Mutex
	domains map[domain.Domain]struct{}
	logger  *log.Logger
}

// NewLegoBackend constructs a LegoBackend. It creates the lego storage
// subdir if needed but does NOT register an ACME account or issue any
// certs eagerly — both happen lazily on first GetCertificate call.
func NewLegoBackend(cfg LegoBackendConfig, logger *log.Logger) (*LegoBackend, error) {
	if logger == nil {
		logger = log.StandardLogger()
	}
	storage := filepath.Join(cfg.CertDir, "lego")
	if err := os.MkdirAll(storage, 0o700); err != nil {
		return nil, fmt.Errorf("create lego storage dir %q: %w", storage, err)
	}
	return &LegoBackend{
		cfg:     cfg,
		storage: storage,
		domains: make(map[domain.Domain]struct{}),
		logger:  logger,
	}, nil
}

// GetCertificate satisfies CertBackend by loading from disk if present,
// or issuing via Lego if not. Single-process; no locking.
func (b *LegoBackend) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	host := hello.ServerName
	if host == "" {
		return nil, fmt.Errorf("missing SNI server name")
	}

	certPath := filepath.Join(b.storage, host+".crt")
	keyPath := filepath.Join(b.storage, host+".key")

	if cert, err := tls.LoadX509KeyPair(certPath, keyPath); err == nil {
		return &cert, nil
	}

	b.logger.Infof("[lego-backend] no cert on disk for %q, issuing via DNS-01", host)
	cli, err := legoclient.New(legoclient.Config{
		StorageDir:         b.storage,
		ACMEDirectoryURL:   b.cfg.ACMEDirectoryURL,
		AccountEmail:       b.cfg.AccountEmail,
		CloudflareAPIToken: b.cfg.CloudflareAPIToken,
		Logger:             b.logger,
	})
	if err != nil {
		return nil, fmt.Errorf("build lego client: %w", err)
	}
	if err := cli.IssueCertificate(context.Background(), host); err != nil {
		return nil, fmt.Errorf("issue cert for %q: %w", host, err)
	}
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, fmt.Errorf("reload cert from disk after issuance: %w", err)
	}
	return &cert, nil
}

// AddDomain satisfies CertBackend. The spike just records the domain;
// production would trigger background prefetch with locking.
func (b *LegoBackend) AddDomain(d domain.Domain, _ types.AccountID, _ types.ServiceID) (wildcardHit bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.domains[d] = struct{}{}
	return false
}

// RemoveDomain satisfies CertBackend.
func (b *LegoBackend) RemoveDomain(d domain.Domain) {
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.domains, d)
}

// Compile-time assertion that LegoBackend satisfies CertBackend.
var _ CertBackend = (*LegoBackend)(nil)
