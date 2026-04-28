package acme

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
)

// AutocertBackendConfig configures the autocert-based CertBackend.
type AutocertBackendConfig struct {
	// CertDir is the directory used by autocert.DirCache for issued certs
	// and account state.
	CertDir string
	// ACMEURL is the ACME directory URL (e.g. Let's Encrypt production
	// or staging).
	ACMEURL string
	// EABKID and EABHMACKey are optional External Account Binding
	// credentials required by some CAs (e.g. ZeroSSL). EABHMACKey is the
	// base64 URL-encoded string provided by the CA.
	EABKID     string
	EABHMACKey string
	// Logger is optional; defaults to logrus.StandardLogger().
	Logger *log.Logger
}

// AutocertBackend implements CertBackend using golang.org/x/crypto/acme/autocert.
// It supports the tls-alpn-01 and http-01 challenge types via the methods
// inherited from autocert.Manager (TLSConfig, HTTPHandler).
type AutocertBackend struct {
	manager *autocert.Manager
	logger  *log.Logger
}

// NewAutocertBackend constructs an AutocertBackend with the given configuration.
// The HostPolicy is left unset; the orchestrator should install one via
// SetHostPolicy after construction.
func NewAutocertBackend(cfg AutocertBackendConfig) (*AutocertBackend, error) {
	logger := cfg.Logger
	if logger == nil {
		logger = log.StandardLogger()
	}

	var eab *acme.ExternalAccountBinding
	if cfg.EABKID != "" && cfg.EABHMACKey != "" {
		decodedKey, err := base64.RawURLEncoding.DecodeString(cfg.EABHMACKey)
		if err != nil {
			return nil, fmt.Errorf("decode EAB HMAC key: %w", err)
		}
		eab = &acme.ExternalAccountBinding{
			KID: cfg.EABKID,
			Key: decodedKey,
		}
		logger.Infof("configured External Account Binding with KID: %s", cfg.EABKID)
	}

	mgr := &autocert.Manager{
		Prompt:                 autocert.AcceptTOS,
		Cache:                  autocert.DirCache(cfg.CertDir),
		ExternalAccountBinding: eab,
		Client: &acme.Client{
			DirectoryURL: cfg.ACMEURL,
		},
	}

	return &AutocertBackend{manager: mgr, logger: logger}, nil
}

// GetCertificate satisfies CertBackend by delegating to the underlying
// autocert.Manager. Issuance is lazy: if no cert exists for hello.ServerName,
// autocert performs the configured ACME challenge and persists the cert
// before returning it.
func (b *AutocertBackend) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	return b.manager.GetCertificate(hello)
}

// ReadCertFromDisk satisfies CertBackend by reading directly from the
// autocert DirCache, bypassing autocert's internal certState mutex. Safe to
// call concurrently with an in-flight ACME request for the same domain.
func (b *AutocertBackend) ReadCertFromDisk(ctx context.Context, name string) (*tls.Certificate, error) {
	if b.manager.Cache == nil {
		return nil, fmt.Errorf("no cache configured")
	}
	data, err := b.manager.Cache.Get(ctx, name)
	if err != nil {
		return nil, err
	}
	privBlock, certsPEM := pem.Decode(data)
	if privBlock == nil || !strings.Contains(privBlock.Type, "PRIVATE") {
		return nil, fmt.Errorf("no private key in cache for %q", name)
	}
	cert, err := tls.X509KeyPair(certsPEM, pem.EncodeToMemory(privBlock))
	if err != nil {
		return nil, fmt.Errorf("parse cached certificate for %q: %w", name, err)
	}
	if len(cert.Certificate) > 0 {
		leaf, err := x509.ParseCertificate(cert.Certificate[0])
		if err != nil {
			return nil, fmt.Errorf("parse leaf for %q: %w", name, err)
		}
		if time.Now().After(leaf.NotAfter) {
			return nil, fmt.Errorf("cached certificate for %q expired at %s", name, leaf.NotAfter)
		}
		cert.Leaf = leaf
	}
	return &cert, nil
}

// SetHostPolicy satisfies HostPolicySetter so the orchestrator can install
// a domain-registration check that runs before issuance.
func (b *AutocertBackend) SetHostPolicy(fn func(ctx context.Context, host string) error) {
	b.manager.HostPolicy = autocert.HostPolicy(fn)
}

// DeleteCert satisfies CertBackend by removing the cached certificate
// from autocert's DirCache. Idempotent: missing entries are not an error.
func (b *AutocertBackend) DeleteCert(ctx context.Context, name string) error {
	if b.manager.Cache == nil {
		return nil
	}
	if err := b.manager.Cache.Delete(ctx, name); err != nil && !errors.Is(err, autocert.ErrCacheMiss) {
		return fmt.Errorf("delete autocert cert %q: %w", name, err)
	}
	return nil
}

// HTTPHandler returns the http-01 challenge handler. Used by the proxy
// server when configured for the http-01 challenge type to serve challenge
// responses on port 80.
func (b *AutocertBackend) HTTPHandler(fallback http.Handler) http.Handler {
	return b.manager.HTTPHandler(fallback)
}

// TLSConfig returns a TLS config wired to the underlying autocert.Manager,
// including NextProtos for the tls-alpn-01 challenge. The orchestrator
// typically overrides GetCertificate on this config to install its
// wildcard-aware version.
func (b *AutocertBackend) TLSConfig() *tls.Config {
	return b.manager.TLSConfig()
}

// Compile-time assertions.
var (
	_ CertBackend      = (*AutocertBackend)(nil)
	_ HostPolicySetter = (*AutocertBackend)(nil)
)
