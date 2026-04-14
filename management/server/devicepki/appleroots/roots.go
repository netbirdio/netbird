// Package appleroots provides the Apple Root CA pool for Secure Enclave attestation
// certificate chain verification.
//
// When a CACertFile is configured the pool is loaded from disk. Otherwise the
// Apple Root CA G3 DER certificate is downloaded from Apple on first use and
// cached in memory for 24 hours; subsequent calls within the cache window return
// the cached pool without a network round-trip. If the download fails and a cache
// exists, the stale cache is returned with a warning log (fail-open for operational
// resilience). If no cache exists and the download fails, an error is returned
// (fail-closed for the initial startup case).
//
// # Production deployment note
//
// Apple's SecKeyCreateAttestation API returns only the leaf attestation certificate.
// The leaf is signed by an Apple Secure Key Attestation intermediate CA (not directly
// by the Apple Root CA G3). For chain verification to succeed, the operator must set
// IntermediateCACertFile to the path of the Apple Secure Key Attestation CA PEM file
// downloaded from https://www.apple.com/certificateauthority/.
//
// Verification will fail (not be skipped) when only the leaf is presented and no
// intermediate is configured — this is intentional fail-closed behaviour.
package appleroots

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"os"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
)

const (
	// appleRootCAURL is the DER-encoded Apple Root CA G3 download URL.
	appleRootCAURL    = "https://www.apple.com/certificateauthority/AppleRootCA-G3.cer"
	cacheRefreshEvery = 24 * time.Hour
)

// Config controls how the Apple Root CA pool is built.
type Config struct {
	// CACertFile is an optional path to a PEM-encoded root CA certificate file.
	// When non-empty, the file is used instead of downloading from Apple.
	// Useful for testing and air-gapped deployments.
	CACertFile string

	// IntermediateCACertFile is the path to a PEM-encoded Apple Secure Key
	// Attestation intermediate CA certificate. SecKeyCreateAttestation returns
	// only the leaf cert; the intermediate is needed for chain verification.
	//
	// Download from https://www.apple.com/certificateauthority/
	// (Apple Secure Key Attestation CA 1/3 or equivalent for your device family).
	//
	// When empty, LoadIntermediateCerts returns nil (no intermediates configured).
	// Verification will fail if the client sends only the leaf and no intermediate
	// is provided either via this field or as part of the attestation_pems chain.
	IntermediateCACertFile string
}

var (
	cachedPool  *x509.CertPool
	cacheExpiry time.Time
	cacheMu     sync.Mutex
)

// BuildAppleSERootPool returns an x509.CertPool for Apple Secure Enclave attestation
// chain verification.
//
// If cfg.CACertFile is set, the pool is loaded from that file (fails immediately if
// the file is unreadable or contains no valid PEM certificates).
// Otherwise, the Apple Root CA G3 DER certificate is downloaded and cached in memory.
func BuildAppleSERootPool(ctx context.Context, cfg Config) (*x509.CertPool, error) {
	if cfg.CACertFile != "" {
		return loadFromFile(cfg.CACertFile)
	}
	return loadFromApple(ctx)
}

// LoadIntermediateCerts loads Apple Secure Key Attestation intermediate CA
// certificates from the file specified by cfg.IntermediateCACertFile.
//
// Returns nil (not an error) when IntermediateCACertFile is empty — this indicates
// that no intermediates are configured; the caller may choose to allow verification
// to proceed without them (for testing) or return an error (production fail-closed).
//
// Returns a non-nil slice of parsed certificates when the file exists and contains
// valid PEM certificates.
func LoadIntermediateCerts(cfg Config) ([]*x509.Certificate, error) {
	if cfg.IntermediateCACertFile == "" {
		return nil, nil
	}
	data, err := os.ReadFile(cfg.IntermediateCACertFile)
	if err != nil {
		return nil, fmt.Errorf("appleroots: read intermediate CA file %q: %w", cfg.IntermediateCACertFile, err)
	}
	var certs []*x509.Certificate
	rest := data
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("appleroots: parse intermediate CA cert: %w", err)
		}
		certs = append(certs, cert)
	}
	if len(certs) == 0 {
		return nil, fmt.Errorf("appleroots: no valid certificates found in intermediate CA file %q", cfg.IntermediateCACertFile)
	}
	return certs, nil
}

func loadFromFile(path string) (*x509.CertPool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("appleroots: read CA file %q: %w", path, err)
	}
	return parsePEMPool(data)
}

func loadFromApple(ctx context.Context) (*x509.CertPool, error) {
	cacheMu.Lock()
	defer cacheMu.Unlock()

	if cachedPool != nil && time.Now().Before(cacheExpiry) {
		return cachedPool, nil
	}

	log.Info("appleroots: downloading Apple Root CA G3")
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, appleRootCAURL, nil)
	if err != nil {
		if cachedPool != nil {
			log.Warnf("appleroots: failed to create request, using cached pool: %v", err)
			return cachedPool, nil
		}
		return nil, fmt.Errorf("appleroots: create request: %w", err)
	}

	httpClient := &http.Client{Timeout: 15 * time.Second}
	resp, err := httpClient.Do(req)
	if err != nil {
		if cachedPool != nil {
			log.Warnf("appleroots: download failed, using cached pool: %v", err)
			return cachedPool, nil
		}
		return nil, fmt.Errorf("appleroots: download Apple Root CA: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		if cachedPool != nil {
			log.Warnf("appleroots: download failed (HTTP %d), using cached pool", resp.StatusCode)
			return cachedPool, nil
		}
		return nil, fmt.Errorf("appleroots: download Apple Root CA: HTTP %d", resp.StatusCode)
	}

	// Limit response body to 1 MiB to prevent memory exhaustion.
	der, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		if cachedPool != nil {
			log.Warnf("appleroots: read response failed, using cached pool: %v", err)
			return cachedPool, nil
		}
		return nil, fmt.Errorf("appleroots: read response: %w", err)
	}

	// Apple distributes the Root CA as raw DER; wrap it as PEM for x509.CertPool.
	pemData := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	pool, err := parsePEMPool(pemData)
	if err != nil {
		return nil, err
	}

	cachedPool = pool
	cacheExpiry = time.Now().Add(cacheRefreshEvery)
	log.Info("appleroots: Apple Root CA G3 cached successfully")
	return pool, nil
}

// parsePEMPool parses one or more PEM-encoded certificates and returns an x509.CertPool.
// Returns an error when no valid certificates are found.
func parsePEMPool(data []byte) (*x509.CertPool, error) {
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(data) {
		return nil, fmt.Errorf("appleroots: no valid certificates found in PEM data")
	}
	return pool, nil
}
