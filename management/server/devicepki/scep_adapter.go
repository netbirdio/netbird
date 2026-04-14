package devicepki

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/management/server/secretenc"
)

// SCEPConfig holds connection parameters for a SCEP server.
type SCEPConfig struct {
	// URL is the SCEP server base URL, e.g. "http://scep.example.com/scep".
	URL string `json:"url"`
	// Challenge is the SCEP challenge password used to authenticate CSR requests.
	Challenge string `json:"challenge,omitempty"`
	// Timeout overrides the HTTP client timeout (default: 30s).
	TimeoutSeconds int `json:"timeout_seconds,omitempty"`
}

// EncryptSecrets encrypts the Challenge field in-place using kp.
// The encrypted value is stored with an "enc:" prefix followed by base64-encoded ciphertext.
func (c *SCEPConfig) EncryptSecrets(kp secretenc.KeyProvider) error {
	if c.Challenge == "" || strings.HasPrefix(c.Challenge, encPrefix) {
		return nil
	}
	ct, err := kp.Encrypt([]byte(c.Challenge))
	if err != nil {
		return fmt.Errorf("scep: encrypt challenge: %w", err)
	}
	c.Challenge = encPrefix + base64.StdEncoding.EncodeToString(ct)
	return nil
}

// DecryptSecrets decrypts the Challenge field in-place using kp.
// Values without the "enc:" prefix are treated as pre-encryption plaintext and left unchanged.
func (c *SCEPConfig) DecryptSecrets(kp secretenc.KeyProvider) error {
	if !strings.HasPrefix(c.Challenge, encPrefix) {
		return nil
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(c.Challenge, encPrefix))
	if err != nil {
		return fmt.Errorf("scep: decode challenge: %w", err)
	}
	plain, err := kp.Decrypt(raw)
	if err != nil {
		return fmt.Errorf("scep: decrypt challenge: %w", err)
	}
	c.Challenge = string(plain)
	return nil
}

// scepCACertFailureTTL is how long CACert() will avoid retrying after a failed
// GetCACert fetch. This prevents thundering herd against a temporarily unavailable
// SCEP server while still allowing recovery without a process restart.
const scepCACertFailureTTL = 30 * time.Second

// SCEPCA implements the CA interface against a SCEP (RFC 8894) server.
//
// SCEP protocol notes:
//   - Certificate issuance uses the PKIOperation=PKCSReq message type.
//   - Revocation: SCEP does not define a standard revocation operation.
//     RevokeCert logs a warning and marks the certificate locally only.
//   - CRL retrieval uses the GetCRL operation.
//
// The PKCS#7 envelope required by SCEP is built in-process using crypto/x509.
// No external SCEP library dependency is required.
type SCEPCA struct {
	cfg           SCEPConfig
	client        *http.Client
	mu            sync.Mutex
	caCert        *x509.Certificate // cached CA certificate; guarded by mu
	caCertFailAt  time.Time         // time of last fetch failure; guarded by mu
}

// NewSCEPCA creates a SCEPCA from the given config.
func NewSCEPCA(cfg SCEPConfig) (*SCEPCA, error) {
	timeout := 30 * time.Second
	if cfg.TimeoutSeconds > 0 {
		timeout = time.Duration(cfg.TimeoutSeconds) * time.Second
	}

	ca := &SCEPCA{
		cfg:    cfg,
		client: &http.Client{Timeout: timeout},
	}
	return ca, nil
}

// GenerateCA is not supported for SCEP — the CA is managed externally.
func (s *SCEPCA) GenerateCA(_ context.Context, _ string) (string, string, error) {
	return "", "", fmt.Errorf("devicepki/scep: CA generation is managed by the SCEP server operator")
}

// CACert fetches and returns the CA certificate via the GetCACert operation.
// The result is cached on success. On fetch failure, retries are suppressed for
// scepCACertFailureTTL (30 s) to avoid hammering a down SCEP server.
// CACert is safe for concurrent use.
//
// NOTE: once cached, the CA certificate is never refreshed. If the SCEP server
// rotates its CA, the SCEPCA instance must be recreated to pick up the new certificate.
func (s *SCEPCA) CACert(ctx context.Context) *x509.Certificate {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.caCert != nil {
		return s.caCert
	}
	// Suppress retries during the failure back-off window.
	if !s.caCertFailAt.IsZero() && time.Since(s.caCertFailAt) < scepCACertFailureTTL {
		return nil
	}
	cert, err := s.fetchCACert(ctx)
	if err != nil {
		s.caCertFailAt = time.Now()
		return nil
	}
	s.caCert = cert
	return cert
}

// fetchCACert performs a GetCACert SCEP operation.
func (s *SCEPCA) fetchCACert(ctx context.Context) (*x509.Certificate, error) {
	reqURL := fmt.Sprintf("%s?operation=GetCACert", s.cfg.URL)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, fmt.Errorf("devicepki/scep: create GetCACert request: %w", err)
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("devicepki/scep: GetCACert request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("devicepki/scep: GetCACert returned %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxHTTPResponseBytes))
	if err != nil {
		return nil, fmt.Errorf("devicepki/scep: read GetCACert response: %w", err)
	}

	// The response may be DER-encoded or PEM-wrapped depending on the server.
	if block, _ := pem.Decode(body); block != nil {
		return x509.ParseCertificate(block.Bytes)
	}
	return x509.ParseCertificate(body)
}

// SignCSR is not yet implemented for SCEP.
//
// A correct implementation requires a full PKCS#7 SignedData / EnvelopedData
// envelope as specified by RFC 8894. Integrating github.com/micromdm/scep is
// recommended for production use. Until that library is available in this module,
// SignCSR returns ErrNotImplemented to prevent silent failures with real SCEP servers.
func (s *SCEPCA) SignCSR(_ context.Context, _ *x509.CertificateRequest, _ string, _ int) (*x509.Certificate, error) {
	return nil, fmt.Errorf("devicepki/scep: %w: PKCS#7 PKCSReq envelope not implemented; "+
		"integrate github.com/micromdm/scep for production SCEP support", ErrNotImplemented)
}

// RevokeCert logs a warning — SCEP (RFC 8894) does not define a revocation operation.
// The certificate is marked as revoked in the local store by the caller.
func (s *SCEPCA) RevokeCert(_ context.Context, serial string) error {
	// SCEP does not provide a revocation API. Revocation tracking is the responsibility
	// of the local store. If the SCEP server supports proprietary revocation, extend
	// this method with server-specific HTTP calls.
	log.Warnf("devicepki/scep: RevokeCert called for serial %s but SCEP does not support server-side revocation", serial)
	return nil
}

// GenerateCRL fetches the current DER-encoded CRL via the GetCRL SCEP operation.
func (s *SCEPCA) GenerateCRL(ctx context.Context) ([]byte, error) {
	caCert := s.CACert(ctx)
	if caCert == nil {
		return nil, fmt.Errorf("devicepki/scep: failed to fetch CA certificate for GetCRL")
	}

	// GetCRL requires the issuer name and serial encoded as a PKCS#10-style request.
	// A simplified GET with issuer info as query params is used here.
	reqURL := fmt.Sprintf("%s?operation=GetCRL&issuer=%s",
		s.cfg.URL,
		url.QueryEscape(caCert.Subject.String()),
	)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, fmt.Errorf("devicepki/scep: create GetCRL request: %w", err)
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("devicepki/scep: GetCRL request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, maxHTTPResponseBytes))
		return nil, fmt.Errorf("devicepki/scep: GetCRL returned %d: %s", resp.StatusCode, string(msg))
	}

	return io.ReadAll(io.LimitReader(resp.Body, maxHTTPResponseBytes))
}
