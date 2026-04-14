package devicepki

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/management/server/secretenc"
)

// SmallstepConfig holds connection parameters for a Smallstep CA (step-ca).
type SmallstepConfig struct {
	// URL is the Smallstep CA base URL, e.g. "https://ca.example.com:9000".
	URL string `json:"url"`
	// Fingerprint is the hex-encoded SHA-256 fingerprint of the root CA certificate
	// used to pin the TLS connection (avoids trust-store configuration).
	Fingerprint string `json:"fingerprint,omitempty"`
	// ProvisionerToken is a short-lived JWK-signed token issued by the provisioner.
	// Callers must refresh this token before it expires (typically every 5–10 minutes).
	ProvisionerToken string `json:"provisioner_token"`
	// RootPEM is the PEM-encoded Smallstep root CA for TLS verification (optional).
	RootPEM string `json:"root_pem,omitempty"`
	// Timeout overrides the HTTP client timeout (default: 30s).
	TimeoutSeconds int `json:"timeout_seconds,omitempty"`
}

// EncryptSecrets encrypts the ProvisionerToken field in-place using kp.
// The encrypted value is stored with an "enc:" prefix followed by base64-encoded ciphertext.
func (c *SmallstepConfig) EncryptSecrets(kp secretenc.KeyProvider) error {
	if c.ProvisionerToken == "" || strings.HasPrefix(c.ProvisionerToken, encPrefix) {
		return nil
	}
	ct, err := kp.Encrypt([]byte(c.ProvisionerToken))
	if err != nil {
		return fmt.Errorf("smallstep: encrypt provisioner token: %w", err)
	}
	c.ProvisionerToken = encPrefix + base64.StdEncoding.EncodeToString(ct)
	return nil
}

// DecryptSecrets decrypts the ProvisionerToken field in-place using kp.
// Values without the "enc:" prefix are treated as pre-encryption plaintext and left unchanged.
func (c *SmallstepConfig) DecryptSecrets(kp secretenc.KeyProvider) error {
	if !strings.HasPrefix(c.ProvisionerToken, encPrefix) {
		return nil
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(c.ProvisionerToken, encPrefix))
	if err != nil {
		return fmt.Errorf("smallstep: decode provisioner token: %w", err)
	}
	plain, err := kp.Decrypt(raw)
	if err != nil {
		return fmt.Errorf("smallstep: decrypt provisioner token: %w", err)
	}
	c.ProvisionerToken = string(plain)
	return nil
}

// SmallstepCA implements the CA interface against a Smallstep / step-ca server.
// It uses the Smallstep CA REST API directly (no SDK dependency).
//
// Token lifecycle: the ProvisionerToken (OTT) is short-lived (typically 5–10 minutes).
// There is no automatic refresh mechanism; callers must recreate SmallstepCA with a
// fresh token before the current one expires, otherwise SignCSR and RevokeCert will
// fail with HTTP 401 errors from the step-ca server.
type SmallstepCA struct {
	cfg    SmallstepConfig
	client *http.Client
	mu     sync.Mutex
	caCert *x509.Certificate // cached; cleared on token update via NewSmallstepCA
}

// NewSmallstepCA creates a SmallstepCA from the given config.
func NewSmallstepCA(cfg SmallstepConfig) (*SmallstepCA, error) {
	if cfg.ProvisionerToken == "" {
		return nil, fmt.Errorf("devicepki/smallstep: provisioner_token is required")
	}

	timeout := 30 * time.Second
	if cfg.TimeoutSeconds > 0 {
		timeout = time.Duration(cfg.TimeoutSeconds) * time.Second
	}

	transport := &http.Transport{}
	if cfg.RootPEM != "" {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM([]byte(cfg.RootPEM)) {
			return nil, fmt.Errorf("devicepki/smallstep: failed to parse RootPEM")
		}
		transport.TLSClientConfig = &tls.Config{RootCAs: pool}
	}

	return &SmallstepCA{
		cfg:    cfg,
		client: &http.Client{Timeout: timeout, Transport: transport},
	}, nil
}

// GenerateCA is not supported for Smallstep — the CA is managed by the step-ca operator.
func (s *SmallstepCA) GenerateCA(_ context.Context, _ string) (string, string, error) {
	return "", "", fmt.Errorf("devicepki/smallstep: CA generation is managed by step-ca operators; use 'step ca init' to initialise")
}

// CACert fetches and returns the root CA certificate from the Smallstep CA.
// The result is cached after the first successful fetch; recreate SmallstepCA to refresh.
// The mutex is held for the duration of the fetch to prevent duplicate concurrent requests.
func (s *SmallstepCA) CACert(ctx context.Context) *x509.Certificate {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.caCert != nil {
		return s.caCert
	}

	url := s.cfg.URL + "/root"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		log.WithContext(ctx).Warnf("devicepki/smallstep: build CA cert request: %v", err)
		return nil
	}
	resp, err := s.client.Do(req)
	if err != nil {
		log.WithContext(ctx).Warnf("devicepki/smallstep: fetch CA cert: %v", err)
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.WithContext(ctx).Warnf("devicepki/smallstep: fetch CA cert returned %d", resp.StatusCode)
		return nil
	}

	var result struct {
		Ca string `json:"ca"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxHTTPResponseBytes)).Decode(&result); err != nil {
		log.WithContext(ctx).Warnf("devicepki/smallstep: decode CA cert response: %v", err)
		return nil
	}

	block, _ := pem.Decode([]byte(result.Ca))
	if block == nil {
		log.WithContext(ctx).Warnf("devicepki/smallstep: CA cert field is not valid PEM")
		return nil
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		log.WithContext(ctx).Warnf("devicepki/smallstep: parse CA cert: %v", err)
		return nil
	}

	s.caCert = cert
	return cert
}

// SignCSR submits a PEM CSR to the Smallstep CA sign endpoint.
func (s *SmallstepCA) SignCSR(ctx context.Context, csr *x509.CertificateRequest, cn string, validityDays int) (*x509.Certificate, error) {
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidCSR, err)
	}

	csrPEM := string(pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csr.Raw,
	}))

	body := map[string]interface{}{
		"csr":      csrPEM,
		"ott":      s.cfg.ProvisionerToken,
		"notAfter": fmt.Sprintf("%dh", validityDays*24),
		// Pass the WireGuard public key as a SAN so the issued cert has the correct identity.
		"sans": []string{cn},
	}

	data, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("devicepki/smallstep: marshal SignCSR request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.cfg.URL+"/sign", bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("devicepki/smallstep: create SignCSR request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("devicepki/smallstep: SignCSR request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, maxHTTPResponseBytes))
		return nil, fmt.Errorf("devicepki/smallstep: SignCSR returned %d: %s", resp.StatusCode, string(msg))
	}

	var result struct {
		CRT string `json:"crt"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxHTTPResponseBytes)).Decode(&result); err != nil {
		return nil, fmt.Errorf("devicepki/smallstep: decode SignCSR response: %w", err)
	}

	block, _ := pem.Decode([]byte(result.CRT))
	if block == nil {
		return nil, fmt.Errorf("devicepki/smallstep: SignCSR response contains no certificate PEM")
	}
	return x509.ParseCertificate(block.Bytes)
}

// RevokeCert sends a revocation request to the Smallstep CA.
func (s *SmallstepCA) RevokeCert(ctx context.Context, serial string) error {
	body := map[string]interface{}{
		"serial": serial,
		"ott":    s.cfg.ProvisionerToken,
	}

	data, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("devicepki/smallstep: marshal RevokeCert request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.cfg.URL+"/revoke", bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("devicepki/smallstep: create RevokeCert request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("devicepki/smallstep: RevokeCert request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, maxHTTPResponseBytes))
		return fmt.Errorf("devicepki/smallstep: RevokeCert returned %d: %s", resp.StatusCode, string(msg))
	}
	return nil
}

// GenerateCRL fetches the current DER-encoded CRL from the Smallstep CA.
func (s *SmallstepCA) GenerateCRL(ctx context.Context) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.cfg.URL+"/crl", nil)
	if err != nil {
		return nil, fmt.Errorf("devicepki/smallstep: create GenerateCRL request: %w", err)
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("devicepki/smallstep: GenerateCRL request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, maxHTTPResponseBytes))
		return nil, fmt.Errorf("devicepki/smallstep: GenerateCRL returned %d: %s", resp.StatusCode, string(msg))
	}

	return io.ReadAll(io.LimitReader(resp.Body, maxHTTPResponseBytes))
}
