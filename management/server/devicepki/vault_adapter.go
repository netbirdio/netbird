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
	"regexp"
	"strings"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/management/server/secretenc"
)

// validPathComponent restricts Vault mount and role names to alphanumeric characters,
// hyphens, and underscores to prevent path traversal in URL construction.
var validPathComponent = regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)

// encPrefix is the sentinel prefix prepended to encrypted secret values.
// DecryptSecrets checks for this prefix to distinguish encrypted from plaintext data.
const encPrefix = "enc:"

// VaultConfig holds the connection parameters for HashiCorp Vault PKI.
type VaultConfig struct {
	// Address is the Vault server URL, e.g. "https://vault.example.com:8200".
	Address string `json:"address"`
	// Token is the Vault authentication token with PKI policy.
	// SECURITY: this token is encrypted at rest via EncryptSecrets before database storage.
	// Use short-lived tokens or Vault AppRole auth in production environments.
	Token string `json:"token"`
	// Mount is the PKI secrets engine mount path (default: "pki").
	Mount string `json:"mount"`
	// Role is the PKI role used to sign certificate requests.
	Role string `json:"role"`
	// Namespace is the Vault Enterprise namespace (optional).
	Namespace string `json:"namespace,omitempty"`
	// CACertPEM is the PEM-encoded CA certificate used to verify Vault's TLS (optional).
	CACertPEM string `json:"ca_cert_pem,omitempty"`
	// Timeout overrides the HTTP client timeout (default: 30s).
	TimeoutSeconds int `json:"timeout_seconds,omitempty"`
}

// EncryptSecrets encrypts the Token field in-place using kp.
// The encrypted value is stored with an "enc:" prefix followed by base64-encoded ciphertext.
func (c *VaultConfig) EncryptSecrets(kp secretenc.KeyProvider) error {
	if c.Token == "" || strings.HasPrefix(c.Token, encPrefix) {
		return nil
	}
	ct, err := kp.Encrypt([]byte(c.Token))
	if err != nil {
		return fmt.Errorf("vault: encrypt token: %w", err)
	}
	c.Token = encPrefix + base64.StdEncoding.EncodeToString(ct)
	return nil
}

// DecryptSecrets decrypts the Token field in-place using kp.
// Values without the "enc:" prefix are treated as pre-encryption plaintext and left unchanged.
func (c *VaultConfig) DecryptSecrets(kp secretenc.KeyProvider) error {
	if !strings.HasPrefix(c.Token, encPrefix) {
		return nil
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(c.Token, encPrefix))
	if err != nil {
		return fmt.Errorf("vault: decode token: %w", err)
	}
	plain, err := kp.Decrypt(raw)
	if err != nil {
		return fmt.Errorf("vault: decrypt token: %w", err)
	}
	c.Token = string(plain)
	return nil
}

// VaultCA implements the CA interface against HashiCorp Vault's PKI secrets engine.
// It uses the Vault HTTP API directly (no SDK dependency).
type VaultCA struct {
	cfg    VaultConfig
	client *http.Client
	mu     sync.Mutex
	caCert *x509.Certificate // cached; recreate VaultCA to refresh
}

// NewVaultCA creates a VaultCA from the given config.
func NewVaultCA(cfg VaultConfig) (*VaultCA, error) {
	if cfg.Role == "" {
		return nil, fmt.Errorf("devicepki/vault: role is required")
	}

	// Apply default mount path if not specified.
	if cfg.Mount == "" {
		cfg.Mount = "pki"
	}

	// Validate that Mount and Role contain only safe path characters to prevent
	// path traversal attacks when they are interpolated into Vault API URLs.
	if !validPathComponent.MatchString(cfg.Mount) {
		return nil, fmt.Errorf("devicepki/vault: mount contains invalid characters")
	}
	if !validPathComponent.MatchString(cfg.Role) {
		return nil, fmt.Errorf("devicepki/vault: role contains invalid characters")
	}

	timeout := 30 * time.Second
	if cfg.TimeoutSeconds > 0 {
		timeout = time.Duration(cfg.TimeoutSeconds) * time.Second
	}

	transport := &http.Transport{}
	if cfg.CACertPEM != "" {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM([]byte(cfg.CACertPEM)) {
			return nil, fmt.Errorf("devicepki/vault: failed to parse CACertPEM")
		}
		transport.TLSClientConfig = &tls.Config{RootCAs: pool}
	}

	return &VaultCA{
		cfg:    cfg,
		client: &http.Client{Timeout: timeout, Transport: transport},
	}, nil
}

// GenerateCA is not supported for Vault — the CA is managed by the Vault operator.
func (v *VaultCA) GenerateCA(_ context.Context, _ string) (string, string, error) {
	return "", "", fmt.Errorf("devicepki/vault: CA generation is managed by Vault operators; use Vault UI or CLI to initialise the PKI mount")
}

// CACert fetches and returns the CA certificate from Vault.
// The result is cached after the first successful fetch; recreate VaultCA to refresh.
// The mutex is held for the duration of the fetch to prevent duplicate concurrent requests.
func (v *VaultCA) CACert(ctx context.Context) *x509.Certificate {
	v.mu.Lock()
	defer v.mu.Unlock()

	if v.caCert != nil {
		return v.caCert
	}

	url := fmt.Sprintf("%s/v1/%s/ca/pem", v.cfg.Address, v.cfg.Mount)
	resp, err := v.doRequest(ctx, http.MethodGet, url, nil)
	if err != nil {
		log.WithContext(ctx).Warnf("devicepki/vault: fetch CA cert: %v", err)
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.WithContext(ctx).Warnf("devicepki/vault: fetch CA cert returned %d", resp.StatusCode)
		return nil
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxHTTPResponseBytes))
	if err != nil {
		log.WithContext(ctx).Warnf("devicepki/vault: read CA cert response: %v", err)
		return nil
	}

	block, _ := pem.Decode(body)
	if block == nil {
		log.WithContext(ctx).Warnf("devicepki/vault: CA cert response is not valid PEM")
		return nil
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		log.WithContext(ctx).Warnf("devicepki/vault: parse CA cert: %v", err)
		return nil
	}

	v.caCert = cert
	return cert
}

// SignCSR submits a PEM CSR to Vault's sign endpoint and returns the signed certificate.
func (v *VaultCA) SignCSR(ctx context.Context, csr *x509.CertificateRequest, cn string, validityDays int) (*x509.Certificate, error) {
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidCSR, err)
	}

	csrPEM := string(pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csr.Raw,
	}))

	body := map[string]interface{}{
		"csr":         csrPEM,
		"common_name": cn,
		"ttl":         fmt.Sprintf("%dh", validityDays*24),
	}

	url := fmt.Sprintf("%s/v1/%s/sign/%s", v.cfg.Address, v.cfg.Mount, v.cfg.Role)
	resp, err := v.doRequest(ctx, http.MethodPost, url, body)
	if err != nil {
		return nil, fmt.Errorf("devicepki/vault: SignCSR request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, maxHTTPResponseBytes))
		return nil, fmt.Errorf("devicepki/vault: SignCSR returned %d: %s", resp.StatusCode, string(msg))
	}

	var result struct {
		Data struct {
			Certificate string `json:"certificate"`
		} `json:"data"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxHTTPResponseBytes)).Decode(&result); err != nil {
		return nil, fmt.Errorf("devicepki/vault: decode SignCSR response: %w", err)
	}

	block, _ := pem.Decode([]byte(result.Data.Certificate))
	if block == nil {
		return nil, fmt.Errorf("devicepki/vault: SignCSR response contains no certificate PEM")
	}
	return x509.ParseCertificate(block.Bytes)
}

// RevokeCert submits a revocation request to Vault for the given decimal serial.
func (v *VaultCA) RevokeCert(ctx context.Context, serial string) error {
	body := map[string]interface{}{"serial_number": serial}

	url := fmt.Sprintf("%s/v1/%s/revoke", v.cfg.Address, v.cfg.Mount)
	resp, err := v.doRequest(ctx, http.MethodPost, url, body)
	if err != nil {
		return fmt.Errorf("devicepki/vault: RevokeCert request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, maxHTTPResponseBytes))
		return fmt.Errorf("devicepki/vault: RevokeCert returned %d: %s", resp.StatusCode, string(msg))
	}
	return nil
}

// GenerateCRL fetches the current DER-encoded CRL from Vault.
func (v *VaultCA) GenerateCRL(ctx context.Context) ([]byte, error) {
	url := fmt.Sprintf("%s/v1/%s/crl", v.cfg.Address, v.cfg.Mount)
	resp, err := v.doRequest(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("devicepki/vault: GenerateCRL request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, maxHTTPResponseBytes))
		return nil, fmt.Errorf("devicepki/vault: GenerateCRL returned %d: %s", resp.StatusCode, string(msg))
	}

	return io.ReadAll(io.LimitReader(resp.Body, maxHTTPResponseBytes))
}

// doRequest executes an authenticated Vault API request.
func (v *VaultCA) doRequest(ctx context.Context, method, url string, body interface{}) (*http.Response, error) {
	var reqBody io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		reqBody = bytes.NewReader(data)
	}

	req, err := http.NewRequestWithContext(ctx, method, url, reqBody)
	if err != nil {
		return nil, err
	}

	req.Header.Set("X-Vault-Token", v.cfg.Token)
	if v.cfg.Namespace != "" {
		req.Header.Set("X-Vault-Namespace", v.cfg.Namespace)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	return v.client.Do(req)
}
