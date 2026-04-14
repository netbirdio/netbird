package deviceinventory

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/netbirdio/netbird/management/server/secretenc"
)

// JamfConfig holds credentials and parameters for the Jamf Pro REST API.
type JamfConfig struct {
	// URL is the Jamf Pro base URL, e.g. "https://company.jamfcloud.com".
	URL string `json:"url"`
	// ClientID is the Jamf Pro API client ID (OAuth 2.0 client credentials).
	ClientID string `json:"client_id"`
	// ClientSecret is the Jamf Pro API client secret.
	ClientSecret string `json:"client_secret"`
	// Timeout overrides the HTTP client timeout (default: 10s).
	TimeoutSeconds int `json:"timeout_seconds,omitempty"`
}

// EncryptSecrets encrypts the ClientSecret field in-place using kp.
// The encrypted value is stored with an "enc:" prefix followed by base64-encoded ciphertext.
func (c *JamfConfig) EncryptSecrets(kp secretenc.KeyProvider) error {
	if c.ClientSecret == "" || strings.HasPrefix(c.ClientSecret, encPrefix) {
		return nil
	}
	ct, err := kp.Encrypt([]byte(c.ClientSecret))
	if err != nil {
		return fmt.Errorf("jamf: encrypt client secret: %w", err)
	}
	c.ClientSecret = encPrefix + base64.StdEncoding.EncodeToString(ct)
	return nil
}

// DecryptSecrets decrypts the ClientSecret field in-place using kp.
// Values without the "enc:" prefix are treated as pre-encryption plaintext and left unchanged.
func (c *JamfConfig) DecryptSecrets(kp secretenc.KeyProvider) error {
	if !strings.HasPrefix(c.ClientSecret, encPrefix) {
		return nil
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(c.ClientSecret, encPrefix))
	if err != nil {
		return fmt.Errorf("jamf: decode client secret: %w", err)
	}
	plain, err := kp.Decrypt(raw)
	if err != nil {
		return fmt.Errorf("jamf: decrypt client secret: %w", err)
	}
	c.ClientSecret = string(plain)
	return nil
}

// JamfInventory checks device registration against Jamf Pro via its REST API
// (/api/v1/computers-inventory).
//
// Authentication uses Jamf Pro's OAuth 2.0 client credentials flow.
type JamfInventory struct {
	cfg         JamfConfig
	client      *http.Client
	mu          sync.Mutex
	accessToken string
	tokenExpiry time.Time
}

// NewJamfInventory parses a JSON config blob and returns a JamfInventory.
func NewJamfInventory(configJSON string) (*JamfInventory, error) {
	var cfg JamfConfig
	if err := json.Unmarshal([]byte(configJSON), &cfg); err != nil {
		return nil, fmt.Errorf("deviceinventory/jamf: parse config: %w", err)
	}
	if cfg.URL == "" || cfg.ClientID == "" || cfg.ClientSecret == "" {
		return nil, fmt.Errorf("deviceinventory/jamf: url, client_id, and client_secret are required")
	}

	timeout := 10 * time.Second
	if cfg.TimeoutSeconds > 0 {
		timeout = time.Duration(cfg.TimeoutSeconds) * time.Second
	}

	return &JamfInventory{
		cfg:    cfg,
		client: &http.Client{Timeout: timeout},
	}, nil
}

// IsRegistered queries Jamf Pro for a computer whose serialNumber matches the
// provided EK serial. Returns true if a matching device is found.
func (j *JamfInventory) IsRegistered(ctx context.Context, ekSerial string) (bool, error) {
	// Validate that ekSerial contains only decimal digits to prevent RSQL injection.
	for _, ch := range ekSerial {
		if ch < '0' || ch > '9' {
			return false, fmt.Errorf("deviceinventory/jamf: invalid EK serial %q (must be decimal digits only)", ekSerial)
		}
	}

	token, err := j.getAccessToken(ctx)
	if err != nil {
		return false, fmt.Errorf("deviceinventory/jamf: get token: %w", err)
	}

	// Jamf Pro REST API: filter computers by serial number.
	apiURL := fmt.Sprintf("%s/api/v1/computers-inventory?section=HARDWARE&filter=hardware.serialNumber==\"%s\"&page=0&page-size=1",
		strings.TrimRight(j.cfg.URL, "/"),
		url.QueryEscape(ekSerial),
	)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, nil)
	if err != nil {
		return false, fmt.Errorf("deviceinventory/jamf: build request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")

	resp, err := j.client.Do(req)
	if err != nil {
		return false, fmt.Errorf("deviceinventory/jamf: query computers: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, maxHTTPResponseBytes))
		return false, fmt.Errorf("deviceinventory/jamf: API returned %d: %s", resp.StatusCode, string(body))
	}

	var result struct {
		Results []struct {
			ID string `json:"id"`
		} `json:"results"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxHTTPResponseBytes)).Decode(&result); err != nil {
		return false, fmt.Errorf("deviceinventory/jamf: decode response: %w", err)
	}

	return len(result.Results) > 0, nil
}

// getAccessToken retrieves a cached or fresh OAuth 2.0 access token from Jamf Pro.
// It is safe for concurrent use.
func (j *JamfInventory) getAccessToken(ctx context.Context) (string, error) {
	j.mu.Lock()
	defer j.mu.Unlock()

	if j.accessToken != "" && time.Now().Before(j.tokenExpiry.Add(-30*time.Second)) {
		return j.accessToken, nil
	}

	tokenURL := fmt.Sprintf("%s/api/oauth/token", strings.TrimRight(j.cfg.URL, "/"))
	body := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {j.cfg.ClientID},
		"client_secret": {j.cfg.ClientSecret},
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(body.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := j.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, maxHTTPResponseBytes))
		return "", fmt.Errorf("jamf token endpoint returned %d: %s", resp.StatusCode, string(raw))
	}

	var tokenResp struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxHTTPResponseBytes)).Decode(&tokenResp); err != nil {
		return "", fmt.Errorf("decode Jamf token response: %w", err)
	}

	j.accessToken = tokenResp.AccessToken
	j.tokenExpiry = time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second)
	return j.accessToken, nil
}
