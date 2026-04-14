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

// encPrefix is the sentinel prefix prepended to encrypted secret values.
// DecryptSecrets checks for this prefix to distinguish encrypted from plaintext data.
const encPrefix = "enc:"

// IntuneConfig holds credentials and parameters for the Microsoft Intune
// device inventory via Microsoft Graph API.
type IntuneConfig struct {
	// TenantID is the Azure AD tenant identifier.
	TenantID string `json:"tenant_id"`
	// ClientID is the Azure AD application (client) ID.
	ClientID string `json:"client_id"`
	// ClientSecret is the Azure AD client secret for client_credentials flow.
	ClientSecret string `json:"client_secret"`
	// Timeout overrides the HTTP client timeout (default: 10s).
	TimeoutSeconds int `json:"timeout_seconds,omitempty"`
	// TokenBaseURL overrides the Azure AD token endpoint base URL.
	// Defaults to "https://login.microsoftonline.com". Used for testing.
	TokenBaseURL string `json:"token_base_url,omitempty"`
	// GraphBaseURL overrides the Microsoft Graph API base URL.
	// Defaults to "https://graph.microsoft.com". Used for testing.
	GraphBaseURL string `json:"graph_base_url,omitempty"`
}

// EncryptSecrets encrypts the ClientSecret field in-place using kp.
// The encrypted value is stored with an "enc:" prefix followed by base64-encoded ciphertext.
func (c *IntuneConfig) EncryptSecrets(kp secretenc.KeyProvider) error {
	if c.ClientSecret == "" || strings.HasPrefix(c.ClientSecret, encPrefix) {
		return nil
	}
	ct, err := kp.Encrypt([]byte(c.ClientSecret))
	if err != nil {
		return fmt.Errorf("intune: encrypt client secret: %w", err)
	}
	c.ClientSecret = encPrefix + base64.StdEncoding.EncodeToString(ct)
	return nil
}

// DecryptSecrets decrypts the ClientSecret field in-place using kp.
// Values without the "enc:" prefix are treated as pre-encryption plaintext and left unchanged.
func (c *IntuneConfig) DecryptSecrets(kp secretenc.KeyProvider) error {
	if !strings.HasPrefix(c.ClientSecret, encPrefix) {
		return nil
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(c.ClientSecret, encPrefix))
	if err != nil {
		return fmt.Errorf("intune: decode client secret: %w", err)
	}
	plain, err := kp.Decrypt(raw)
	if err != nil {
		return fmt.Errorf("intune: decrypt client secret: %w", err)
	}
	c.ClientSecret = string(plain)
	return nil
}

// defaultTokenBaseURL is the Azure AD token endpoint base.
const defaultTokenBaseURL = "https://login.microsoftonline.com" //nolint:gosec // not a credential

// defaultGraphBaseURL is the Microsoft Graph API base URL.
const defaultGraphBaseURL = "https://graph.microsoft.com"

// IntuneInventory checks device registration against Microsoft Intune via the
// Microsoft Graph API (/deviceManagement/managedDevices).
//
// Authentication uses the OAuth 2.0 client credentials flow; the access token
// is obtained on first use and cached until expiry.
type IntuneInventory struct {
	cfg          IntuneConfig
	client       *http.Client
	mu           sync.Mutex
	accessToken  string
	tokenExpiry  time.Time
	tokenBaseURL string
	graphBaseURL string
}

// NewIntuneInventory parses a JSON config blob and returns an IntuneInventory.
func NewIntuneInventory(configJSON string) (*IntuneInventory, error) {
	var cfg IntuneConfig
	if err := json.Unmarshal([]byte(configJSON), &cfg); err != nil {
		return nil, fmt.Errorf("deviceinventory/intune: parse config: %w", err)
	}
	if cfg.TenantID == "" || cfg.ClientID == "" || cfg.ClientSecret == "" {
		return nil, fmt.Errorf("deviceinventory/intune: tenant_id, client_id, and client_secret are required")
	}

	timeout := 10 * time.Second
	if cfg.TimeoutSeconds > 0 {
		timeout = time.Duration(cfg.TimeoutSeconds) * time.Second
	}

	tokenBase := defaultTokenBaseURL
	if cfg.TokenBaseURL != "" {
		tokenBase = cfg.TokenBaseURL
	}

	graphBase := defaultGraphBaseURL
	if cfg.GraphBaseURL != "" {
		graphBase = cfg.GraphBaseURL
	}

	return &IntuneInventory{
		cfg:          cfg,
		client:       &http.Client{Timeout: timeout},
		tokenBaseURL: tokenBase,
		graphBaseURL: graphBase,
	}, nil
}

// IsRegistered queries Intune for a managed device whose serialNumber matches
// the provided EK serial. Returns true if at least one device is found.
func (i *IntuneInventory) IsRegistered(ctx context.Context, ekSerial string) (bool, error) {
	// Validate that ekSerial contains only decimal digits to prevent OData injection.
	for _, ch := range ekSerial {
		if ch < '0' || ch > '9' {
			return false, fmt.Errorf("deviceinventory/intune: invalid EK serial %q (must be decimal digits only)", ekSerial)
		}
	}

	token, err := i.getAccessToken(ctx)
	if err != nil {
		return false, fmt.Errorf("deviceinventory/intune: get token: %w", err)
	}

	// Graph API filter by serialNumber.
	filter := url.QueryEscape(fmt.Sprintf("serialNumber eq '%s'", ekSerial))
	apiURL := fmt.Sprintf("%s/v1.0/deviceManagement/managedDevices?$filter=%s&$select=id,serialNumber", i.graphBaseURL, filter)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, nil)
	if err != nil {
		return false, fmt.Errorf("deviceinventory/intune: build request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")

	resp, err := i.client.Do(req)
	if err != nil {
		return false, fmt.Errorf("deviceinventory/intune: query devices: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, maxHTTPResponseBytes))
		return false, fmt.Errorf("deviceinventory/intune: Graph API returned %d: %s", resp.StatusCode, string(body))
	}

	var result struct {
		Value []struct {
			ID string `json:"id"`
		} `json:"value"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxHTTPResponseBytes)).Decode(&result); err != nil {
		return false, fmt.Errorf("deviceinventory/intune: decode response: %w", err)
	}

	return len(result.Value) > 0, nil
}

// getAccessToken retrieves a cached or fresh OAuth 2.0 access token.
// It is safe for concurrent use.
func (i *IntuneInventory) getAccessToken(ctx context.Context) (string, error) {
	i.mu.Lock()
	defer i.mu.Unlock()

	if i.accessToken != "" && time.Now().Before(i.tokenExpiry.Add(-30*time.Second)) {
		return i.accessToken, nil
	}

	tokenURL := fmt.Sprintf("%s/%s/oauth2/v2.0/token", i.tokenBaseURL, i.cfg.TenantID)
	body := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {i.cfg.ClientID},
		"client_secret": {i.cfg.ClientSecret},
		"scope":         {"https://graph.microsoft.com/.default"},
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(body.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := i.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, maxHTTPResponseBytes))
		return "", fmt.Errorf("token endpoint returned %d: %s", resp.StatusCode, string(raw))
	}

	var tokenResp struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxHTTPResponseBytes)).Decode(&tokenResp); err != nil {
		return "", fmt.Errorf("decode token response: %w", err)
	}

	i.accessToken = tokenResp.AccessToken
	i.tokenExpiry = time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second)
	return i.accessToken, nil
}
