package entra_device

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// GraphClient is the subset of Microsoft Graph calls the enrolment flow needs.
type GraphClient interface {
	// Device returns the device object along with accountEnabled state. If the
	// device cannot be found, returns (nil, nil) — not an error.
	Device(ctx context.Context, deviceID string) (*GraphDevice, error)
	// TransitiveMemberOf returns the set of group object IDs the device belongs
	// to, transitively.
	TransitiveMemberOf(ctx context.Context, deviceID string) ([]string, error)
	// IsCompliant returns true if Intune reports complianceState == compliant
	// for a managed device with the given azureADDeviceId.
	IsCompliant(ctx context.Context, deviceID string) (bool, error)
}

// GraphDevice is the subset of the Graph `device` resource we care about.
type GraphDevice struct {
	ID                string `json:"id"`
	DeviceID          string `json:"deviceId"`
	AccountEnabled    bool   `json:"accountEnabled"`
	DisplayName       string `json:"displayName"`
	OperatingSystem   string `json:"operatingSystem"`
	TrustType         string `json:"trustType"`
	ApproximateLastSignInDateTime *time.Time `json:"approximateLastSignInDateTime,omitempty"`
}

// HTTPGraphClient is the default GraphClient implementation, talking to Graph
// over HTTPS with an app-only OAuth2 client-credentials token obtained from
// the tenant's token endpoint.
type HTTPGraphClient struct {
	HTTPClient *http.Client

	TenantID     string
	ClientID     string
	ClientSecret string

	// GraphBaseURL defaults to https://graph.microsoft.com (can be overridden
	// for sovereign clouds).
	GraphBaseURL string

	mu        sync.Mutex
	token     string
	tokenExp  time.Time
}

// NewHTTPGraphClient builds a client. The caller is expected to pre-validate
// that client ID/secret/tenant ID are non-empty.
func NewHTTPGraphClient(tenantID, clientID, clientSecret string) *HTTPGraphClient {
	return &HTTPGraphClient{
		HTTPClient:   &http.Client{Timeout: 15 * time.Second},
		TenantID:     tenantID,
		ClientID:     clientID,
		ClientSecret: clientSecret,
		GraphBaseURL: "https://graph.microsoft.com",
	}
}

func (c *HTTPGraphClient) baseURL() string {
	if c.GraphBaseURL != "" {
		return strings.TrimRight(c.GraphBaseURL, "/")
	}
	return "https://graph.microsoft.com"
}

// token caches the app-only bearer token.
func (c *HTTPGraphClient) bearer(ctx context.Context) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.token != "" && time.Until(c.tokenExp) > 30*time.Second {
		return c.token, nil
	}

	form := url.Values{
		"client_id":     {c.ClientID},
		"client_secret": {c.ClientSecret},
		"grant_type":    {"client_credentials"},
		"scope":         {c.baseURL() + "/.default"},
	}
	endpoint := fmt.Sprintf("https://login.microsoftonline.com/%s/oauth2/v2.0/token", c.TenantID)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("token endpoint %d: %s", resp.StatusCode, string(body))
	}

	var tr struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
		TokenType   string `json:"token_type"`
	}
	if err := json.Unmarshal(body, &tr); err != nil {
		return "", err
	}
	if tr.AccessToken == "" {
		return "", fmt.Errorf("token endpoint returned empty access_token")
	}
	c.token = tr.AccessToken
	c.tokenExp = time.Now().Add(time.Duration(tr.ExpiresIn) * time.Second)
	return c.token, nil
}

func (c *HTTPGraphClient) graphGET(ctx context.Context, path string, q url.Values, dst any) (int, error) {
	token, err := c.bearer(ctx)
	if err != nil {
		return 0, err
	}
	full := c.baseURL() + path
	if len(q) > 0 {
		full += "?" + q.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, full, nil)
	if err != nil {
		return 0, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("ConsistencyLevel", "eventual")

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode == http.StatusNotFound {
		return resp.StatusCode, nil
	}
	if resp.StatusCode >= 400 {
		return resp.StatusCode, fmt.Errorf("graph %s: %d: %s", path, resp.StatusCode, string(body))
	}
	if dst != nil {
		if err := json.Unmarshal(body, dst); err != nil {
			return resp.StatusCode, fmt.Errorf("graph %s decode: %w", path, err)
		}
	}
	return resp.StatusCode, nil
}

// odataEscape escapes a string literal for an OData v4 filter expression.
// Single quotes are the only character OData requires escaping inside a
// single-quoted string (replace ' with '').
func odataEscape(s string) string { return strings.ReplaceAll(s, "'", "''") }

// Device implements GraphClient.
func (c *HTTPGraphClient) Device(ctx context.Context, deviceID string) (*GraphDevice, error) {
	q := url.Values{}
	q.Set("$select", "id,deviceId,accountEnabled,displayName,operatingSystem,trustType,approximateLastSignInDateTime")
	q.Set("$filter", fmt.Sprintf("deviceId eq '%s'", odataEscape(deviceID)))
	var wrap struct {
		Value []GraphDevice `json:"value"`
	}
	status, err := c.graphGET(ctx, "/v1.0/devices", q, &wrap)
	if err != nil {
		return nil, err
	}
	if status == http.StatusNotFound || len(wrap.Value) == 0 {
		return nil, nil
	}
	d := wrap.Value[0]
	return &d, nil
}

// TransitiveMemberOf implements GraphClient.
func (c *HTTPGraphClient) TransitiveMemberOf(ctx context.Context, entraObjectID string) ([]string, error) {
	q := url.Values{}
	q.Set("$select", "id")
	q.Set("$top", "100")
	path := fmt.Sprintf("/v1.0/devices/%s/transitiveMemberOf", url.PathEscape(entraObjectID))

	groupIDs := make([]string, 0, 32)
	for path != "" {
		var wrap struct {
			Value    []struct{ ID string `json:"id"` } `json:"value"`
			NextLink string                            `json:"@odata.nextLink"`
		}
		if _, err := c.graphGET(ctx, path, q, &wrap); err != nil {
			return nil, err
		}
		for _, v := range wrap.Value {
			if v.ID != "" {
				groupIDs = append(groupIDs, v.ID)
			}
		}
		if wrap.NextLink == "" {
			break
		}
		// NextLink is an absolute URL; strip the base so graphGET can prepend it.
		if strings.HasPrefix(wrap.NextLink, c.baseURL()) {
			path = strings.TrimPrefix(wrap.NextLink, c.baseURL())
			q = nil
		} else {
			// Fail closed: a nextLink under a different host would either
			// silently truncate the group list (over-scoping risk) or leak
			// our bearer to an unintended host. Return an error so the caller
			// doesn't enroll a device with half-enumerated groups.
			return nil, fmt.Errorf("graph pagination nextLink host does not match base URL: nextLink=%q base=%q", wrap.NextLink, c.baseURL())
		}
	}
	return groupIDs, nil
}

// IsCompliant implements GraphClient.
func (c *HTTPGraphClient) IsCompliant(ctx context.Context, deviceID string) (bool, error) {
	q := url.Values{}
	q.Set("$select", "id,complianceState,azureADDeviceId")
	q.Set("$filter", fmt.Sprintf("azureADDeviceId eq '%s'", odataEscape(deviceID)))
	var wrap struct {
		Value []struct {
			ComplianceState string `json:"complianceState"`
		} `json:"value"`
	}
	if _, err := c.graphGET(ctx, "/v1.0/deviceManagement/managedDevices", q, &wrap); err != nil {
		return false, err
	}
	if len(wrap.Value) == 0 {
		return false, nil
	}
	return strings.EqualFold(wrap.Value[0].ComplianceState, "compliant"), nil
}
