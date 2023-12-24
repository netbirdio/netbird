package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/netbirdio/netbird/client/internal"
)

// HostedGrantType grant type for device flow on Hosted
const (
	HostedGrantType = "urn:ietf:params:oauth:grant-type:device_code"
)

var _ OAuthFlow = &DeviceAuthorizationFlow{}

// DeviceAuthorizationFlow implements the OAuthFlow interface,
// for the Device Authorization Flow.
type DeviceAuthorizationFlow struct {
	providerConfig internal.DeviceAuthProviderConfig

	HTTPClient HTTPClient
}

// RequestDeviceCodePayload used for request device code payload for auth0
type RequestDeviceCodePayload struct {
	Audience string `json:"audience"`
	ClientID string `json:"client_id"`
	Scope    string `json:"scope"`
}

// TokenRequestPayload used for requesting the auth0 token
type TokenRequestPayload struct {
	GrantType    string `json:"grant_type"`
	DeviceCode   string `json:"device_code,omitempty"`
	ClientID     string `json:"client_id"`
	RefreshToken string `json:"refresh_token,omitempty"`
}

// TokenRequestResponse used for parsing Hosted token's response
type TokenRequestResponse struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
	TokenInfo
}

// NewDeviceAuthorizationFlow returns device authorization flow client
func NewDeviceAuthorizationFlow(config internal.DeviceAuthProviderConfig) (*DeviceAuthorizationFlow, error) {
	httpTransport := http.DefaultTransport.(*http.Transport).Clone()
	httpTransport.MaxIdleConns = 5

	httpClient := &http.Client{
		Timeout:   10 * time.Second,
		Transport: httpTransport,
	}

	return &DeviceAuthorizationFlow{
		providerConfig: config,
		HTTPClient:     httpClient,
	}, nil
}

// GetClientID returns the provider client id
func (d *DeviceAuthorizationFlow) GetClientID(ctx context.Context) string {
	return d.providerConfig.ClientID
}

// RequestAuthInfo requests a device code login flow information from Hosted
func (d *DeviceAuthorizationFlow) RequestAuthInfo(ctx context.Context) (AuthFlowInfo, error) {
	form := url.Values{}
	form.Add("client_id", d.providerConfig.ClientID)
	form.Add("audience", d.providerConfig.Audience)
	form.Add("scope", d.providerConfig.Scope)
	req, err := http.NewRequest("POST", d.providerConfig.DeviceAuthEndpoint,
		strings.NewReader(form.Encode()))
	if err != nil {
		return AuthFlowInfo{}, fmt.Errorf("creating request failed with error: %v", err)
	}
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	res, err := d.HTTPClient.Do(req)
	if err != nil {
		return AuthFlowInfo{}, fmt.Errorf("doing request failed with error: %v", err)
	}

	defer res.Body.Close()
	body, err := io.ReadAll(res.Body)
	if err != nil {
		return AuthFlowInfo{}, fmt.Errorf("reading body failed with error: %v", err)
	}

	if res.StatusCode != 200 {
		return AuthFlowInfo{}, fmt.Errorf("request device code returned status %d error: %s", res.StatusCode, string(body))
	}

	deviceCode := AuthFlowInfo{}
	err = json.Unmarshal(body, &deviceCode)
	if err != nil {
		return AuthFlowInfo{}, fmt.Errorf("unmarshaling response failed with error: %v", err)
	}

	// Fallback to the verification_uri if the IdP doesn't support verification_uri_complete
	if deviceCode.VerificationURIComplete == "" {
		deviceCode.VerificationURIComplete = deviceCode.VerificationURI
	}

	return deviceCode, err
}

func (d *DeviceAuthorizationFlow) requestToken(info AuthFlowInfo) (TokenRequestResponse, error) {
	form := url.Values{}
	form.Add("client_id", d.providerConfig.ClientID)
	form.Add("grant_type", HostedGrantType)
	form.Add("device_code", info.DeviceCode)

	req, err := http.NewRequest("POST", d.providerConfig.TokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return TokenRequestResponse{}, fmt.Errorf("failed to create request access token: %v", err)
	}
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	res, err := d.HTTPClient.Do(req)
	if err != nil {
		return TokenRequestResponse{}, fmt.Errorf("failed to request access token with error: %v", err)
	}

	defer func() {
		err := res.Body.Close()
		if err != nil {
			return
		}
	}()

	body, err := io.ReadAll(res.Body)
	if err != nil {
		return TokenRequestResponse{}, fmt.Errorf("failed reading access token response body with error: %v", err)
	}

	if res.StatusCode > 499 {
		return TokenRequestResponse{}, fmt.Errorf("access token response returned code: %s", string(body))
	}

	tokenResponse := TokenRequestResponse{}
	err = json.Unmarshal(body, &tokenResponse)
	if err != nil {
		return TokenRequestResponse{}, fmt.Errorf("parsing token response failed with error: %v", err)
	}

	return tokenResponse, nil
}

// WaitToken waits user's login and authorize the app. Once the user's authorize
// it retrieves the access token from Hosted's endpoint and validates it before returning
func (d *DeviceAuthorizationFlow) WaitToken(ctx context.Context, info AuthFlowInfo) (TokenInfo, error) {
	interval := time.Duration(info.Interval) * time.Second
	ticker := time.NewTicker(interval)
	for {
		select {
		case <-ctx.Done():
			return TokenInfo{}, ctx.Err()
		case <-ticker.C:

			tokenResponse, err := d.requestToken(info)
			if err != nil {
				return TokenInfo{}, fmt.Errorf("parsing token response failed with error: %v", err)
			}

			if tokenResponse.Error != "" {
				if tokenResponse.Error == "authorization_pending" {
					continue
				} else if tokenResponse.Error == "slow_down" {
					interval += (3 * time.Second)
					ticker.Reset(interval)
					continue
				}

				return TokenInfo{}, fmt.Errorf(tokenResponse.ErrorDescription)
			}

			tokenInfo := TokenInfo{
				AccessToken:  tokenResponse.AccessToken,
				TokenType:    tokenResponse.TokenType,
				RefreshToken: tokenResponse.RefreshToken,
				IDToken:      tokenResponse.IDToken,
				ExpiresIn:    tokenResponse.ExpiresIn,
				UseIDToken:   d.providerConfig.UseIDToken,
			}

			err = isValidAccessToken(tokenInfo.GetTokenToUse(), d.providerConfig.Audience)
			if err != nil {
				return TokenInfo{}, fmt.Errorf("validate access token failed with error: %v", err)
			}

			return tokenInfo, err
		}
	}
}
