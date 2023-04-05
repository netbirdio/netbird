package internal

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"time"
)

// OAuthClient is a OAuth client interface for various idp providers
type OAuthClient interface {
	RequestDeviceCode(ctx context.Context) (DeviceAuthInfo, error)
	WaitToken(ctx context.Context, info DeviceAuthInfo) (TokenInfo, error)
	GetClientID(ctx context.Context) string
}

// HTTPClient http client interface for API calls
type HTTPClient interface {
	Do(req *http.Request) (*http.Response, error)
}

// DeviceAuthInfo holds information for the OAuth device login flow
type DeviceAuthInfo struct {
	DeviceCode              string `json:"device_code"`
	UserCode                string `json:"user_code"`
	VerificationURI         string `json:"verification_uri"`
	VerificationURIComplete string `json:"verification_uri_complete"`
	ExpiresIn               int    `json:"expires_in"`
	Interval                int    `json:"interval"`
}

// HostedGrantType grant type for device flow on Hosted
const (
	HostedGrantType    = "urn:ietf:params:oauth:grant-type:device_code"
	HostedRefreshGrant = "refresh_token"
)

// Hosted client
type Hosted struct {
	providerConfig ProviderConfig

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

// Claims used when validating the access token
type Claims struct {
	Audience interface{} `json:"aud"`
}

// TokenInfo holds information of issued access token
type TokenInfo struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	IDToken      string `json:"id_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	UseIDToken   bool   `json:"-"`
}

// GetTokenToUse returns either the access or id token based on UseIDToken field
func (t TokenInfo) GetTokenToUse() string {
	if t.UseIDToken {
		return t.IDToken
	}
	return t.AccessToken
}

// NewHostedDeviceFlow returns an Hosted OAuth client
func NewHostedDeviceFlow(config ProviderConfig) *Hosted {
	httpTransport := http.DefaultTransport.(*http.Transport).Clone()
	httpTransport.MaxIdleConns = 5

	httpClient := &http.Client{
		Timeout:   10 * time.Second,
		Transport: httpTransport,
	}

	return &Hosted{
		providerConfig: config,
		HTTPClient:     httpClient,
	}
}

// GetClientID returns the provider client id
func (h *Hosted) GetClientID(ctx context.Context) string {
	return h.providerConfig.ClientID
}

// RequestDeviceCode requests a device code login flow information from Hosted
func (h *Hosted) RequestDeviceCode(ctx context.Context) (DeviceAuthInfo, error) {
	form := url.Values{}
	form.Add("client_id", h.providerConfig.ClientID)
	form.Add("audience", h.providerConfig.Audience)
	form.Add("scope", h.providerConfig.Scope)
	req, err := http.NewRequest("POST", h.providerConfig.DeviceAuthEndpoint,
		strings.NewReader(form.Encode()))
	if err != nil {
		return DeviceAuthInfo{}, fmt.Errorf("creating request failed with error: %v", err)
	}
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	res, err := h.HTTPClient.Do(req)
	if err != nil {
		return DeviceAuthInfo{}, fmt.Errorf("doing request failed with error: %v", err)
	}

	defer res.Body.Close()
	body, err := io.ReadAll(res.Body)
	if err != nil {
		return DeviceAuthInfo{}, fmt.Errorf("reading body failed with error: %v", err)
	}

	if res.StatusCode != 200 {
		return DeviceAuthInfo{}, fmt.Errorf("request device code returned status %d error: %s", res.StatusCode, string(body))
	}

	deviceCode := DeviceAuthInfo{}
	err = json.Unmarshal(body, &deviceCode)
	if err != nil {
		return DeviceAuthInfo{}, fmt.Errorf("unmarshaling response failed with error: %v", err)
	}

	return deviceCode, err
}

func (h *Hosted) requestToken(info DeviceAuthInfo) (TokenRequestResponse, error) {
	form := url.Values{}
	form.Add("client_id", h.providerConfig.ClientID)
	form.Add("grant_type", HostedGrantType)
	form.Add("device_code", info.DeviceCode)
	req, err := http.NewRequest("POST", h.providerConfig.TokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return TokenRequestResponse{}, fmt.Errorf("failed to create request access token: %v", err)
	}

	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	res, err := h.HTTPClient.Do(req)
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
func (h *Hosted) WaitToken(ctx context.Context, info DeviceAuthInfo) (TokenInfo, error) {
	interval := time.Duration(info.Interval) * time.Second
	ticker := time.NewTicker(interval)
	for {
		select {
		case <-ctx.Done():
			return TokenInfo{}, ctx.Err()
		case <-ticker.C:

			tokenResponse, err := h.requestToken(info)
			if err != nil {
				return TokenInfo{}, fmt.Errorf("parsing token response failed with error: %v", err)
			}

			if tokenResponse.Error != "" {
				if tokenResponse.Error == "authorization_pending" {
					continue
				} else if tokenResponse.Error == "slow_down" {
					interval = interval + (3 * time.Second)
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
				UseIDToken:   h.providerConfig.UseIDToken,
			}

			err = isValidAccessToken(tokenInfo.GetTokenToUse(), h.providerConfig.Audience)
			if err != nil {
				return TokenInfo{}, fmt.Errorf("validate access token failed with error: %v", err)
			}

			return tokenInfo, err
		}
	}
}

// isValidAccessToken is a simple validation of the access token
func isValidAccessToken(token string, audience string) error {
	if token == "" {
		return fmt.Errorf("token received is empty")
	}

	encodedClaims := strings.Split(token, ".")[1]
	claimsString, err := base64.RawURLEncoding.DecodeString(encodedClaims)
	if err != nil {
		return err
	}

	claims := Claims{}
	err = json.Unmarshal(claimsString, &claims)
	if err != nil {
		return err
	}

	if claims.Audience == nil {
		return fmt.Errorf("required token field audience is absent")
	}

	// Audience claim of JWT can be a string or an array of strings
	typ := reflect.TypeOf(claims.Audience)
	switch typ.Kind() {
	case reflect.String:
		if claims.Audience == audience {
			return nil
		}
	case reflect.Slice:
		for _, aud := range claims.Audience.([]interface{}) {
			if audience == aud {
				return nil
			}
		}
	}

	return fmt.Errorf("invalid JWT token audience field")
}
