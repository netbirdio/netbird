package internal

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"time"
)

// OAuthClient is a OAuth client interface for various idp providers
type OAuthClient interface {
	RequestDeviceCode(ctx context.Context) (DeviceAuthInfo, error)
	RotateAccessToken(ctx context.Context, refreshToken string) (TokenInfo, error)
	WaitToken(ctx context.Context, info DeviceAuthInfo) (TokenInfo, error)
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

// TokenInfo holds information of issued access token
type TokenInfo struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	IDToken      string `json:"id_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
}

// HostedGrantType grant type for device flow on Hosted
const (
	HostedGrantType    = "urn:ietf:params:oauth:grant-type:device_code"
	HostedRefreshGrant = "refresh_token"
)

// Hosted client
type Hosted struct {
	// Hosted API Audience for validation
	Audience string
	// Hosted Native application client id
	ClientID string
	// Hosted domain
	Domain string

	HTTPClient HTTPClient
}

// RequestDeviceCodePayload used for request device code payload for auth0
type RequestDeviceCodePayload struct {
	Audience string `json:"audience"`
	ClientID string `json:"client_id"`
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
	Audience string `json:"aud"`
}

// NewHostedDeviceFlow returns an Hosted OAuth client
func NewHostedDeviceFlow(audience string, clientID string, domain string) *Hosted {
	httpTransport := http.DefaultTransport.(*http.Transport).Clone()
	httpTransport.MaxIdleConns = 5

	httpClient := &http.Client{
		Timeout:   10 * time.Second,
		Transport: httpTransport,
	}

	return &Hosted{
		Audience:   audience,
		ClientID:   clientID,
		Domain:     domain,
		HTTPClient: httpClient,
	}
}

// RequestDeviceCode requests a device code login flow information from Hosted
func (h *Hosted) RequestDeviceCode(ctx context.Context) (DeviceAuthInfo, error) {
	url := "https://" + h.Domain + "/oauth/device/code"
	codePayload := RequestDeviceCodePayload{
		Audience: h.Audience,
		ClientID: h.ClientID,
	}
	p, err := json.Marshal(codePayload)
	if err != nil {
		return DeviceAuthInfo{}, fmt.Errorf("parsing payload failed with error: %v", err)
	}
	payload := strings.NewReader(string(p))
	req, err := http.NewRequest("POST", url, payload)
	if err != nil {
		return DeviceAuthInfo{}, fmt.Errorf("creating request failed with error: %v", err)
	}

	req.Header.Add("content-type", "application/json")

	res, err := h.HTTPClient.Do(req)
	if err != nil {
		return DeviceAuthInfo{}, fmt.Errorf("doing request failed with error: %v", err)
	}

	defer res.Body.Close()
	body, err := ioutil.ReadAll(res.Body)
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

// WaitToken waits user's login and authorize the app. Once the user's authorize
// it retrieves the access token from Hosted's endpoint and validates it before returning
func (h *Hosted) WaitToken(ctx context.Context, info DeviceAuthInfo) (TokenInfo, error) {
	ticker := time.NewTicker(time.Duration(info.Interval) * time.Second)
	for {
		select {
		case <-ctx.Done():
			return TokenInfo{}, ctx.Err()
		case <-ticker.C:
			url := "https://" + h.Domain + "/oauth/token"
			tokenReqPayload := TokenRequestPayload{
				GrantType:  HostedGrantType,
				DeviceCode: info.DeviceCode,
				ClientID:   h.ClientID,
			}

			body, statusCode, err := requestToken(h.HTTPClient, url, tokenReqPayload)
			if err != nil {
				return TokenInfo{}, fmt.Errorf("wait for token: %v", err)
			}

			if statusCode > 499 {
				return TokenInfo{}, fmt.Errorf("wait token code returned error: %s", string(body))
			}

			tokenResponse := TokenRequestResponse{}
			err = json.Unmarshal(body, &tokenResponse)
			if err != nil {
				return TokenInfo{}, fmt.Errorf("parsing token response failed with error: %v", err)
			}

			if tokenResponse.Error != "" {
				if tokenResponse.Error == "authorization_pending" {
					continue
				}
				return TokenInfo{}, fmt.Errorf(tokenResponse.ErrorDescription)
			}

			err = isValidAccessToken(tokenResponse.AccessToken, h.Audience)
			if err != nil {
				return TokenInfo{}, fmt.Errorf("validate access token failed with error: %v", err)
			}

			tokenInfo := TokenInfo{
				AccessToken:  tokenResponse.AccessToken,
				TokenType:    tokenResponse.TokenType,
				RefreshToken: tokenResponse.RefreshToken,
				IDToken:      tokenResponse.IDToken,
				ExpiresIn:    tokenResponse.ExpiresIn,
			}
			return tokenInfo, err
		}
	}
}

// RotateAccessToken requests a new token using an existing refresh token
func (h *Hosted) RotateAccessToken(ctx context.Context, refreshToken string) (TokenInfo, error) {
	url := "https://" + h.Domain + "/oauth/token"
	tokenReqPayload := TokenRequestPayload{
		GrantType:    HostedRefreshGrant,
		ClientID:     h.ClientID,
		RefreshToken: refreshToken,
	}

	body, statusCode, err := requestToken(h.HTTPClient, url, tokenReqPayload)
	if err != nil {
		return TokenInfo{}, fmt.Errorf("rotate access token: %v", err)
	}

	if statusCode != 200 {
		return TokenInfo{}, fmt.Errorf("rotating token returned error: %s", string(body))
	}

	tokenResponse := TokenRequestResponse{}
	err = json.Unmarshal(body, &tokenResponse)
	if err != nil {
		return TokenInfo{}, fmt.Errorf("parsing token response failed with error: %v", err)
	}

	err = isValidAccessToken(tokenResponse.AccessToken, h.Audience)
	if err != nil {
		return TokenInfo{}, fmt.Errorf("validate access token failed with error: %v", err)
	}

	tokenInfo := TokenInfo{
		AccessToken:  tokenResponse.AccessToken,
		TokenType:    tokenResponse.TokenType,
		RefreshToken: tokenResponse.RefreshToken,
		IDToken:      tokenResponse.IDToken,
		ExpiresIn:    tokenResponse.ExpiresIn,
	}
	return tokenInfo, err
}

func requestToken(client HTTPClient, url string, tokenReqPayload TokenRequestPayload) ([]byte, int, error) {
	p, err := json.Marshal(tokenReqPayload)
	if err != nil {
		return nil, 0, fmt.Errorf("parsing token payload failed with error: %v", err)
	}
	payload := strings.NewReader(string(p))
	req, err := http.NewRequest("POST", url, payload)
	if err != nil {
		return nil, 0, fmt.Errorf("creating token request failed with error: %v", err)
	}

	req.Header.Add("content-type", "application/json")

	res, err := client.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("doing token request failed with error: %v", err)
	}

	defer res.Body.Close()
	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return nil, 0, fmt.Errorf("reading token body failed with error: %v", err)
	}
	return body, res.StatusCode, nil
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

	if claims.Audience != audience {
		return fmt.Errorf("invalid audience")
	}

	return nil
}
