package oauth

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

// auth0GrantType grant type for device flow on Auth0
const (
	auth0GrantType    = "urn:ietf:params:oauth:grant-type:device_code"
	auth0RefreshGrant = "refresh_token"
)

// Auth0 client
type Auth0 struct {
	// Auth0 API Audience for validation
	Audience string
	// Auth0 Native application client id
	ClientID string
	// Auth0 domain
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

// TokenRequestResponse used for parsing Auth0 token's response
type TokenRequestResponse struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
	TokenInfo
}

// Claims used when validating the access token
type Claims struct {
	Audience string `json:"aud"`
}

// NewAuth0DeviceFlow returns an Auth0 OAuth client
func NewAuth0DeviceFlow(audience string, clientID string, domain string) *Auth0 {
	httpTransport := http.DefaultTransport.(*http.Transport).Clone()
	httpTransport.MaxIdleConns = 5

	httpClient := &http.Client{
		Timeout:   10 * time.Second,
		Transport: httpTransport,
	}

	return &Auth0{
		Audience:   audience,
		ClientID:   clientID,
		Domain:     domain,
		HTTPClient: httpClient,
	}
}

// RequestDeviceCode requests a device code login flow information from Auth0
func (a *Auth0) RequestDeviceCode(ctx context.Context) (DeviceAuthInfo, error) {
	url := "https://" + a.Domain + "/oauth/device/code"
	codePayload := RequestDeviceCodePayload{
		Audience: a.Audience,
		ClientID: a.ClientID,
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

	res, err := a.HTTPClient.Do(req)
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
// it retrieves the access token from Auth0's endpoint and validates it before returning
func (a *Auth0) WaitToken(ctx context.Context, info DeviceAuthInfo) (TokenInfo, error) {
	ticker := time.NewTicker(time.Duration(info.Interval) * time.Second)
	for {
		select {
		case <-ctx.Done():
			return TokenInfo{}, ctx.Err()
		case <-ticker.C:
			url := "https://" + a.Domain + "/oauth/token"
			tokenReqPayload := TokenRequestPayload{
				GrantType:  auth0GrantType,
				DeviceCode: info.DeviceCode,
				ClientID:   a.ClientID,
			}

			body, statusCode, err := requestToken(a.HTTPClient, url, tokenReqPayload)
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

			err = isValidAccessToken(tokenResponse.AccessToken, a.Audience)
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
func (a *Auth0) RotateAccessToken(ctx context.Context, refreshToken string) (TokenInfo, error) {
	url := "https://" + a.Domain + "/oauth/token"
	tokenReqPayload := TokenRequestPayload{
		GrantType:    auth0RefreshGrant,
		ClientID:     a.ClientID,
		RefreshToken: refreshToken,
	}

	body, statusCode, err := requestToken(a.HTTPClient, url, tokenReqPayload)
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

	err = isValidAccessToken(tokenResponse.AccessToken, a.Audience)
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
