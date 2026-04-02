package auth

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/util/embeddedroots"
)

// HostedGrantType grant type for device flow on Hosted
const (
	HostedGrantType = "urn:ietf:params:oauth:grant-type:device_code"
)

var _ OAuthFlow = &DeviceAuthorizationFlow{}

// DeviceAuthProviderConfig has all attributes needed to initiate a device authorization flow
type DeviceAuthProviderConfig struct {
	// ClientID An IDP application client id
	ClientID string
	// ClientSecret An IDP application client secret
	ClientSecret string
	// Domain An IDP API domain
	// Deprecated. Use OIDCConfigEndpoint instead
	Domain string
	// Audience An Audience for to authorization validation
	Audience string
	// TokenEndpoint is the endpoint of an IDP manager where clients can obtain access token
	TokenEndpoint string
	// DeviceAuthEndpoint is the endpoint of an IDP manager where clients can obtain device authorization code
	DeviceAuthEndpoint string
	// Scopes provides the scopes to be included in the token request
	Scope string
	// UseIDToken indicates if the id token should be used for authentication
	UseIDToken bool
	// LoginHint is used to pre-fill the email/username field during authentication
	LoginHint string
}

// validateDeviceAuthConfig validates device authorization provider configuration
func validateDeviceAuthConfig(config *DeviceAuthProviderConfig) error {
	errorMsgFormat := "invalid provider configuration received from management: %s value is empty. Contact your NetBird administrator"

	if config.Audience == "" {
		return fmt.Errorf(errorMsgFormat, "Audience")
	}
	if config.ClientID == "" {
		return fmt.Errorf(errorMsgFormat, "Client ID")
	}
	if config.TokenEndpoint == "" {
		return fmt.Errorf(errorMsgFormat, "Token Endpoint")
	}
	if config.DeviceAuthEndpoint == "" {
		return fmt.Errorf(errorMsgFormat, "Device Auth Endpoint")
	}
	if config.Scope == "" {
		return fmt.Errorf(errorMsgFormat, "Device Auth Scopes")
	}
	return nil
}

// DeviceAuthorizationFlow implements the OAuthFlow interface,
// for the Device Authorization Flow.
type DeviceAuthorizationFlow struct {
	providerConfig DeviceAuthProviderConfig
	HTTPClient     HTTPClient
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
func NewDeviceAuthorizationFlow(config DeviceAuthProviderConfig) (*DeviceAuthorizationFlow, error) {
	httpTransport := http.DefaultTransport.(*http.Transport).Clone()
	httpTransport.MaxIdleConns = 5

	certPool, err := x509.SystemCertPool()
	if err != nil || certPool == nil {
		log.Debugf("System cert pool not available; falling back to embedded cert, error: %v", err)
		certPool = embeddedroots.Get()
	} else {
		log.Debug("Using system certificate pool.")
	}

	httpTransport.TLSClientConfig = &tls.Config{
		RootCAs: certPool,
	}

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

// SetLoginHint sets the login hint for the device authorization flow
func (d *DeviceAuthorizationFlow) SetLoginHint(hint string) {
	d.providerConfig.LoginHint = hint
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

	if d.providerConfig.LoginHint != "" {
		deviceCode.VerificationURIComplete = appendLoginHint(deviceCode.VerificationURIComplete, d.providerConfig.LoginHint)
		if deviceCode.VerificationURI != "" {
			deviceCode.VerificationURI = appendLoginHint(deviceCode.VerificationURI, d.providerConfig.LoginHint)
		}
	}

	return deviceCode, err
}

func appendLoginHint(uri, loginHint string) string {
	if uri == "" || loginHint == "" {
		return uri
	}

	parsedURL, err := url.Parse(uri)
	if err != nil {
		log.Debugf("failed to parse verification URI for login_hint: %v", err)
		return uri
	}

	query := parsedURL.Query()
	query.Set("login_hint", loginHint)
	parsedURL.RawQuery = query.Encode()

	return parsedURL.String()
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
// it retrieves the access token from Hosted's endpoint and validates it before returning.
// The method creates a timeout context internally based on info.ExpiresIn.
func (d *DeviceAuthorizationFlow) WaitToken(ctx context.Context, info AuthFlowInfo) (TokenInfo, error) {
	// Create timeout context based on flow expiration
	timeout := time.Duration(info.ExpiresIn) * time.Second
	waitCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	interval := time.Duration(info.Interval) * time.Second
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-waitCtx.Done():
			return TokenInfo{}, waitCtx.Err()
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

				return TokenInfo{}, errors.New(tokenResponse.ErrorDescription)
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
