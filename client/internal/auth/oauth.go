package auth

import (
	"context"
	"github.com/netbirdio/netbird/client/internal"
	"net/http"
)

// OAuthFlow represents an interface for authorization using different OAuth 2.0 flows
type OAuthFlow interface {
	RequestAuthInfo(ctx context.Context) (AuthFlowInfo, error)
	WaitToken(ctx context.Context, info AuthFlowInfo) (TokenInfo, error)
	GetClientID(ctx context.Context) string
}

// HTTPClient http client interface for API calls
type HTTPClient interface {
	Do(req *http.Request) (*http.Response, error)
}

// AuthFlowInfo holds information for the OAuth 2.0  authorization flow
type AuthFlowInfo struct {
	DeviceCode              string `json:"device_code"`
	UserCode                string `json:"user_code"`
	VerificationURI         string `json:"verification_uri"`
	VerificationURIComplete string `json:"verification_uri_complete"`
	ExpiresIn               int    `json:"expires_in"`
	Interval                int    `json:"interval"`
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

// NewOAuthFlow initializes and returns the appropriate OAuth flow based on the management configuration.
func NewOAuthFlow(ctx context.Context, config *internal.Config) (OAuthFlow, error) {
	flowInfo, err := internal.GetDeviceAuthorizationFlowInfo(ctx, config.PrivateKey, config.ManagementURL)
	if err != nil {
		// TODO: check if PKCE flow config if available
		return nil, err
	}

	return NewDeviceAuthorizationFlow(flowInfo.ProviderConfig)
}
