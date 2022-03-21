package oauth

import (
	"context"
	"net/http"
)

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

// Client is a OAuth client interface for various idp providers
type Client interface {
	RequestDeviceCode(ctx context.Context) (DeviceAuthInfo, error)
	RotateAccessToken(ctx context.Context, refreshToken string) (TokenInfo, error)
	WaitToken(ctx context.Context, info DeviceAuthInfo) (TokenInfo, error)
}
