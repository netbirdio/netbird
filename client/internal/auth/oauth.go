package auth

import (
	"context"
	"fmt"
	"net/http"

	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc/codes"
	gstatus "google.golang.org/grpc/status"

	"github.com/netbirdio/netbird/client/internal"
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
	log.Debug("getting device authorization flow info")

	// Try to initialize the Device Authorization Flow
	deviceFlowInfo, err := internal.GetDeviceAuthorizationFlowInfo(ctx, config.PrivateKey, config.ManagementURL)
	if err == nil {
		return NewDeviceAuthorizationFlow(deviceFlowInfo.ProviderConfig)
	}

	log.Debugf("getting device authorization flow info failed with error: %v", err)
	log.Debugf("falling back to pkce authorization flow info")

	// If Device Authorization Flow failed, try the PKCE Authorization Flow
	pkceFlowInfo, err := internal.GetPKCEAuthorizationFlowInfo(ctx, config.PrivateKey, config.ManagementURL)
	if err != nil {
		s, ok := gstatus.FromError(err)
		if ok && s.Code() == codes.NotFound {
			return nil, fmt.Errorf("no SSO provider returned from management. " +
				"If you are using hosting Netbird see documentation at " +
				"https://github.com/netbirdio/netbird/tree/main/management for details")
		} else if ok && s.Code() == codes.Unimplemented {
			return nil, fmt.Errorf("the management server, %s, does not support SSO providers, "+
				"please update your server or use Setup Keys to login", config.ManagementURL)
		} else {
			return nil, fmt.Errorf("getting pkce authorization flow info failed with error: %v", err)
		}
	}

	return NewPKCEAuthorizationFlow(pkceFlowInfo.ProviderConfig)
}
