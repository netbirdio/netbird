package auth

import (
	"context"
	"fmt"
	"net/http"
	"runtime"
	"strings"

	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc/codes"
	gstatus "google.golang.org/grpc/status"

	"github.com/netbirdio/netbird/client/internal/profilemanager"
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

// accountPromptForcer is implemented by the PKCE flow only. The device code
// flow has no equivalent: RFC 8628 defines no prompt parameter, and the user
// confirms the code on a page that shows which account signs in, so a silent
// wrong-account answer is not the failure mode there.
type accountPromptForcer interface {
	ForceAccountPrompt()
}

// AuthFlowInfo holds information for the OAuth 2.0  authorization flow
type AuthFlowInfo struct { //nolint:revive
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
	Email        string `json:"-"`
}

// MatchesAccount reports whether the token belongs to the account a profile is
// bound to. A hint the IdP could not have acted on — no hint stored, or a token
// that carried no email — is reported as a match: the check exists to catch a
// login answered from the wrong account, not to block one it cannot judge.
//
// The comparison is case-insensitive. Local-parts are case-sensitive per RFC
// 5321, but no IdP in practice issues two accounts differing only in case, and
// an IdP that echoes a differently-cased address would otherwise fail every
// login.
func (t TokenInfo) MatchesAccount(hint string) bool {
	if hint == "" || t.Email == "" {
		return true
	}
	return strings.EqualFold(t.Email, hint)
}

// GetTokenToUse returns either the access or id token based on UseIDToken field
func (t TokenInfo) GetTokenToUse() string {
	if t.UseIDToken {
		return t.IDToken
	}
	return t.AccessToken
}

func shouldUseDeviceFlow(force bool, isUnixDesktopClient bool) bool {
	return force || (runtime.GOOS == "linux" || runtime.GOOS == "freebsd") && !isUnixDesktopClient
}

// NewOAuthFlow initializes and returns the appropriate OAuth flow based on the management configuration
//
// It starts by initializing the PKCE.If this process fails, it resorts to the Device Code Flow,
// and if that also fails, the authentication process is deemed unsuccessful
//
// On Linux distros without desktop environment support, it only tries to initialize the Device Code Flow
// forceDeviceCodeFlow can be used to skip PKCE and go directly to Device Code Flow (e.g., for Android TV)
//
// sessionExtend marks the flow as renewing an existing peer's session rather than
// logging one in; see PKCEAuthorizationFlowRequest for what the server makes of it.
func NewOAuthFlow(ctx context.Context, config *profilemanager.Config, isUnixDesktopClient bool, forceDeviceCodeFlow bool, hint string, sessionExtend bool) (OAuthFlow, error) {
	if shouldUseDeviceFlow(forceDeviceCodeFlow, isUnixDesktopClient) {
		return authenticateWithDeviceCodeFlow(ctx, config, hint)
	}

	pkceFlow, err := authenticateWithPKCEFlow(ctx, config, hint, sessionExtend)
	if err != nil {
		log.Debugf("failed to initialize pkce authentication with error: %v\n", err)
		log.Debug("falling back to device code flow")
		return authenticateWithDeviceCodeFlow(ctx, config, hint)
	}
	return pkceFlow, nil
}

// authenticateWithPKCEFlow initializes the Proof Key for Code Exchange flow auth flow
func authenticateWithPKCEFlow(ctx context.Context, config *profilemanager.Config, hint string, sessionExtend bool) (OAuthFlow, error) {
	authClient, err := NewAuth(ctx, config.PrivateKey, config.ManagementURL, config)
	if err != nil {
		return nil, fmt.Errorf("failed to create auth client: %v", err)
	}
	defer authClient.Close()

	pkceFlowInfo, err := authClient.getPKCEFlow(authClient.client, sessionExtend)
	if err != nil {
		return nil, fmt.Errorf("getting pkce authorization flow info failed with error: %v", err)
	}

	if hint != "" {
		pkceFlowInfo.SetLoginHint(hint)
	}

	return pkceFlowInfo, nil
}

// authenticateWithDeviceCodeFlow initializes the Device Code auth Flow
func authenticateWithDeviceCodeFlow(ctx context.Context, config *profilemanager.Config, hint string) (OAuthFlow, error) {
	authClient, err := NewAuth(ctx, config.PrivateKey, config.ManagementURL, config)
	if err != nil {
		return nil, fmt.Errorf("failed to create auth client: %v", err)
	}
	defer authClient.Close()

	deviceFlowInfo, err := authClient.getDeviceFlow(authClient.client)
	if err != nil {
		switch s, ok := gstatus.FromError(err); {
		case ok && s.Code() == codes.NotFound:
			return nil, fmt.Errorf("no SSO provider returned from management. " +
				"Please proceed with setting up this device using setup keys " +
				"https://docs.netbird.io/how-to/register-machines-using-setup-keys")
		case ok && s.Code() == codes.Unimplemented:
			return nil, fmt.Errorf("the management server, %s, does not support SSO providers, "+
				"please update your server or use Setup Keys to login", config.ManagementURL)
		default:
			return nil, fmt.Errorf("getting device authorization flow info failed with error: %v", err)
		}
	}

	if hint != "" {
		deviceFlowInfo.SetLoginHint(hint)
	}

	return deviceFlowInfo, nil
}

// RetryFlowForAccount returns a flow that asks the IdP to re-authenticate, for
// a login answered with an account other than the one hinted. Returns nil when
// the flow cannot ask — the caller then proceeds with the token it has.
//
// Proceeding rather than failing is deliberate. The hint is an email that may
// simply have changed since it was stored, and refusing the login would lock a
// user out of their own profile over a rename. The retry gives the account a
// chance to be corrected; the server still rejects a token that does not own
// the peer.
func RetryFlowForAccount(flow OAuthFlow) OAuthFlow {
	forcer, ok := flow.(accountPromptForcer)
	if !ok {
		return nil
	}
	forcer.ForceAccountPrompt()
	return flow
}
