package auth

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"github.com/netbirdio/netbird/client/internal"
	"golang.org/x/oauth2"
	"io"
	"strings"
)

var _ OAuthFlow = &PKCEAuthorizationFlow{}

const (
	QUERY_STATE = "state"
	QUERY_CODE  = "code"
)

// PKCEAuthorizationFlow implements the OAuthFlow interface for the Authorization Code Flow with PKCE
type PKCEAuthorizationFlow struct {
	ProviderConfig internal.PKCEAuthProviderConfig
	State          string
	CodeVerifier   string
	OAuthConfig    *oauth2.Config
}

// NewPKCEAuthorizationFlow returns new PKCE authorization code flow
func NewPKCEAuthorizationFlow(config internal.PKCEAuthProviderConfig) (*PKCEAuthorizationFlow, error) {
	cfg := &oauth2.Config{
		ClientID:     config.ClientID,
		ClientSecret: config.ClientSecret,
		Endpoint: oauth2.Endpoint{
			AuthURL:  config.AuthorizationEndpoint,
			TokenURL: config.TokenEndpoint,
		},
		RedirectURL: config.RedirectURL,
		Scopes:      strings.Split(config.Scope, " "),
	}

	return &PKCEAuthorizationFlow{
		ProviderConfig: config,
		OAuthConfig:    cfg,
	}, nil
}

func (p *PKCEAuthorizationFlow) GetClientID(_ context.Context) string {
	return p.ProviderConfig.ClientID
}

func (p *PKCEAuthorizationFlow) RequestAuthInfo(_ context.Context) (AuthFlowInfo, error) {
	codeVerifier, err := randomBytesInHex(64)
	if err != nil {
		return AuthFlowInfo{}, fmt.Errorf("could not create a code verifier: %v", err)
	}
	p.CodeVerifier = codeVerifier

	sha2 := sha256.New()
	_, err = io.WriteString(sha2, codeVerifier)
	if err != nil {
		return AuthFlowInfo{}, err
	}

	codeChallenge := base64.RawURLEncoding.EncodeToString(sha2.Sum(nil))

	state, err := randomBytesInHex(24)
	if err != nil {
		return AuthFlowInfo{}, fmt.Errorf("could not generate random state: %v", err)
	}
	p.State = state

	authURL := p.OAuthConfig.AuthCodeURL(
		state,
		oauth2.SetAuthURLParam("code_challenge_method", "S256"),
		oauth2.SetAuthURLParam("code_challenge", codeChallenge),
		oauth2.SetAuthURLParam("audience", p.ProviderConfig.Audience),
	)

	p.State = state
	return AuthFlowInfo{
		VerificationURIComplete: authURL,
	}, nil
}

func (p *PKCEAuthorizationFlow) WaitToken(_ context.Context, _ AuthFlowInfo) (TokenInfo, error) {
	return TokenInfo{}, nil
}
