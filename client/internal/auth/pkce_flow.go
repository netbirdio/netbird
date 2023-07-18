package auth

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"github.com/netbirdio/netbird/client/internal"
	"golang.org/x/oauth2"
	"io"
	"net/http"
	"strings"
)

var _ OAuthFlow = &PKCEAuthorizationFlow{}

const (
	queryState = "state"
	queryCode  = "code"
)

// PKCEAuthorizationFlow implements the OAuthFlow interface for the Authorization Code Flow with PKCE
type PKCEAuthorizationFlow struct {
	providerConfig internal.PKCEAuthProviderConfig
	state          string
	codeVerifier   string
	oAuthConfig    *oauth2.Config
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
		providerConfig: config,
		oAuthConfig:    cfg,
	}, nil
}

func (p *PKCEAuthorizationFlow) GetClientID(_ context.Context) string {
	return p.providerConfig.ClientID
}

func (p *PKCEAuthorizationFlow) RequestAuthInfo(_ context.Context) (AuthFlowInfo, error) {
	codeVerifier, err := randomBytesInHex(64)
	if err != nil {
		return AuthFlowInfo{}, fmt.Errorf("could not create a code verifier: %v", err)
	}
	p.codeVerifier = codeVerifier

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
	p.state = state

	authURL := p.oAuthConfig.AuthCodeURL(
		state,
		oauth2.SetAuthURLParam("code_challenge_method", "S256"),
		oauth2.SetAuthURLParam("code_challenge", codeChallenge),
		oauth2.SetAuthURLParam("audience", p.providerConfig.Audience),
	)

	return AuthFlowInfo{
		VerificationURIComplete: authURL,
	}, nil
}

func (p *PKCEAuthorizationFlow) WaitToken(_ context.Context, _ AuthFlowInfo) (TokenInfo, error) {
	tokenChan := make(chan *oauth2.Token, 1)
	errChan := make(chan error, 1)

	server := http.Server{Addr: p.providerConfig.RedirectURL}
	defer server.Shutdown(context.Background())

	http.HandleFunc("/", func(wr http.ResponseWriter, req *http.Request) {
		query := req.URL.Query()

		state := query.Get(queryState)
		// prevent timing attacks on state
		if subtle.ConstantTimeCompare([]byte(p.state), []byte(state)) == 0 {
			errChan <- fmt.Errorf("invalid state")
			return
		}

		code := query.Get(queryCode)
		if code == "" {
			errChan <- fmt.Errorf("missing code")
			return
		}

		token, err := p.oAuthConfig.Exchange(
			req.Context(),
			code,
			oauth2.SetAuthURLParam("code_verifier", p.codeVerifier),
		)
		if err != nil {
			errChan <- fmt.Errorf("OAuth token exchange failed: %v", err)
			return
		}

		tokenChan <- token
	})

	go func() {
		if err := server.ListenAndServe(); err != nil {
			errChan <- err
		}
	}()

	select {
	case token := <-tokenChan:
		tokenInfo := TokenInfo{
			AccessToken:  token.AccessToken,
			RefreshToken: token.RefreshToken,
			TokenType:    token.TokenType,
			ExpiresIn:    token.Expiry.Second(),
			UseIDToken:   p.providerConfig.UseIDToken,
		}

		idToken, ok := token.Extra("id_token").(string)
		if ok {
			tokenInfo.IDToken = idToken
		}

		err := isValidAccessToken(tokenInfo.GetTokenToUse(), p.providerConfig.Audience)
		if err != nil {
			return TokenInfo{}, fmt.Errorf("validate access token failed with error: %v", err)
		}

		return tokenInfo, nil
	case err := <-errChan:
		return TokenInfo{}, err
	}
}
