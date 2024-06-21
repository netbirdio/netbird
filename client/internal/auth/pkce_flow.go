package auth

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"html/template"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
	"golang.org/x/oauth2"

	"github.com/netbirdio/netbird/client/internal"
	"github.com/netbirdio/netbird/client/internal/templates"
)

var _ OAuthFlow = &PKCEAuthorizationFlow{}

const (
	queryState                = "state"
	queryCode                 = "code"
	queryError                = "error"
	queryErrorDesc            = "error_description"
	defaultPKCETimeoutSeconds = 300
)

// PKCEAuthorizationFlow implements the OAuthFlow interface for
// the Authorization Code Flow with PKCE.
type PKCEAuthorizationFlow struct {
	providerConfig internal.PKCEAuthProviderConfig
	state          string
	codeVerifier   string
	oAuthConfig    *oauth2.Config
}

// NewPKCEAuthorizationFlow returns new PKCE authorization code flow.
func NewPKCEAuthorizationFlow(config internal.PKCEAuthProviderConfig) (*PKCEAuthorizationFlow, error) {
	var availableRedirectURL string

	// find the first available redirect URL
	for _, redirectURL := range config.RedirectURLs {
		if !isRedirectURLPortUsed(redirectURL) {
			availableRedirectURL = redirectURL
			break
		}
	}

	if availableRedirectURL == "" {
		return nil, fmt.Errorf("no available port found from configured redirect URLs: %q", config.RedirectURLs)
	}

	cfg := &oauth2.Config{
		ClientID:     config.ClientID,
		ClientSecret: config.ClientSecret,
		Endpoint: oauth2.Endpoint{
			AuthURL:  config.AuthorizationEndpoint,
			TokenURL: config.TokenEndpoint,
		},
		RedirectURL: availableRedirectURL,
		Scopes:      strings.Split(config.Scope, " "),
	}

	return &PKCEAuthorizationFlow{
		providerConfig: config,
		oAuthConfig:    cfg,
	}, nil
}

// GetClientID returns the provider client id
func (p *PKCEAuthorizationFlow) GetClientID(_ context.Context) string {
	return p.providerConfig.ClientID
}

// RequestAuthInfo requests a authorization code login flow information.
func (p *PKCEAuthorizationFlow) RequestAuthInfo(ctx context.Context) (AuthFlowInfo, error) {
	state, err := randomBytesInHex(24)
	if err != nil {
		return AuthFlowInfo{}, fmt.Errorf("could not generate random state: %v", err)
	}
	p.state = state

	codeVerifier, err := randomBytesInHex(64)
	if err != nil {
		return AuthFlowInfo{}, fmt.Errorf("could not create a code verifier: %v", err)
	}
	p.codeVerifier = codeVerifier

	codeChallenge := createCodeChallenge(codeVerifier)
	authURL := p.oAuthConfig.AuthCodeURL(
		state,
		oauth2.SetAuthURLParam("code_challenge_method", "S256"),
		oauth2.SetAuthURLParam("code_challenge", codeChallenge),
		oauth2.SetAuthURLParam("audience", p.providerConfig.Audience),
	)

	return AuthFlowInfo{
		VerificationURIComplete: authURL,
		ExpiresIn:               defaultPKCETimeoutSeconds,
	}, nil
}

// WaitToken waits for the OAuth token in the PKCE Authorization Flow.
// It starts an HTTP server to receive the OAuth token callback and waits for the token or an error.
// Once the token is received, it is converted to TokenInfo and validated before returning.
func (p *PKCEAuthorizationFlow) WaitToken(ctx context.Context, _ AuthFlowInfo) (TokenInfo, error) {
	tokenChan := make(chan *oauth2.Token, 1)
	errChan := make(chan error, 1)

	parsedURL, err := url.Parse(p.oAuthConfig.RedirectURL)
	if err != nil {
		return TokenInfo{}, fmt.Errorf("failed to parse redirect URL: %v", err)
	}

	server := &http.Server{Addr: fmt.Sprintf(":%s", parsedURL.Port())}
	defer func() {
		shutdownCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()

		if err := server.Shutdown(shutdownCtx); err != nil {
			log.Errorf("failed to close the server: %v", err)
		}
	}()

	go p.startServer(server, tokenChan, errChan)

	select {
	case <-ctx.Done():
		return TokenInfo{}, ctx.Err()
	case token := <-tokenChan:
		return p.parseOAuthToken(token)
	case err := <-errChan:
		return TokenInfo{}, err
	}
}

func (p *PKCEAuthorizationFlow) startServer(server *http.Server, tokenChan chan<- *oauth2.Token, errChan chan<- error) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, req *http.Request) {
		token, err := p.handleRequest(req)
		if err != nil {
			renderPKCEFlowTmpl(w, err)
			errChan <- fmt.Errorf("PKCE authorization flow failed: %v", err)
			return
		}

		renderPKCEFlowTmpl(w, nil)
		tokenChan <- token
	})

	server.Handler = mux
	if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		errChan <- err
	}
}

func (p *PKCEAuthorizationFlow) handleRequest(req *http.Request) (*oauth2.Token, error) {
	query := req.URL.Query()

	if authError := query.Get(queryError); authError != "" {
		authErrorDesc := query.Get(queryErrorDesc)
		return nil, fmt.Errorf("%s.%s", authError, authErrorDesc)
	}

	// Prevent timing attacks on the state
	if state := query.Get(queryState); subtle.ConstantTimeCompare([]byte(p.state), []byte(state)) == 0 {
		return nil, fmt.Errorf("invalid state")
	}

	code := query.Get(queryCode)
	if code == "" {
		return nil, fmt.Errorf("missing code")
	}

	return p.oAuthConfig.Exchange(
		req.Context(),
		code,
		oauth2.SetAuthURLParam("code_verifier", p.codeVerifier),
	)
}

func (p *PKCEAuthorizationFlow) parseOAuthToken(token *oauth2.Token) (TokenInfo, error) {
	tokenInfo := TokenInfo{
		AccessToken:  token.AccessToken,
		RefreshToken: token.RefreshToken,
		TokenType:    token.TokenType,
		ExpiresIn:    token.Expiry.Second(),
		UseIDToken:   p.providerConfig.UseIDToken,
	}
	if idToken, ok := token.Extra("id_token").(string); ok {
		tokenInfo.IDToken = idToken
	}

	// if a provider doesn't support an audience, use the Client ID for token verification
	audience := p.providerConfig.Audience
	if audience == "" {
		audience = p.providerConfig.ClientID
	}

	if err := isValidAccessToken(tokenInfo.GetTokenToUse(), audience); err != nil {
		return TokenInfo{}, fmt.Errorf("validate access token failed with error: %v", err)
	}

	return tokenInfo, nil
}

func createCodeChallenge(codeVerifier string) string {
	sha2 := sha256.Sum256([]byte(codeVerifier))
	return base64.RawURLEncoding.EncodeToString(sha2[:])
}

// isRedirectURLPortUsed checks if the port used in the redirect URL is in use.
func isRedirectURLPortUsed(redirectURL string) bool {
	parsedURL, err := url.Parse(redirectURL)
	if err != nil {
		log.Errorf("failed to parse redirect URL: %v", err)
		return true
	}

	addr := fmt.Sprintf(":%s", parsedURL.Port())
	conn, err := net.DialTimeout("tcp", addr, 3*time.Second)
	if err != nil {
		return false
	}
	defer func() {
		if err := conn.Close(); err != nil {
			log.Errorf("error while closing the connection: %v", err)
		}
	}()

	return true
}

func renderPKCEFlowTmpl(w http.ResponseWriter, authError error) {
	tmpl, err := template.New("pkce-auth-flow").Parse(templates.PKCEAuthMsgTmpl)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	data := make(map[string]string)
	if authError != nil {
		data["Error"] = authError.Error()
	}

	if err := tmpl.Execute(w, data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}
