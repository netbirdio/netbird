package auth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	log "github.com/sirupsen/logrus"
	"golang.org/x/oauth2"
)

const stateExpiration = 10 * time.Minute

// OIDCConfig holds configuration for OIDC authentication
type OIDCConfig struct {
	OIDCProviderURL  string
	OIDCClientID     string
	OIDCClientSecret string
	OIDCRedirectURL  string
	OIDCScopes       []string
}

// oidcState stores CSRF state with expiration
type oidcState struct {
	OriginalURL string
	CreatedAt   time.Time
}

// OIDC implements the Scheme interface for JWT/OIDC authentication
type OIDC struct {
	id, accountId string
	verifier      *oidc.IDTokenVerifier
	oauthConfig   *oauth2.Config
	states        map[string]*oidcState
	statesMux     sync.RWMutex
}

// NewOIDC creates a new OIDC authentication scheme
func NewOIDC(ctx context.Context, id, accountId string, cfg OIDCConfig) (*OIDC, error) {
	if cfg.OIDCProviderURL == "" || cfg.OIDCClientID == "" {
		return nil, fmt.Errorf("OIDC provider URL and client ID are required")
	}

	scopes := cfg.OIDCScopes
	if len(scopes) == 0 {
		scopes = []string{oidc.ScopeOpenID, "profile", "email"}
	}

	provider, err := oidc.NewProvider(ctx, cfg.OIDCProviderURL)
	if err != nil {
		return nil, fmt.Errorf("failed to create OIDC provider: %w", err)
	}

	o := &OIDC{
		id:        id,
		accountId: accountId,
		verifier: provider.Verifier(&oidc.Config{
			ClientID: cfg.OIDCClientID,
		}),
		oauthConfig: &oauth2.Config{
			ClientID:     cfg.OIDCClientID,
			ClientSecret: cfg.OIDCClientSecret,
			RedirectURL:  cfg.OIDCRedirectURL,
			Scopes:       scopes,
			Endpoint:     provider.Endpoint(),
		},
		states: make(map[string]*oidcState),
	}

	go o.cleanupStates()

	return o, nil
}

func (*OIDC) Type() Method {
	return MethodOIDC
}

func (o *OIDC) Authenticate(r *http.Request) (string, bool, any) {
	// Try Authorization: Bearer <token> header
	if auth := r.Header.Get("Authorization"); strings.HasPrefix(auth, "Bearer ") {
		if userID := o.validateToken(r.Context(), strings.TrimPrefix(auth, "Bearer ")); userID != "" {
			return userID, false, nil
		}
	}

	// Try _auth_token query parameter (from OIDC callback redirect)
	if token := r.URL.Query().Get("_auth_token"); token != "" {
		if userID := o.validateToken(r.Context(), token); userID != "" {
			return userID, true, nil // Redirect needed to clean up URL
		}
	}

	// If the request is not authenticated, return a redirect URL for the UI to
	// route the user through if they select OIDC login.
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	state := base64.URLEncoding.EncodeToString(b)

	// TODO: this does not work if you are load balancing across multiple proxy servers.
	o.statesMux.Lock()
	o.states[state] = &oidcState{OriginalURL: fmt.Sprintf("https://%s%s", r.Host, r.URL), CreatedAt: time.Now()}
	o.statesMux.Unlock()

	return "", false, o.oauthConfig.AuthCodeURL(state)
}

// Middleware returns an http.Handler that handles OIDC callback and flow initiation.
func (o *OIDC) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Handle OIDC callback
		if r.URL.Path == "/oauth/callback" {
			o.handleCallback(w, r)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// validateToken validates a JWT ID token and returns the user ID (subject)
func (o *OIDC) validateToken(ctx context.Context, token string) string {
	if o.verifier == nil {
		return ""
	}

	idToken, err := o.verifier.Verify(ctx, token)
	if err != nil {
		return ""
	}

	return idToken.Subject
}

// handleCallback processes the OIDC callback
func (o *OIDC) handleCallback(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	state := r.URL.Query().Get("state")

	if code == "" || state == "" {
		http.Error(w, "Invalid callback parameters", http.StatusBadRequest)
		return
	}

	// Verify and consume state
	o.statesMux.Lock()
	st, ok := o.states[state]
	if ok {
		delete(o.states, state)
	}
	o.statesMux.Unlock()

	if !ok {
		http.Error(w, "Invalid or expired state", http.StatusBadRequest)
		return
	}

	// Exchange code for token
	token, err := o.oauthConfig.Exchange(r.Context(), code)
	if err != nil {
		log.WithError(err).Error("Token exchange failed")
		http.Error(w, "Authentication failed", http.StatusUnauthorized)
		return
	}

	// Prefer ID token if available
	idToken := token.AccessToken
	if id, ok := token.Extra("id_token").(string); ok && id != "" {
		idToken = id
	}

	// Redirect back to original URL with token
	origURL, err := url.Parse(st.OriginalURL)
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	q := origURL.Query()
	q.Set("_auth_token", idToken)
	origURL.RawQuery = q.Encode()

	http.Redirect(w, r, origURL.String(), http.StatusFound)
}

// cleanupStates periodically removes expired states
func (o *OIDC) cleanupStates() {
	for range time.Tick(time.Minute) {
		cutoff := time.Now().Add(-stateExpiration)
		o.statesMux.Lock()
		for k, v := range o.states {
			if v.CreatedAt.Before(cutoff) {
				delete(o.states, k)
			}
		}
		o.statesMux.Unlock()
	}
}
