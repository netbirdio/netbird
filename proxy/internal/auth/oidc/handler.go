package oidc

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/shared/auth/jwt"
)

// Handler manages OIDC authentication flow
type Handler struct {
	config       *Config
	stateStore   *StateStore
	jwtValidator *jwt.Validator
}

// NewHandler creates a new OIDC handler
func NewHandler(config *Config, stateStore *StateStore) *Handler {
	// Initialize JWT validator
	var jwtValidator *jwt.Validator
	if config.JWTKeysLocation != "" {
		jwtValidator = jwt.NewValidator(
			config.JWTIssuer,
			config.JWTAudience,
			config.JWTKeysLocation,
			config.JWTIdpSignkeyRefreshEnabled,
		)
	}

	return &Handler{
		config:       config,
		stateStore:   stateStore,
		jwtValidator: jwtValidator,
	}
}

// RedirectToProvider initiates the OAuth/OIDC authentication flow by redirecting to the provider
func (h *Handler) RedirectToProvider(w http.ResponseWriter, r *http.Request, routeID string) {
	// Generate random state for CSRF protection
	state, err := generateRandomString(32)
	if err != nil {
		log.WithError(err).Error("Failed to generate OIDC state")
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	// Store state with original URL for redirect after auth
	// Include the full URL with scheme and host
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	originalURL := fmt.Sprintf("%s://%s%s", scheme, r.Host, r.URL.String())
	h.stateStore.Store(state, originalURL, routeID)

	// Default scopes if not configured
	scopes := h.config.Scopes
	if len(scopes) == 0 {
		scopes = []string{"openid", "profile", "email"}
	}

	// Build authorization URL
	authURL, err := url.Parse(h.config.ProviderURL)
	if err != nil {
		log.WithError(err).Error("Invalid OIDC provider URL")
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	// Append /authorize if it doesn't exist (common OIDC endpoint)
	if !strings.HasSuffix(authURL.Path, "/authorize") && !strings.HasSuffix(authURL.Path, "/auth") {
		authURL.Path = strings.TrimSuffix(authURL.Path, "/") + "/authorize"
	}

	// Build query parameters
	params := url.Values{}
	params.Set("client_id", h.config.ClientID)
	params.Set("redirect_uri", h.config.RedirectURL)
	params.Set("response_type", "code")
	params.Set("scope", strings.Join(scopes, " "))
	params.Set("state", state)

	// Add audience parameter to get an access token for the API
	// This ensures we get a proper JWT for the API audience, not just an ID token
	if len(h.config.JWTAudience) > 0 && h.config.JWTAudience[0] != h.config.ClientID {
		params.Set("audience", h.config.JWTAudience[0])
	}

	authURL.RawQuery = params.Encode()

	log.WithFields(log.Fields{
		"route_id":     routeID,
		"provider_url": authURL.String(),
		"redirect_url": h.config.RedirectURL,
		"state":        state,
	}).Info("Redirecting to OIDC provider for authentication")

	// Redirect user to identity provider login page
	http.Redirect(w, r, authURL.String(), http.StatusFound)
}

// HandleCallback creates an HTTP handler for the OIDC callback endpoint
func (h *Handler) HandleCallback() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Get authorization code and state from query parameters
		code := r.URL.Query().Get("code")
		state := r.URL.Query().Get("state")

		if code == "" || state == "" {
			log.Error("Missing code or state in OIDC callback")
			http.Error(w, "Invalid callback parameters", http.StatusBadRequest)
			return
		}

		// Verify state to prevent CSRF
		oidcSt, ok := h.stateStore.Get(state)
		if !ok {
			log.Error("Invalid or expired OIDC state")
			http.Error(w, "Invalid or expired state parameter", http.StatusBadRequest)
			return
		}

		// Delete state to prevent reuse
		h.stateStore.Delete(state)

		// Exchange authorization code for token
		token, err := h.exchangeCodeForToken(code)
		if err != nil {
			log.WithError(err).Error("Failed to exchange code for token")
			http.Error(w, "Authentication failed", http.StatusUnauthorized)
			return
		}

		// Parse the original URL to add the token as a query parameter
		origURL, err := url.Parse(oidcSt.OriginalURL)
		if err != nil {
			log.WithError(err).Error("Failed to parse original URL")
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}

		// Add token as query parameter so the original domain can set its own cookie
		// We use a special parameter name that the auth middleware will look for
		q := origURL.Query()
		q.Set("_auth_token", token)
		origURL.RawQuery = q.Encode()

		log.WithFields(log.Fields{
			"route_id":      oidcSt.RouteID,
			"original_url":  oidcSt.OriginalURL,
			"redirect_url":  origURL.String(),
			"callback_host": r.Host,
		}).Info("OIDC authentication successful, redirecting with token parameter")

		// Redirect back to original URL with token parameter
		http.Redirect(w, r, origURL.String(), http.StatusFound)
	}
}

// exchangeCodeForToken exchanges an authorization code for an access token
func (h *Handler) exchangeCodeForToken(code string) (string, error) {
	// Build token endpoint URL
	tokenURL, err := url.Parse(h.config.ProviderURL)
	if err != nil {
		return "", fmt.Errorf("invalid OIDC provider URL: %w", err)
	}

	// Auth0 uses /oauth/token, standard OIDC uses /token
	// Check if path already contains token endpoint
	if !strings.Contains(tokenURL.Path, "/token") {
		tokenURL.Path = strings.TrimSuffix(tokenURL.Path, "/") + "/oauth/token"
	}

	// Build request body
	data := url.Values{}
	data.Set("grant_type", "authorization_code")
	data.Set("code", code)
	data.Set("redirect_uri", h.config.RedirectURL)
	data.Set("client_id", h.config.ClientID)

	// Only include client_secret if it's provided (not needed for public/SPA clients)
	if h.config.ClientSecret != "" {
		data.Set("client_secret", h.config.ClientSecret)
	}

	// Make token exchange request
	resp, err := http.PostForm(tokenURL.String(), data)
	if err != nil {
		return "", fmt.Errorf("token exchange request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("token exchange failed with status %d: %s", resp.StatusCode, string(body))
	}

	// Parse response
	var tokenResp struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		ExpiresIn   int    `json:"expires_in"`
		IDToken     string `json:"id_token"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return "", fmt.Errorf("failed to decode token response: %w", err)
	}

	if tokenResp.AccessToken == "" {
		return "", fmt.Errorf("no access token in response")
	}

	// Return the ID token if available (contains user claims), otherwise access token
	if tokenResp.IDToken != "" {
		return tokenResp.IDToken, nil
	}

	return tokenResp.AccessToken, nil
}

// ValidateJWT validates a JWT token
func (h *Handler) ValidateJWT(tokenString string) bool {
	if h.jwtValidator == nil {
		log.Error("JWT validation failed: JWT validator not initialized")
		return false
	}

	// Validate the token
	ctx := context.Background()
	parsedToken, err := h.jwtValidator.ValidateAndParse(ctx, tokenString)
	if err != nil {
		log.WithError(err).Error("JWT validation failed")
		// Try to parse token without validation to see what's in it
		parts := strings.Split(tokenString, ".")
		if len(parts) == 3 {
			// Decode payload (middle part)
			payload, err := base64.RawURLEncoding.DecodeString(parts[1])
			if err == nil {
				log.WithFields(log.Fields{
					"payload": string(payload),
				}).Debug("Token payload for debugging")
			}
		}
		return false
	}

	// Token is valid if parsedToken is not nil and Valid is true
	return parsedToken != nil && parsedToken.Valid
}

// ExtractUserID extracts the user ID from a JWT token
func (h *Handler) ExtractUserID(tokenString string) string {
	if h.jwtValidator == nil {
		return ""
	}

	// Parse the token
	ctx := context.Background()
	parsedToken, err := h.jwtValidator.ValidateAndParse(ctx, tokenString)
	if err != nil {
		return ""
	}

	// parsedToken is already *jwtgo.Token from ValidateAndParse
	// Create extractor to get user auth info
	extractor := jwt.NewClaimsExtractor()
	userAuth, err := extractor.ToUserAuth(parsedToken)
	if err != nil {
		log.WithError(err).Debug("Failed to extract user ID from JWT")
		return ""
	}

	return userAuth.UserId
}

// SessionCookieName returns the configured session cookie name or default
func (h *Handler) SessionCookieName() string {
	if h.config.SessionCookieName != "" {
		return h.config.SessionCookieName
	}
	return "auth_session"
}
