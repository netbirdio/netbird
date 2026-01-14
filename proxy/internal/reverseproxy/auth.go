package reverseproxy

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/shared/auth/jwt"
)

const (
	// Default values for authentication
	defaultSessionCookieName = "auth_session"
	defaultPINHeader         = "X-PIN"

	// OIDC state expiration time
	oidcStateExpiration = 10 * time.Minute

	// Error messages
	errInternalServer = "Internal Server Error"
)

// Global state store for OIDC flow (state -> original URL)
var (
	oidcStateStore = &stateStore{
		states: make(map[string]*oidcState),
	}
)

type stateStore struct {
	mu     sync.RWMutex
	states map[string]*oidcState
}

type oidcState struct {
	originalURL string
	createdAt   time.Time
	routeID     string
}

func (s *stateStore) Store(state, originalURL, routeID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.states[state] = &oidcState{
		originalURL: originalURL,
		createdAt:   time.Now(),
		routeID:     routeID,
	}

	// Clean up expired states
	cutoff := time.Now().Add(-oidcStateExpiration)
	for k, v := range s.states {
		if v.createdAt.Before(cutoff) {
			delete(s.states, k)
		}
	}
}

func (s *stateStore) Get(state string) (*oidcState, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	st, ok := s.states[state]
	return st, ok
}

func (s *stateStore) Delete(state string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.states, state)
}

// AuthConfig holds the authentication configuration for a route
// Only ONE auth method should be configured per route
type AuthConfig struct {
	// HTTP Basic authentication (username/password)
	BasicAuth *BasicAuthConfig

	// PIN authentication
	PIN *PINConfig

	// Bearer token with JWT validation and OAuth/OIDC flow
	// When enabled, uses the global OIDCConfig from proxy Config
	Bearer *BearerConfig
}

// BasicAuthConfig holds HTTP Basic authentication settings
type BasicAuthConfig struct {
	Username string
	Password string
}

// PINConfig holds PIN authentication settings
type PINConfig struct {
	PIN    string
	Header string // Header name (default: "X-PIN")
}

// BearerConfig holds JWT/OAuth/OIDC bearer token authentication settings
// The actual OIDC/JWT configuration comes from the global proxy Config.OIDCConfig
// This just enables Bearer auth for a specific route
type BearerConfig struct {
	// Enable bearer token authentication for this route
	// Uses the global OIDC configuration from proxy Config
	Enabled bool
}

// IsEmpty returns true if no auth methods are configured
func (c *AuthConfig) IsEmpty() bool {
	if c == nil {
		return true
	}
	return c.BasicAuth == nil && c.PIN == nil && c.Bearer == nil
}

// authMiddlewareHandler is a static middleware that checks AuthConfig
type authMiddlewareHandler struct {
	next           http.Handler
	authConfig     *AuthConfig
	routeID        string
	rejectResponse func(w http.ResponseWriter, r *http.Request)
	oidcConfig     *OIDCConfig    // Global OIDC configuration from proxy
	jwtValidator   *jwt.Validator // JWT validator instance (lazily initialized)
	validatorMu    sync.Mutex     // Mutex for thread-safe validator initialization
}

func (h *authMiddlewareHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// If no auth configured, allow request
	if h.authConfig.IsEmpty() {
		log.WithFields(log.Fields{
			"route_id":    h.routeID,
			"auth_method": "none",
			"path":        r.URL.Path,
		}).Debug("No authentication configured, allowing request")
		r.Header.Set("X-Auth-Method", "none")
		h.next.ServeHTTP(w, r)
		return
	}

	var authMethod string
	var userID string
	authenticated := false

	// 1. Check Basic Auth
	if h.authConfig.BasicAuth != nil {
		if auth := r.Header.Get("Authorization"); auth != "" && strings.HasPrefix(auth, "Basic ") {
			encoded := strings.TrimPrefix(auth, "Basic ")
			if decoded, err := base64.StdEncoding.DecodeString(encoded); err == nil {
				credentials := string(decoded)
				parts := strings.SplitN(credentials, ":", 2)
				if len(parts) == 2 {
					username, password := parts[0], parts[1]
					if username == h.authConfig.BasicAuth.Username && password == h.authConfig.BasicAuth.Password {
						authenticated = true
						authMethod = "basic"
						userID = username
					}
				}
			}
		}
	}

	// 2. Check PIN (if not already authenticated)
	if !authenticated && h.authConfig.PIN != nil {
		headerName := h.authConfig.PIN.Header
		if headerName == "" {
			headerName = defaultPINHeader
		}
		if pin := r.Header.Get(headerName); pin != "" {
			if pin == h.authConfig.PIN.PIN {
				authenticated = true
				authMethod = "pin"
				userID = "pin_user" // PIN doesn't have a specific user ID
			}
		}
	}

	// 3. Check Bearer Token with JWT validation (if not already authenticated)
	if !authenticated && h.authConfig.Bearer != nil && h.oidcConfig != nil {
		cookieName := h.oidcConfig.SessionCookieName
		if cookieName == "" {
			cookieName = defaultSessionCookieName
		}

		// First, check if there's an _auth_token query parameter (from callback redirect)
		// This allows us to set the cookie for the current domain
		if authToken := r.URL.Query().Get("_auth_token"); authToken != "" {
			log.WithFields(log.Fields{
				"route_id": h.routeID,
				"host":     r.Host,
			}).Info("Found auth token in query parameter, setting cookie and redirecting")

			// Validate the token before setting cookie
			if h.validateJWT(authToken) {
				// Set cookie for current domain
				cookie := &http.Cookie{
					Name:     cookieName,
					Value:    authToken,
					Path:     "/",
					MaxAge:   3600, // 1 hour
					HttpOnly: true,
					Secure:   false, // Set to false for HTTP testing, true for HTTPS in production
					SameSite: http.SameSiteLaxMode,
				}
				http.SetCookie(w, cookie)

				// Redirect to same URL without the token parameter
				cleanURL := *r.URL
				q := cleanURL.Query()
				q.Del("_auth_token")
				cleanURL.RawQuery = q.Encode()

				// Build full URL with scheme and host
				scheme := "http"
				if r.TLS != nil {
					scheme = "https"
				}
				redirectURL := fmt.Sprintf("%s://%s%s", scheme, r.Host, cleanURL.String())

				log.WithFields(log.Fields{
					"route_id":     h.routeID,
					"redirect_url": redirectURL,
				}).Debug("Redirecting to clean URL after setting cookie")

				http.Redirect(w, r, redirectURL, http.StatusFound)
				return
			} else {
				log.WithFields(log.Fields{
					"route_id": h.routeID,
				}).Warn("Invalid token in query parameter")
			}
		}

		// Check if we have an existing session cookie (from OIDC flow)
		log.WithFields(log.Fields{
			"route_id":    h.routeID,
			"cookie_name": cookieName,
			"host":        r.Host,
			"path":        r.URL.Path,
		}).Debug("Checking for session cookie")

		if cookie, err := r.Cookie(cookieName); err == nil && cookie.Value != "" {
			log.WithFields(log.Fields{
				"route_id":    h.routeID,
				"cookie_name": cookieName,
			}).Debug("Session cookie found, validating JWT")

			// Validate the JWT token from the session cookie
			if h.validateJWT(cookie.Value) {
				authenticated = true
				authMethod = "bearer_session"
				userID = h.extractUserIDFromJWT(cookie.Value)
			} else {
				log.WithFields(log.Fields{
					"route_id": h.routeID,
				}).Debug("JWT validation failed for session cookie")
			}
		} else {
			log.WithFields(log.Fields{
				"route_id": h.routeID,
				"error":    err,
			}).Debug("No session cookie found")
		}

		// If no session cookie or validation failed, check Authorization header
		if !authenticated {
			if auth := r.Header.Get("Authorization"); auth != "" && strings.HasPrefix(auth, "Bearer ") {
				token := strings.TrimPrefix(auth, "Bearer ")
				// Validate JWT token from Authorization header
				if h.validateJWT(token) {
					authenticated = true
					authMethod = "bearer"
					userID = h.extractUserIDFromJWT(token)
				}
			} else {
				// No bearer token and no valid session - redirect to OIDC provider
				if h.oidcConfig.ProviderURL != "" {
					// Initiate OAuth/OIDC flow
					h.redirectToOIDC(w, r)
					return
				}
			}
		}
	}

	// Reject if authentication failed
	if !authenticated {
		log.WithFields(log.Fields{
			"route_id":  h.routeID,
			"path":      r.URL.Path,
			"source_ip": extractSourceIP(r),
		}).Warn("Authentication failed")

		// Call custom reject response or use default
		if h.rejectResponse != nil {
			h.rejectResponse(w, r)
		} else {
			// Default: return 401 with WWW-Authenticate header
			w.Header().Set("WWW-Authenticate", `Bearer realm="Restricted"`)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
		}
		return
	}

	log.WithFields(log.Fields{
		"route_id":    h.routeID,
		"auth_method": authMethod,
		"user_id":     userID,
		"path":        r.URL.Path,
	}).Debug("Authentication successful")

	// Store auth info in headers for logging
	r.Header.Set("X-Auth-Method", authMethod)
	r.Header.Set("X-Auth-User-ID", userID)

	// Continue to next handler
	h.next.ServeHTTP(w, r)
}

// redirectToOIDC initiates the OAuth/OIDC authentication flow
func (h *authMiddlewareHandler) redirectToOIDC(w http.ResponseWriter, r *http.Request) {
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
	oidcStateStore.Store(state, originalURL, h.routeID)

	// Default scopes if not configured
	scopes := h.oidcConfig.Scopes
	if len(scopes) == 0 {
		scopes = []string{"openid", "profile", "email"}
	}

	// Build authorization URL
	authURL, err := url.Parse(h.oidcConfig.ProviderURL)
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
	params.Set("client_id", h.oidcConfig.ClientID)
	params.Set("redirect_uri", h.oidcConfig.RedirectURL)
	params.Set("response_type", "code")
	params.Set("scope", strings.Join(scopes, " "))
	params.Set("state", state)

	// Add audience parameter to get an access token for the API
	// This ensures we get a proper JWT for the API audience, not just an ID token
	if len(h.oidcConfig.JWTAudience) > 0 && h.oidcConfig.JWTAudience[0] != h.oidcConfig.ClientID {
		params.Set("audience", h.oidcConfig.JWTAudience[0])
	}

	authURL.RawQuery = params.Encode()

	log.WithFields(log.Fields{
		"route_id":     h.routeID,
		"provider_url": authURL.String(),
		"redirect_url": h.oidcConfig.RedirectURL,
		"state":        state,
	}).Info("Redirecting to OIDC provider for authentication")

	// Redirect user to identity provider login page
	http.Redirect(w, r, authURL.String(), http.StatusFound)
}

// generateRandomString generates a cryptographically secure random string
func generateRandomString(length int) (string, error) {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(bytes)[:length], nil
}

// HandleOIDCCallback handles the callback from the OIDC provider
// This should be registered as a route handler for the callback URL
func HandleOIDCCallback(oidcConfig *OIDCConfig) http.HandlerFunc {
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
		oidcSt, ok := oidcStateStore.Get(state)
		if !ok {
			log.Error("Invalid or expired OIDC state")
			http.Error(w, "Invalid or expired state parameter", http.StatusBadRequest)
			return
		}

		// Delete state to prevent reuse
		oidcStateStore.Delete(state)

		// Exchange authorization code for token
		token, err := exchangeCodeForToken(code, oidcConfig)
		if err != nil {
			log.WithError(err).Error("Failed to exchange code for token")
			http.Error(w, "Authentication failed", http.StatusUnauthorized)
			return
		}

		// Parse the original URL to add the token as a query parameter
		origURL, err := url.Parse(oidcSt.originalURL)
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
			"route_id":      oidcSt.routeID,
			"original_url":  oidcSt.originalURL,
			"redirect_url":  origURL.String(),
			"callback_host": r.Host,
		}).Info("OIDC authentication successful, redirecting with token parameter")

		// Redirect back to original URL with token parameter
		http.Redirect(w, r, origURL.String(), http.StatusFound)
	}
}

// exchangeCodeForToken exchanges an authorization code for an access token
func exchangeCodeForToken(code string, config *OIDCConfig) (string, error) {
	// Build token endpoint URL
	tokenURL, err := url.Parse(config.ProviderURL)
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
	data.Set("redirect_uri", config.RedirectURL)
	data.Set("client_id", config.ClientID)

	// Only include client_secret if it's provided (not needed for public/SPA clients)
	if config.ClientSecret != "" {
		data.Set("client_secret", config.ClientSecret)
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

// getOrInitValidator lazily initializes and returns the JWT validator
func (h *authMiddlewareHandler) getOrInitValidator() *jwt.Validator {
	h.validatorMu.Lock()
	defer h.validatorMu.Unlock()

	if h.jwtValidator == nil {
		h.jwtValidator = jwt.NewValidator(
			h.oidcConfig.JWTIssuer,
			h.oidcConfig.JWTAudience,
			h.oidcConfig.JWTKeysLocation,
			h.oidcConfig.JWTIdpSignkeyRefreshEnabled,
		)
	}

	return h.jwtValidator
}

// validateJWT validates a JWT token using the handler's JWT validator
func (h *authMiddlewareHandler) validateJWT(tokenString string) bool {
	if h.oidcConfig == nil || h.oidcConfig.JWTKeysLocation == "" {
		log.Error("JWT validation failed: OIDC config or JWTKeysLocation is missing")
		return false
	}

	// Get or initialize validator
	validator := h.getOrInitValidator()

	// Validate the token
	ctx := context.Background()
	parsedToken, err := validator.ValidateAndParse(ctx, tokenString)
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

// extractUserIDFromJWT extracts the user ID from a JWT token
func (h *authMiddlewareHandler) extractUserIDFromJWT(tokenString string) string {
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

// wrapWithAuth wraps a handler with the static authentication middleware
// This ALWAYS runs (even when authConfig is nil or empty)
func wrapWithAuth(next http.Handler, authConfig *AuthConfig, routeID string, rejectResponse func(w http.ResponseWriter, r *http.Request), oidcConfig *OIDCConfig) http.Handler {
	if authConfig == nil {
		authConfig = &AuthConfig{} // Empty config = no auth
	}

	return &authMiddlewareHandler{
		next:           next,
		authConfig:     authConfig,
		routeID:        routeID,
		rejectResponse: rejectResponse,
		oidcConfig:     oidcConfig,
	}
}
