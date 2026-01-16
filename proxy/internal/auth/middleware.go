package auth

import (
	"fmt"
	"net/http"
	"strings"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/proxy/internal/auth/oidc"
)

// Middleware wraps an HTTP handler with authentication middleware
type Middleware struct {
	next           http.Handler
	config         *Config
	routeID        string
	rejectResponse func(w http.ResponseWriter, r *http.Request)
	oidcHandler    *oidc.Handler // OIDC handler for OAuth flow (contains config and JWT validator)
}

// authResult holds the result of an authentication attempt
type authResult struct {
	authenticated bool
	method        string
	userID        string
}

// ServeHTTP implements the http.Handler interface
func (m *Middleware) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if m.config.IsEmpty() {
		m.allowWithoutAuth(w, r)
		return
	}

	result := m.authenticate(w, r)
	if result == nil {
		// Authentication triggered a redirect (e.g., OIDC flow)
		return
	}

	if !result.authenticated {
		m.rejectRequest(w, r)
		return
	}

	m.continueWithAuth(w, r, result)
}

// allowWithoutAuth allows requests when no authentication is configured
func (m *Middleware) allowWithoutAuth(w http.ResponseWriter, r *http.Request) {
	log.WithFields(log.Fields{
		"route_id":    m.routeID,
		"auth_method": "none",
		"path":        r.URL.Path,
	}).Debug("No authentication configured, allowing request")
	r.Header.Set("X-Auth-Method", "none")
	m.next.ServeHTTP(w, r)
}

// authenticate attempts to authenticate the request using configured methods
// Returns nil if a redirect occurred (e.g., OIDC flow initiated)
func (m *Middleware) authenticate(w http.ResponseWriter, r *http.Request) *authResult {
	if result := m.tryBasicAuth(r); result.authenticated {
		return result
	}

	if result := m.tryPINAuth(r); result.authenticated {
		return result
	}

	return m.tryBearerAuth(w, r)
}

// tryBasicAuth attempts Basic authentication
func (m *Middleware) tryBasicAuth(r *http.Request) *authResult {
	if m.config.BasicAuth == nil {
		return &authResult{}
	}

	if !m.config.BasicAuth.Validate(r) {
		return &authResult{}
	}

	result := &authResult{
		authenticated: true,
		method:        "basic",
	}

	if username, _, ok := r.BasicAuth(); ok {
		result.userID = username
	}

	return result
}

// tryPINAuth attempts PIN authentication
func (m *Middleware) tryPINAuth(r *http.Request) *authResult {
	if m.config.PIN == nil {
		return &authResult{}
	}

	if !m.config.PIN.Validate(r) {
		return &authResult{}
	}

	return &authResult{
		authenticated: true,
		method:        "pin",
		userID:        "pin_user",
	}
}

// tryBearerAuth attempts Bearer token authentication with JWT validation
// Returns nil if OIDC redirect occurred
func (m *Middleware) tryBearerAuth(w http.ResponseWriter, r *http.Request) *authResult {
	if m.config.Bearer == nil || m.oidcHandler == nil {
		return &authResult{}
	}

	cookieName := m.oidcHandler.SessionCookieName()

	if m.handleAuthTokenParameter(w, r, cookieName) {
		return nil
	}

	if result := m.trySessionCookie(r, cookieName); result.authenticated {
		return result
	}

	if result := m.tryAuthorizationHeader(r); result.authenticated {
		return result
	}

	m.oidcHandler.RedirectToProvider(w, r, m.routeID)
	return nil
}

// handleAuthTokenParameter processes the _auth_token query parameter from OIDC callback
// Returns true if a redirect occurred
func (m *Middleware) handleAuthTokenParameter(w http.ResponseWriter, r *http.Request, cookieName string) bool {
	authToken := r.URL.Query().Get("_auth_token")
	if authToken == "" {
		return false
	}

	log.WithFields(log.Fields{
		"route_id": m.routeID,
		"host":     r.Host,
	}).Info("Found auth token in query parameter, setting cookie and redirecting")

	if !m.oidcHandler.ValidateJWT(authToken) {
		log.WithFields(log.Fields{
			"route_id": m.routeID,
		}).Warn("Invalid token in query parameter")
		return false
	}

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
	redirectURL := m.buildCleanRedirectURL(r)

	log.WithFields(log.Fields{
		"route_id":     m.routeID,
		"redirect_url": redirectURL,
	}).Debug("Redirecting to clean URL after setting cookie")

	http.Redirect(w, r, redirectURL, http.StatusFound)
	return true
}

// buildCleanRedirectURL builds a redirect URL without the _auth_token parameter
func (m *Middleware) buildCleanRedirectURL(r *http.Request) string {
	cleanURL := *r.URL
	q := cleanURL.Query()
	q.Del("_auth_token")
	cleanURL.RawQuery = q.Encode()

	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}

	return fmt.Sprintf("%s://%s%s", scheme, r.Host, cleanURL.String())
}

// trySessionCookie attempts authentication using a session cookie
func (m *Middleware) trySessionCookie(r *http.Request, cookieName string) *authResult {
	log.WithFields(log.Fields{
		"route_id":    m.routeID,
		"cookie_name": cookieName,
		"host":        r.Host,
		"path":        r.URL.Path,
	}).Debug("Checking for session cookie")

	cookie, err := r.Cookie(cookieName)
	if err != nil || cookie.Value == "" {
		log.WithFields(log.Fields{
			"route_id": m.routeID,
			"error":    err,
		}).Debug("No session cookie found")
		return &authResult{}
	}

	log.WithFields(log.Fields{
		"route_id":    m.routeID,
		"cookie_name": cookieName,
	}).Debug("Session cookie found, validating JWT")

	if !m.oidcHandler.ValidateJWT(cookie.Value) {
		log.WithFields(log.Fields{
			"route_id": m.routeID,
		}).Debug("JWT validation failed for session cookie")
		return &authResult{}
	}

	return &authResult{
		authenticated: true,
		method:        "bearer_session",
		userID:        m.oidcHandler.ExtractUserID(cookie.Value),
	}
}

// tryAuthorizationHeader attempts authentication using the Authorization header
func (m *Middleware) tryAuthorizationHeader(r *http.Request) *authResult {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
		return &authResult{}
	}

	token := strings.TrimPrefix(authHeader, "Bearer ")
	if !m.oidcHandler.ValidateJWT(token) {
		return &authResult{}
	}

	return &authResult{
		authenticated: true,
		method:        "bearer",
		userID:        m.oidcHandler.ExtractUserID(token),
	}
}

// rejectRequest rejects an unauthenticated request
func (m *Middleware) rejectRequest(w http.ResponseWriter, r *http.Request) {
	log.WithFields(log.Fields{
		"route_id": m.routeID,
		"path":     r.URL.Path,
	}).Warn("Authentication failed")

	if m.rejectResponse != nil {
		m.rejectResponse(w, r)
	} else {
		w.Header().Set("WWW-Authenticate", `Bearer realm="Restricted"`)
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
	}
}

// continueWithAuth continues the request with authenticated user info
func (m *Middleware) continueWithAuth(w http.ResponseWriter, r *http.Request, result *authResult) {
	log.WithFields(log.Fields{
		"route_id":    m.routeID,
		"auth_method": result.method,
		"user_id":     result.userID,
		"path":        r.URL.Path,
	}).Debug("Authentication successful")

	// TODO: Find other means of auth logging than headers
	r.Header.Set("X-Auth-Method", result.method)
	r.Header.Set("X-Auth-User-ID", result.userID)

	// Continue to next handler
	m.next.ServeHTTP(w, r)
}

// Wrap wraps an HTTP handler with authentication middleware
func Wrap(next http.Handler, authConfig *Config, routeID string, rejectResponse func(w http.ResponseWriter, r *http.Request), oidcHandler *oidc.Handler) http.Handler {
	if authConfig == nil {
		authConfig = &Config{}
	}

	return &Middleware{
		next:           next,
		config:         authConfig,
		routeID:        routeID,
		rejectResponse: rejectResponse,
		oidcHandler:    oidcHandler,
	}
}
