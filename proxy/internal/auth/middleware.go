package auth

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"

	"github.com/netbirdio/netbird/proxy/auth"
	"github.com/netbirdio/netbird/proxy/internal/proxy"
	"github.com/netbirdio/netbird/proxy/internal/types"
	"github.com/netbirdio/netbird/proxy/web"
	"github.com/netbirdio/netbird/shared/management/proto"
)

type authenticator interface {
	Authenticate(ctx context.Context, in *proto.AuthenticateRequest, opts ...grpc.CallOption) (*proto.AuthenticateResponse, error)
}

// SessionValidator validates session tokens and checks user access permissions.
type SessionValidator interface {
	ValidateSession(ctx context.Context, in *proto.ValidateSessionRequest, opts ...grpc.CallOption) (*proto.ValidateSessionResponse, error)
}

// Scheme defines an authentication mechanism for a domain.
type Scheme interface {
	Type() auth.Method
	// Authenticate checks the request and determines whether it represents
	// an authenticated user. An empty token indicates an unauthenticated
	// request; optionally, promptData may be returned for the login UI.
	// An error indicates an infrastructure failure (e.g. gRPC unavailable).
	Authenticate(*http.Request) (token string, promptData string, err error)
}

type DomainConfig struct {
	Schemes           []Scheme
	SessionPublicKey  ed25519.PublicKey
	SessionExpiration time.Duration
	AccountID         string
	ServiceID         string
}

type validationResult struct {
	UserID       string
	Valid        bool
	DeniedReason string
}

type Middleware struct {
	domainsMux       sync.RWMutex
	domains          map[string]DomainConfig
	logger           *log.Logger
	sessionValidator SessionValidator
}

// NewMiddleware creates a new authentication middleware.
// The sessionValidator is optional; if nil, OIDC session tokens will be validated
// locally without group access checks.
func NewMiddleware(logger *log.Logger, sessionValidator SessionValidator) *Middleware {
	if logger == nil {
		logger = log.StandardLogger()
	}
	return &Middleware{
		domains:          make(map[string]DomainConfig),
		logger:           logger,
		sessionValidator: sessionValidator,
	}
}

// Protect applies authentication middleware to the passed handler.
// For each incoming request it will be checked against the middleware's
// internal list of protected domains.
// If the Host domain in the inbound request is not present, then it will
// simply be passed through.
// However, if the Host domain is present, then the specified authentication
// schemes for that domain will be applied to the request.
// In the event that no authentication schemes are defined for the domain,
// then the request will also be simply passed through.
func (mw *Middleware) Protect(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host, _, err := net.SplitHostPort(r.Host)
		if err != nil {
			host = r.Host
		}

		config, exists := mw.getDomainConfig(host)
		mw.logger.Debugf("checking authentication for host: %s, exists: %t", host, exists)

		// Domains that are not configured here or have no authentication schemes applied should simply pass through.
		if !exists || len(config.Schemes) == 0 {
			next.ServeHTTP(w, r)
			return
		}

		// Set account and service IDs in captured data for access logging.
		setCapturedIDs(r, config)

		if mw.handleOAuthCallbackError(w, r) {
			return
		}

		if mw.forwardWithSessionCookie(w, r, host, config, next) {
			return
		}

		mw.authenticateWithSchemes(w, r, host, config)
	})
}

func (mw *Middleware) getDomainConfig(host string) (DomainConfig, bool) {
	mw.domainsMux.RLock()
	defer mw.domainsMux.RUnlock()
	config, exists := mw.domains[host]
	return config, exists
}

func setCapturedIDs(r *http.Request, config DomainConfig) {
	if cd := proxy.CapturedDataFromContext(r.Context()); cd != nil {
		cd.SetAccountId(types.AccountID(config.AccountID))
		cd.SetServiceId(config.ServiceID)
	}
}

// handleOAuthCallbackError checks for error query parameters from an OAuth
// callback and renders the access denied page if present.
func (mw *Middleware) handleOAuthCallbackError(w http.ResponseWriter, r *http.Request) bool {
	errCode := r.URL.Query().Get("error")
	if errCode == "" {
		return false
	}

	var requestID string
	if cd := proxy.CapturedDataFromContext(r.Context()); cd != nil {
		cd.SetOrigin(proxy.OriginAuth)
		cd.SetAuthMethod(auth.MethodOIDC.String())
		requestID = cd.GetRequestID()
	}
	errDesc := r.URL.Query().Get("error_description")
	if errDesc == "" {
		errDesc = "An error occurred during authentication"
	}
	web.ServeAccessDeniedPage(w, r, http.StatusForbidden, "Access Denied", errDesc, requestID)
	return true
}

// forwardWithSessionCookie checks for a valid session cookie and, if found,
// sets the user identity on the request context and forwards to the next handler.
func (mw *Middleware) forwardWithSessionCookie(w http.ResponseWriter, r *http.Request, host string, config DomainConfig, next http.Handler) bool {
	cookie, err := r.Cookie(auth.SessionCookieName)
	if err != nil {
		return false
	}
	userID, method, err := auth.ValidateSessionJWT(cookie.Value, host, config.SessionPublicKey)
	if err != nil {
		return false
	}
	if cd := proxy.CapturedDataFromContext(r.Context()); cd != nil {
		cd.SetUserID(userID)
		cd.SetAuthMethod(method)
	}
	next.ServeHTTP(w, r)
	return true
}

// authenticateWithSchemes tries each configured auth scheme in order.
// On success it sets a session cookie and redirects; on failure it renders the login page.
func (mw *Middleware) authenticateWithSchemes(w http.ResponseWriter, r *http.Request, host string, config DomainConfig) {
	methods := make(map[string]string)
	var attemptedMethod string

	for _, scheme := range config.Schemes {
		token, promptData, err := scheme.Authenticate(r)
		if err != nil {
			mw.logger.WithField("scheme", scheme.Type().String()).Warnf("authentication infrastructure error: %v", err)
			if cd := proxy.CapturedDataFromContext(r.Context()); cd != nil {
				cd.SetOrigin(proxy.OriginAuth)
			}
			http.Error(w, "authentication service unavailable", http.StatusBadGateway)
			return
		}

		// Track if credentials were submitted but auth failed
		if token == "" && wasCredentialSubmitted(r, scheme.Type()) {
			attemptedMethod = scheme.Type().String()
		}

		if token != "" {
			mw.handleAuthenticatedToken(w, r, host, token, config, scheme)
			return
		}
		methods[scheme.Type().String()] = promptData
	}

	if cd := proxy.CapturedDataFromContext(r.Context()); cd != nil {
		cd.SetOrigin(proxy.OriginAuth)
		if attemptedMethod != "" {
			cd.SetAuthMethod(attemptedMethod)
		}
	}
	web.ServeHTTP(w, r, map[string]any{"methods": methods}, http.StatusUnauthorized)
}

// handleAuthenticatedToken validates the token, handles denied access, and on
// success sets a session cookie and redirects to the original URL.
func (mw *Middleware) handleAuthenticatedToken(w http.ResponseWriter, r *http.Request, host, token string, config DomainConfig, scheme Scheme) {
	result, err := mw.validateSessionToken(r.Context(), host, token, config.SessionPublicKey, scheme.Type())
	if err != nil {
		if cd := proxy.CapturedDataFromContext(r.Context()); cd != nil {
			cd.SetOrigin(proxy.OriginAuth)
			cd.SetAuthMethod(scheme.Type().String())
		}
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if !result.Valid {
		var requestID string
		if cd := proxy.CapturedDataFromContext(r.Context()); cd != nil {
			cd.SetOrigin(proxy.OriginAuth)
			cd.SetUserID(result.UserID)
			cd.SetAuthMethod(scheme.Type().String())
			requestID = cd.GetRequestID()
		}
		web.ServeAccessDeniedPage(w, r, http.StatusForbidden, "Access Denied", "You are not authorized to access this service", requestID)
		return
	}

	expiration := config.SessionExpiration
	if expiration == 0 {
		expiration = auth.DefaultSessionExpiry
	}
	http.SetCookie(w, &http.Cookie{
		Name:     auth.SessionCookieName,
		Value:    token,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(expiration.Seconds()),
	})

	// Redirect instead of forwarding the auth POST to the backend.
	// The browser will follow with a GET carrying the new session cookie.
	if cd := proxy.CapturedDataFromContext(r.Context()); cd != nil {
		cd.SetOrigin(proxy.OriginAuth)
		cd.SetUserID(result.UserID)
		cd.SetAuthMethod(scheme.Type().String())
	}
	redirectURL := stripSessionTokenParam(r.URL)
	http.Redirect(w, r, redirectURL, http.StatusSeeOther)
}

// wasCredentialSubmitted checks if credentials were submitted for the given auth method.
func wasCredentialSubmitted(r *http.Request, method auth.Method) bool {
	switch method {
	case auth.MethodPIN:
		return r.FormValue("pin") != ""
	case auth.MethodPassword:
		return r.FormValue("password") != ""
	case auth.MethodOIDC:
		return r.URL.Query().Get("session_token") != ""
	}
	return false
}

// AddDomain registers authentication schemes for the given domain.
// If schemes are provided, a valid session public key is required to sign/verify
// session JWTs. Returns an error if the key is missing or invalid.
// Callers must not serve the domain if this returns an error, to avoid
// exposing an unauthenticated service.
func (mw *Middleware) AddDomain(domain string, schemes []Scheme, publicKeyB64 string, expiration time.Duration, accountID, serviceID string) error {
	if len(schemes) == 0 {
		mw.domainsMux.Lock()
		defer mw.domainsMux.Unlock()
		mw.domains[domain] = DomainConfig{
			AccountID: accountID,
			ServiceID: serviceID,
		}
		return nil
	}

	pubKeyBytes, err := base64.StdEncoding.DecodeString(publicKeyB64)
	if err != nil {
		return fmt.Errorf("decode session public key for domain %s: %w", domain, err)
	}
	if len(pubKeyBytes) != ed25519.PublicKeySize {
		return fmt.Errorf("invalid session public key size for domain %s: got %d, want %d", domain, len(pubKeyBytes), ed25519.PublicKeySize)
	}

	mw.domainsMux.Lock()
	defer mw.domainsMux.Unlock()
	mw.domains[domain] = DomainConfig{
		Schemes:           schemes,
		SessionPublicKey:  pubKeyBytes,
		SessionExpiration: expiration,
		AccountID:         accountID,
		ServiceID:         serviceID,
	}
	return nil
}

func (mw *Middleware) RemoveDomain(domain string) {
	mw.domainsMux.Lock()
	defer mw.domainsMux.Unlock()
	delete(mw.domains, domain)
}

// validateSessionToken validates a session token, optionally checking group access via gRPC.
// For OIDC tokens with a configured validator, it calls ValidateSession to check group access.
// For other auth methods (PIN, password), it validates the JWT locally.
// Returns a validationResult with user ID and validity status, or error for invalid tokens.
func (mw *Middleware) validateSessionToken(ctx context.Context, host, token string, publicKey ed25519.PublicKey, method auth.Method) (*validationResult, error) {
	// For OIDC with a session validator, call the gRPC service to check group access
	if method == auth.MethodOIDC && mw.sessionValidator != nil {
		resp, err := mw.sessionValidator.ValidateSession(ctx, &proto.ValidateSessionRequest{
			Domain:       host,
			SessionToken: token,
		})
		if err != nil {
			mw.logger.WithError(err).Error("ValidateSession gRPC call failed")
			return nil, fmt.Errorf("session validation failed")
		}
		if !resp.Valid {
			mw.logger.WithFields(log.Fields{
				"domain":        host,
				"denied_reason": resp.DeniedReason,
				"user_id":       resp.UserId,
			}).Debug("Session validation denied")
			return &validationResult{
				UserID:       resp.UserId,
				Valid:        false,
				DeniedReason: resp.DeniedReason,
			}, nil
		}
		return &validationResult{UserID: resp.UserId, Valid: true}, nil
	}

	// For non-OIDC methods or when no validator is configured, validate JWT locally
	userID, _, err := auth.ValidateSessionJWT(token, host, publicKey)
	if err != nil {
		return nil, err
	}
	return &validationResult{UserID: userID, Valid: true}, nil
}

// stripSessionTokenParam returns the request URI with the session_token query
// parameter removed so it doesn't linger in the browser's address bar or history.
func stripSessionTokenParam(u *url.URL) string {
	q := u.Query()
	if !q.Has("session_token") {
		return u.RequestURI()
	}
	q.Del("session_token")
	clean := *u
	clean.RawQuery = q.Encode()
	return clean.RequestURI()
}
