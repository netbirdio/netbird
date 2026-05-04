package auth

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"html"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"

	"github.com/netbirdio/netbird/proxy/auth"
	"github.com/netbirdio/netbird/proxy/internal/proxy"
	"github.com/netbirdio/netbird/proxy/internal/restrict"
	"github.com/netbirdio/netbird/proxy/internal/types"
	"github.com/netbirdio/netbird/proxy/web"
	"github.com/netbirdio/netbird/shared/management/proto"
)

// errValidationUnavailable indicates that session validation failed due to
// an infrastructure error (e.g. gRPC unavailable), not an invalid token.
var errValidationUnavailable = errors.New("session validation unavailable")

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

// DomainConfig holds the authentication and restriction settings for a protected domain.
type DomainConfig struct {
	Schemes           []Scheme
	SessionPublicKey  ed25519.PublicKey
	SessionExpiration time.Duration
	AccountID         types.AccountID
	ServiceID         types.ServiceID
	IPRestrictions    *restrict.Filter
}

type validationResult struct {
	UserID       string
	Valid        bool
	DeniedReason string
}

// Middleware applies per-domain authentication and IP restriction checks.
type Middleware struct {
	domainsMux       sync.RWMutex
	domains          map[string]DomainConfig
	logger           *log.Logger
	sessionValidator SessionValidator
	geo              restrict.GeoResolver
}

// NewMiddleware creates a new authentication middleware. The sessionValidator is
// optional; if nil, OIDC session tokens are validated locally without group access checks.
func NewMiddleware(logger *log.Logger, sessionValidator SessionValidator, geo restrict.GeoResolver) *Middleware {
	if logger == nil {
		logger = log.StandardLogger()
	}
	return &Middleware{
		domains:          make(map[string]DomainConfig),
		logger:           logger,
		sessionValidator: sessionValidator,
		geo:              geo,
	}
}

// Protect wraps next with per-domain authentication and IP restriction checks.
// Requests whose Host is not registered pass through unchanged.
func (mw *Middleware) Protect(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host, _, err := net.SplitHostPort(r.Host)
		if err != nil {
			host = r.Host
		}

		config, exists := mw.getDomainConfig(host)
		mw.logger.Debugf("checking authentication for host: %s, exists: %t", host, exists)

		if !exists {
			next.ServeHTTP(w, r)
			return
		}

		// Set account and service IDs in captured data for access logging.
		setCapturedIDs(r, config)

		if !mw.checkIPRestrictions(w, r, config) {
			return
		}

		// Domains with no authentication schemes pass through after IP checks.
		if len(config.Schemes) == 0 {
			next.ServeHTTP(w, r)
			return
		}

		if mw.handleOAuthCallbackError(w, r) {
			return
		}

		if mw.forwardWithSessionCookie(w, r, host, config, next) {
			return
		}

		if mw.forwardWithHeaderAuth(w, r, host, config, next) {
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
		cd.SetAccountID(config.AccountID)
		cd.SetServiceID(config.ServiceID)
	}
}

// checkIPRestrictions validates the client IP against the domain's IP restrictions.
// Uses the resolved client IP from CapturedData (which accounts for trusted proxies)
// rather than r.RemoteAddr directly.
func (mw *Middleware) checkIPRestrictions(w http.ResponseWriter, r *http.Request, config DomainConfig) bool {
	if config.IPRestrictions == nil {
		return true
	}

	clientIP := mw.resolveClientIP(r)
	if !clientIP.IsValid() {
		mw.logger.Debugf("IP restriction: cannot resolve client address for %q, denying", r.RemoteAddr)
		http.Error(w, "Forbidden", http.StatusForbidden)
		return false
	}

	verdict := config.IPRestrictions.Check(clientIP, mw.geo)
	if verdict == restrict.Allow {
		return true
	}

	if verdict.IsCrowdSec() {
		if cd := proxy.CapturedDataFromContext(r.Context()); cd != nil {
			cd.SetMetadata("crowdsec_verdict", verdict.String())
			if config.IPRestrictions.IsObserveOnly(verdict) {
				cd.SetMetadata("crowdsec_mode", "observe")
			}
		}
	}

	if config.IPRestrictions.IsObserveOnly(verdict) {
		mw.logger.Debugf("CrowdSec observe: would block %s for %s (%s)", clientIP, r.Host, verdict)
		return true
	}

	reason := verdict.String()
	mw.blockIPRestriction(r, reason)
	http.Error(w, "Forbidden", http.StatusForbidden)
	return false
}

// resolveClientIP extracts the real client IP from CapturedData, falling back to r.RemoteAddr.
func (mw *Middleware) resolveClientIP(r *http.Request) netip.Addr {
	if cd := proxy.CapturedDataFromContext(r.Context()); cd != nil {
		if ip := cd.GetClientIP(); ip.IsValid() {
			return ip
		}
	}

	clientIPStr, _, _ := net.SplitHostPort(r.RemoteAddr)
	if clientIPStr == "" {
		clientIPStr = r.RemoteAddr
	}
	addr, err := netip.ParseAddr(clientIPStr)
	if err != nil {
		return netip.Addr{}
	}
	return addr.Unmap()
}

// blockIPRestriction sets captured data fields for an IP-restriction block event.
func (mw *Middleware) blockIPRestriction(r *http.Request, reason string) {
	if cd := proxy.CapturedDataFromContext(r.Context()); cd != nil {
		cd.SetOrigin(proxy.OriginAuth)
		cd.SetAuthMethod(reason)
	}
	mw.logger.Debugf("IP restriction: %s for %s", reason, r.RemoteAddr)
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
	} else {
		errDesc = html.EscapeString(errDesc)
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

// forwardWithHeaderAuth checks for a Header auth scheme. If the header validates,
// the request is forwarded directly (no redirect), which is important for API clients.
func (mw *Middleware) forwardWithHeaderAuth(w http.ResponseWriter, r *http.Request, host string, config DomainConfig, next http.Handler) bool {
	for _, scheme := range config.Schemes {
		hdr, ok := scheme.(Header)
		if !ok {
			continue
		}

		handled := mw.tryHeaderScheme(w, r, host, config, hdr, next)
		if handled {
			return true
		}
	}
	return false
}

func (mw *Middleware) tryHeaderScheme(w http.ResponseWriter, r *http.Request, host string, config DomainConfig, hdr Header, next http.Handler) bool {
	token, _, err := hdr.Authenticate(r)
	if err != nil {
		return mw.handleHeaderAuthError(w, r, err)
	}
	if token == "" {
		return false
	}

	result, err := mw.validateSessionToken(r.Context(), host, token, config.SessionPublicKey, auth.MethodHeader)
	if err != nil {
		setHeaderCapturedData(r.Context(), "")
		status := http.StatusBadRequest
		msg := "invalid session token"
		if errors.Is(err, errValidationUnavailable) {
			status = http.StatusBadGateway
			msg = "authentication service unavailable"
		}
		http.Error(w, msg, status)
		return true
	}

	if !result.Valid {
		setHeaderCapturedData(r.Context(), result.UserID)
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return true
	}

	setSessionCookie(w, token, config.SessionExpiration)
	if cd := proxy.CapturedDataFromContext(r.Context()); cd != nil {
		cd.SetUserID(result.UserID)
		cd.SetAuthMethod(auth.MethodHeader.String())
	}

	next.ServeHTTP(w, r)
	return true
}

func (mw *Middleware) handleHeaderAuthError(w http.ResponseWriter, r *http.Request, err error) bool {
	if errors.Is(err, ErrHeaderAuthFailed) {
		setHeaderCapturedData(r.Context(), "")
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return true
	}
	mw.logger.WithField("scheme", "header").Warnf("header auth infrastructure error: %v", err)
	if cd := proxy.CapturedDataFromContext(r.Context()); cd != nil {
		cd.SetOrigin(proxy.OriginAuth)
	}
	http.Error(w, "authentication service unavailable", http.StatusBadGateway)
	return true
}

func setHeaderCapturedData(ctx context.Context, userID string) {
	cd := proxy.CapturedDataFromContext(ctx)
	if cd == nil {
		return
	}
	cd.SetOrigin(proxy.OriginAuth)
	cd.SetAuthMethod(auth.MethodHeader.String())
	cd.SetUserID(userID)
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

	if oidcURL, ok := methods[auth.MethodOIDC.String()]; ok && len(methods) == 1 && oidcURL != "" {
		http.Redirect(w, r, oidcURL, http.StatusFound)
		return
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
		status := http.StatusBadRequest
		msg := "invalid session token"
		if errors.Is(err, errValidationUnavailable) {
			status = http.StatusBadGateway
			msg = "authentication service unavailable"
		}
		http.Error(w, msg, status)
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

	setSessionCookie(w, token, config.SessionExpiration)

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

// setSessionCookie writes a session cookie with secure defaults.
func setSessionCookie(w http.ResponseWriter, token string, expiration time.Duration) {
	if expiration == 0 {
		expiration = auth.DefaultSessionExpiry
	}
	http.SetCookie(w, &http.Cookie{
		Name:     auth.SessionCookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(expiration.Seconds()),
	})
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
func (mw *Middleware) AddDomain(domain string, schemes []Scheme, publicKeyB64 string, expiration time.Duration, accountID types.AccountID, serviceID types.ServiceID, ipRestrictions *restrict.Filter) error {
	if len(schemes) == 0 {
		mw.domainsMux.Lock()
		defer mw.domainsMux.Unlock()
		mw.domains[domain] = DomainConfig{
			AccountID:      accountID,
			ServiceID:      serviceID,
			IPRestrictions: ipRestrictions,
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
		IPRestrictions:    ipRestrictions,
	}
	return nil
}

// RemoveDomain unregisters authentication for the given domain.
func (mw *Middleware) RemoveDomain(domain string) {
	mw.domainsMux.Lock()
	defer mw.domainsMux.Unlock()
	delete(mw.domains, domain)
}

// validateSessionToken validates a session token. OIDC tokens with a configured
// validator go through gRPC for group access checks; other methods validate locally.
func (mw *Middleware) validateSessionToken(ctx context.Context, host, token string, publicKey ed25519.PublicKey, method auth.Method) (*validationResult, error) {
	if method == auth.MethodOIDC && mw.sessionValidator != nil {
		resp, err := mw.sessionValidator.ValidateSession(ctx, &proto.ValidateSessionRequest{
			Domain:       host,
			SessionToken: token,
		})
		if err != nil {
			return nil, fmt.Errorf("%w: %w", errValidationUnavailable, err)
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
