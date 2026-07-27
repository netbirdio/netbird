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
	"github.com/netbirdio/netbird/proxy/internal/appsec"
	"github.com/netbirdio/netbird/proxy/internal/proxy"
	"github.com/netbirdio/netbird/proxy/internal/restrict"
	"github.com/netbirdio/netbird/proxy/internal/types"
	"github.com/netbirdio/netbird/proxy/web"
	"github.com/netbirdio/netbird/shared/management/proto"
)

// sessionCookieNames is the cookie set AppSec redacts before mirroring: the
// proxy's session cookie is a bearer credential for the service, and the
// reverse proxy already strips it before forwarding upstream.
var sessionCookieNames = []string{auth.SessionCookieName}

// errValidationUnavailable indicates that session validation failed due to
// an infrastructure error (e.g. gRPC unavailable), not an invalid token.
var errValidationUnavailable = errors.New("session validation unavailable")

type authenticator interface {
	Authenticate(ctx context.Context, in *proto.AuthenticateRequest, opts ...grpc.CallOption) (*proto.AuthenticateResponse, error)
}

// SessionValidator validates session tokens and checks user access permissions.
type SessionValidator interface {
	ValidateSession(ctx context.Context, in *proto.ValidateSessionRequest, opts ...grpc.CallOption) (*proto.ValidateSessionResponse, error)
	ValidateTunnelPeer(ctx context.Context, in *proto.ValidateTunnelPeerRequest, opts ...grpc.CallOption) (*proto.ValidateTunnelPeerResponse, error)
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
	// Private routes the domain through ValidateTunnelPeer; failure → 403.
	Private bool
	// AppSecMode enables CrowdSec AppSec request inspection for this domain.
	AppSecMode restrict.AppSecMode
	// redact* name the credentials this domain's schemes accept, resolved once
	// at registration. AppSec replaces their values before mirroring a request,
	// matching what the reverse proxy strips before forwarding upstream.
	redactBodyFields  []string
	redactHeaders     []string
	redactQueryParams []string
}

type validationResult struct {
	UserID       string
	UserEmail    string
	Valid        bool
	DeniedReason string
	Groups       []string
	// GroupNames carries the human-readable display names for Groups,
	// ordered identically (positional pairing). May be shorter than
	// Groups for tokens minted before names were embedded; the consumer
	// falls back to ids for missing positions.
	GroupNames []string
}

// Middleware applies per-domain authentication and IP restriction checks.
type Middleware struct {
	domainsMux       sync.RWMutex
	domains          map[string]DomainConfig
	logger           *log.Logger
	sessionValidator SessionValidator
	geo              restrict.GeoResolver
	tunnelCache      *tunnelValidationCache
	// appsec is the shared CrowdSec AppSec client, nil when the proxy has no
	// AppSec endpoint configured. Set once during startup, before serving.
	appsec *appsec.Client
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
		tunnelCache:      newTunnelValidationCache(),
	}
}

// SetAppSec installs the shared CrowdSec AppSec client. Must be called during
// startup, before the middleware serves any request.
func (mw *Middleware) SetAppSec(client *appsec.Client) {
	mw.appsec = client
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

		// Deferred, not released here: the inspected body stays alive as r.Body
		// until the backend has read it, which happens inside next.ServeHTTP.
		appSecAllowed, releaseAppSec := mw.checkAppSec(w, r, config)
		defer releaseAppSec()
		if !appSecAllowed {
			return
		}

		// Private services bypass operator schemes and gate on tunnel peer.
		if config.Private {
			if mw.forwardWithTunnelPeer(w, r, host, config, next) {
				return
			}
			http.Error(w, "Forbidden", http.StatusForbidden)
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

		if mw.forwardWithTunnelPeer(w, r, host, config, next) {
			return
		}

		if mw.blockOIDCOnPlainHTTP(w, r, config) {
			return
		}

		mw.authenticateWithSchemes(w, r, host, config)
	})
}

// requestIsPlainHTTP reports whether the request arrived without TLS.
// Used to gate cookie-on-plain warnings and the OIDC plain-HTTP block.
func requestIsPlainHTTP(r *http.Request) bool {
	return r.TLS == nil
}

// hasOIDCScheme reports whether any of the configured schemes requires
// TLS to round-trip safely with an external IdP.
func hasOIDCScheme(schemes []Scheme) bool {
	for _, s := range schemes {
		if s.Type() == auth.MethodOIDC {
			return true
		}
	}
	return false
}

// blockOIDCOnPlainHTTP fails fast when an OIDC-configured domain is hit
// over plain HTTP. Most IdPs reject http:// redirect URIs, so surfacing
// the misconfiguration here yields a clearer error than the IdP's
// "invalid redirect_uri" round-trip.
func (mw *Middleware) blockOIDCOnPlainHTTP(w http.ResponseWriter, r *http.Request, config DomainConfig) bool {
	if !requestIsPlainHTTP(r) {
		return false
	}
	if !hasOIDCScheme(config.Schemes) {
		return false
	}
	mw.logger.WithFields(log.Fields{
		"host":   r.Host,
		"remote": r.RemoteAddr,
	}).Warn("OIDC scheme reached on plain HTTP path; rejecting with 400 — use port 443")
	http.Error(w, "OIDC requires TLS — use port 443", http.StatusBadRequest)
	return true
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

	var verdict restrict.Verdict
	if types.IsOverlayOrigin(r.Context()) {
		// Geo/CrowdSec checks don't apply over the WireGuard overlay:
		// the source address is always inside the NetBird CGNAT range,
		// which is never in a GeoIP database or a CrowdSec decision
		// list. Enforcing them here would either no-op (best case) or
		// fail-closed when the geo database is missing.
		verdict = config.IPRestrictions.CheckCIDR(clientIP)
	} else {
		verdict = config.IPRestrictions.Check(clientIP, mw.geo)
	}
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

// checkAppSec mirrors the request to the CrowdSec AppSec engine when the domain
// enables inspection. Returns false when the request was blocked and a response
// has been written.
//
// The returned release frees the body-buffering budget the inspection reserved
// and is never nil. It must run only after the request has been served, since
// the buffered body stays alive as r.Body for the backend to read.
//
// Every non-allow remediation blocks with 403, captcha included: the proxy has
// no challenge flow to serve. The distinct verdict is still recorded so the
// access log shows which remediation the engine actually chose.
//
// Unlike the geo and IP-reputation checks, this runs for overlay traffic too:
// AppSec inspects request content, which is just as meaningful when the caller
// reached the proxy through the WireGuard tunnel.
func (mw *Middleware) checkAppSec(w http.ResponseWriter, r *http.Request, config DomainConfig) (bool, func()) {
	if !config.AppSecMode.Enabled() {
		return true, func() {}
	}

	verdict, release := mw.inspectAppSec(r, config)
	if verdict == restrict.Allow {
		return true, release
	}

	observe := config.AppSecMode == restrict.AppSecObserve
	if cd := proxy.CapturedDataFromContext(r.Context()); cd != nil {
		cd.SetMetadata("appsec_verdict", verdict.String())
		if observe {
			cd.SetMetadata("appsec_mode", "observe")
		}
	}

	if observe {
		mw.logger.Debugf("AppSec observe: would block %s for %s (%s)", r.RemoteAddr, r.Host, verdict)
		return true, release
	}

	mw.markDenied(r, verdict.String())
	mw.logger.Debugf("AppSec: %s for %s %s", verdict, r.Host, r.RemoteAddr)
	http.Error(w, "Forbidden", http.StatusForbidden)
	return false, release
}

// inspectAppSec runs the AppSec call and returns its verdict. Failures come
// back as DenyAppSecUnavailable regardless of mode so observe mode still
// records that inspection did not happen; the caller decides what blocks. The
// returned release is never nil.
func (mw *Middleware) inspectAppSec(r *http.Request, config DomainConfig) (restrict.Verdict, func()) {
	// Mode requested but the proxy has no AppSec endpoint configured. Management
	// gates this on the cluster capability; a stale mapping can still arrive.
	if mw.appsec == nil {
		mw.logger.Debugf("AppSec mode %q requested for %s but no AppSec endpoint is configured", config.AppSecMode, r.Host)
		return restrict.DenyAppSecUnavailable, func() {}
	}

	clientIP := mw.resolveClientIP(r)
	if !clientIP.IsValid() {
		// The engine requires a client address, and a request whose source we
		// cannot establish is exactly the kind we must not wave through.
		mw.logger.Debugf("AppSec: cannot resolve client address for %q", r.RemoteAddr)
		return restrict.DenyAppSecUnavailable, func() {}
	}

	req := appsec.Request{
		HTTP:              r,
		ClientIP:          clientIP,
		RedactBodyFields:  config.redactBodyFields,
		RedactHeaders:     config.redactHeaders,
		RedactCookies:     sessionCookieNames,
		RedactQueryParams: config.redactQueryParams,
	}
	if cd := proxy.CapturedDataFromContext(r.Context()); cd != nil {
		req.TransactionID = cd.GetRequestID()
	}

	result, err := mw.appsec.Inspect(r.Context(), req)
	if err != nil {
		mw.logger.Debugf("AppSec inspection failed for %s: %v", r.Host, err)
	}
	// Record when the body went uninspected: headers and URI were still
	// checked, but an operator reading the log should not read a clean verdict
	// as "the payload was examined". Oversize is reachable by padding, so its
	// absence from the log would hide a deliberate opt-out.
	if result.BodyBypass != "" {
		if cd := proxy.CapturedDataFromContext(r.Context()); cd != nil {
			cd.SetMetadata("appsec_body_bypass", result.BodyBypass)
		}
	}
	return result.Verdict, result.Release
}

// credentialFormFields lists the login form fields whose values are redacted
// from the mirrored body, so a password or PIN submitted to the proxy's own
// login form never reaches the Security Engine.
func credentialFormFields(schemes []Scheme) []string {
	var fields []string
	for _, s := range schemes {
		switch s.Type() {
		case auth.MethodPassword:
			fields = append(fields, passwordFormId)
		case auth.MethodPIN:
			fields = append(fields, pinFormId)
		}
	}
	return fields
}

// credentialHeaders lists the request headers whose values are redacted from
// the mirrored request. A header-auth scheme carries a session token the proxy
// validates and never forwards upstream, so the engine must not see it either.
func credentialHeaders(schemes []Scheme) []string {
	var names []string
	for _, s := range schemes {
		// Structural, not a concrete Header assertion: if the scheme is ever
		// registered as a pointer, a type assertion would quietly stop matching
		// and the header would start reaching the engine again.
		named, ok := s.(interface{ HeaderName() string })
		if !ok {
			continue
		}
		if name := named.HeaderName(); name != "" {
			names = append(names, name)
		}
	}
	return names
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

// markDenied records the deny reason on the captured data so the access log
// attributes the response to the proxy rather than the backend.
func (mw *Middleware) markDenied(r *http.Request, reason string) {
	if cd := proxy.CapturedDataFromContext(r.Context()); cd != nil {
		cd.SetOrigin(proxy.OriginAuth)
		cd.SetAuthMethod(reason)
	}
}

// blockIPRestriction sets captured data fields for an IP-restriction block event.
func (mw *Middleware) blockIPRestriction(r *http.Request, reason string) {
	mw.markDenied(r, reason)
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
	userID, email, method, groups, groupNames, err := auth.ValidateSessionJWT(cookie.Value, host, config.SessionPublicKey)
	if err != nil {
		return false
	}
	if cd := proxy.CapturedDataFromContext(r.Context()); cd != nil {
		cd.SetUserID(userID)
		cd.SetUserEmail(email)
		cd.SetUserGroups(groups)
		cd.SetUserGroupNames(groupNames)
		cd.SetAuthMethod(method)
	}
	next.ServeHTTP(w, r)
	return true
}

// forwardWithTunnelPeer is the OIDC fast-path for requests originating on the
// netbird mesh. When the source IP belongs to a private/CGNAT range the proxy
// asks management to resolve it to a peer/user and to gate by the service's
// distribution_groups. On success the proxy installs the freshly minted JWT
// as a session cookie, sets UserID + Method=oidc on the captured data, and
// forwards directly — operators see the same access-log shape as if the user
// had completed an OIDC redirect. Any failure (private-range mismatch,
// management unreachable, peer unknown, user not in group) returns false so
// the caller falls back to the existing OIDC scheme dispatch.
//
// The fast-path is gated on TunnelLookupFromContext(r.Context()) being
// present — that context value is attached only by the per-account
// inbound (overlay) listener. The host listener never sets it, so a
// public client whose source IP happens to fall inside an RFC1918 / ULA
// / CGNAT range can't impersonate a mesh peer by colliding with a
// tunnel-IP. Once we know the request arrived over WireGuard the
// per-account peerstore lookup is consulted: a miss denies fast (no
// management round-trip), a hit gates the cached ValidateTunnelPeer RPC
// that mints the session JWT.
func (mw *Middleware) forwardWithTunnelPeer(w http.ResponseWriter, r *http.Request, host string, config DomainConfig, next http.Handler) bool {
	if mw.sessionValidator == nil {
		return false
	}
	clientIP := mw.resolveClientIP(r)
	if !clientIP.IsValid() {
		return false
	}

	// Anti-spoof: only honour the tunnel-peer fast-path on requests that
	// were stamped by an overlay listener. Without that marker an
	// attacker could send a request from a colliding RFC1918 / CGNAT
	// source on the public listener and bypass operator auth.
	lookup := TunnelLookupFromContext(r.Context())
	if lookup == nil {
		return false
	}
	if !isTunnelSourceIP(clientIP) {
		return false
	}
	if _, ok := lookup(clientIP); !ok {
		mw.logger.WithFields(log.Fields{
			"host":   host,
			"remote": clientIP,
		}).Debug("local peerstore: tunnel IP not in account roster; denying without RPC")
		return false
	}

	resp, _, err := mw.tunnelCache.fetch(r.Context(), tunnelCacheKey{
		accountID: config.AccountID,
		tunnelIP:  clientIP,
		domain:    host,
	}, mw.validateTunnelPeer)
	if err != nil {
		mw.logger.WithError(err).Debug("ValidateTunnelPeer failed; falling back to OIDC")
		return false
	}
	if !resp.GetValid() || resp.GetSessionToken() == "" {
		return false
	}

	setSessionCookie(w, resp.GetSessionToken(), config.SessionExpiration)
	if cd := proxy.CapturedDataFromContext(r.Context()); cd != nil {
		cd.SetOrigin(proxy.OriginAuth)
		cd.SetUserID(resp.GetUserId())
		cd.SetUserEmail(resp.GetUserEmail())
		cd.SetUserGroups(resp.GetPeerGroupIds())
		cd.SetUserGroupNames(resp.GetPeerGroupNames())
		cd.SetAuthMethod(auth.MethodOIDC.String())
	}
	next.ServeHTTP(w, r)
	return true
}

// validateTunnelPeer adapts the SessionValidator interface to the cache's
// validateTunnelPeerFn signature.
func (mw *Middleware) validateTunnelPeer(ctx context.Context, req *proto.ValidateTunnelPeerRequest) (*proto.ValidateTunnelPeerResponse, error) {
	return mw.sessionValidator.ValidateTunnelPeer(ctx, req)
}

// cgnatPrefix covers RFC 6598 100.64.0.0/10, the CGNAT block NetBird
// allocates tunnel addresses from by default. IsPrivate() doesn't include
// it, so we check it explicitly.
var cgnatPrefix = netip.MustParsePrefix("100.64.0.0/10")

// isTunnelSourceIP reports whether ip falls within an address range typical
// of NetBird tunnels: RFC1918 private space, IPv6 ULA, or CGNAT 100.64/10
// (NetBird's default range). Loopback and link-local are excluded — the
// fast-path is meant for peer-to-peer mesh traffic, not localhost.
func isTunnelSourceIP(ip netip.Addr) bool {
	if !ip.IsValid() || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
		return false
	}
	if ip.IsPrivate() {
		return true
	}
	return cgnatPrefix.Contains(ip)
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
		setHeaderCapturedData(r.Context(), "", "", nil, nil)
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
		setHeaderCapturedData(r.Context(), result.UserID, result.UserEmail, result.Groups, result.GroupNames)
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return true
	}

	setSessionCookie(w, token, config.SessionExpiration)
	if cd := proxy.CapturedDataFromContext(r.Context()); cd != nil {
		cd.SetUserID(result.UserID)
		cd.SetUserEmail(result.UserEmail)
		cd.SetUserGroups(result.Groups)
		cd.SetUserGroupNames(result.GroupNames)
		cd.SetAuthMethod(auth.MethodHeader.String())
	}

	next.ServeHTTP(w, r)
	return true
}

func (mw *Middleware) handleHeaderAuthError(w http.ResponseWriter, r *http.Request, err error) bool {
	if errors.Is(err, ErrHeaderAuthFailed) {
		setHeaderCapturedData(r.Context(), "", "", nil, nil)
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

func setHeaderCapturedData(ctx context.Context, userID, userEmail string, groups, groupNames []string) {
	cd := proxy.CapturedDataFromContext(ctx)
	if cd == nil {
		return
	}
	cd.SetOrigin(proxy.OriginAuth)
	cd.SetAuthMethod(auth.MethodHeader.String())
	cd.SetUserID(userID)
	cd.SetUserEmail(userEmail)
	cd.SetUserGroups(groups)
	cd.SetUserGroupNames(groupNames)
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
			cd.SetUserEmail(result.UserEmail)
			cd.SetUserGroups(result.Groups)
			cd.SetUserGroupNames(result.GroupNames)
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
		cd.SetUserEmail(result.UserEmail)
		cd.SetUserGroups(result.Groups)
		cd.SetUserGroupNames(result.GroupNames)
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
		return r.URL.Query().Get(sessionTokenParam) != ""
	}
	return false
}

// DomainSettings is the per-domain configuration AddDomain applies.
type DomainSettings struct {
	Schemes []Scheme
	// SessionPublicKey is the base64-encoded ed25519 key used to verify session
	// cookies. Required when Schemes is non-empty.
	SessionPublicKey  string
	SessionExpiration time.Duration
	AccountID         types.AccountID
	ServiceID         types.ServiceID
	IPRestrictions    *restrict.Filter
	// Private forces ValidateTunnelPeer enforcement (403 on failure) regardless
	// of the schemes list.
	Private    bool
	AppSecMode restrict.AppSecMode
}

// AddDomain registers authentication schemes for the given domain. With schemes
// a valid session public key is required.
func (mw *Middleware) AddDomain(domain string, settings DomainSettings) error {
	credentialFields := credentialFormFields(settings.Schemes)
	config := DomainConfig{
		AccountID:        settings.AccountID,
		ServiceID:        settings.ServiceID,
		IPRestrictions:   settings.IPRestrictions,
		Private:          settings.Private,
		AppSecMode:       settings.AppSecMode,
		redactBodyFields: credentialFields,
		redactHeaders:    credentialHeaders(settings.Schemes),
		// A credential can arrive in the query too: r.FormValue merges the URL
		// query into the form, so "?password=..." authenticates just as a form
		// post does and must not be mirrored in the clear either.
		redactQueryParams: append([]string{sessionTokenParam}, credentialFields...),
	}

	if len(settings.Schemes) > 0 {
		pubKeyBytes, err := base64.StdEncoding.DecodeString(settings.SessionPublicKey)
		if err != nil {
			return fmt.Errorf("decode session public key for domain %s: %w", domain, err)
		}
		if len(pubKeyBytes) != ed25519.PublicKeySize {
			return fmt.Errorf("invalid session public key size for domain %s: got %d, want %d", domain, len(pubKeyBytes), ed25519.PublicKeySize)
		}
		config.Schemes = settings.Schemes
		config.SessionPublicKey = pubKeyBytes
		config.SessionExpiration = settings.SessionExpiration
	}

	mw.domainsMux.Lock()
	defer mw.domainsMux.Unlock()
	mw.domains[domain] = config
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
				UserEmail:    resp.GetUserEmail(),
				Valid:        false,
				DeniedReason: resp.DeniedReason,
			}, nil
		}
		return &validationResult{
			UserID:     resp.UserId,
			UserEmail:  resp.GetUserEmail(),
			Valid:      true,
			Groups:     resp.GetPeerGroupIds(),
			GroupNames: resp.GetPeerGroupNames(),
		}, nil
	}

	userID, email, _, groups, groupNames, err := auth.ValidateSessionJWT(token, host, publicKey)
	if err != nil {
		return nil, err
	}
	return &validationResult{UserID: userID, UserEmail: email, Valid: true, Groups: groups, GroupNames: groupNames}, nil
}

// stripSessionTokenParam returns the request URI with the session_token query
// parameter removed so it doesn't linger in the browser's address bar or history.
func stripSessionTokenParam(u *url.URL) string {
	q := u.Query()
	if !q.Has(sessionTokenParam) {
		return u.RequestURI()
	}
	q.Del(sessionTokenParam)
	clean := *u
	clean.RawQuery = q.Encode()
	return clean.RequestURI()
}
