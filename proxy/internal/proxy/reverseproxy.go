package proxy

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"net/netip"
	"net/url"
	"strings"
	"sync"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/proxy/auth"
	"github.com/netbirdio/netbird/proxy/internal/roundtrip"
	"github.com/netbirdio/netbird/proxy/web"
)

type ReverseProxy struct {
	transport http.RoundTripper
	// forwardedProto overrides the X-Forwarded-Proto header value.
	// Valid values: "auto" (detect from TLS), "http", "https".
	forwardedProto string
	// trustedProxies is a list of IP prefixes for trusted upstream proxies.
	// When the direct connection comes from a trusted proxy, forwarding
	// headers are preserved and appended to instead of being stripped.
	trustedProxies []netip.Prefix
	mappingsMux    sync.RWMutex
	mappings       map[string]Mapping
	logger         *log.Logger
}

// NewReverseProxy configures a new NetBird ReverseProxy.
// This is a wrapper around an httputil.ReverseProxy set
// to dynamically route requests based on internal mapping
// between requested URLs and targets.
// The internal mappings can be modified using the AddMapping
// and RemoveMapping functions.
func NewReverseProxy(transport http.RoundTripper, forwardedProto string, trustedProxies []netip.Prefix, logger *log.Logger) *ReverseProxy {
	if logger == nil {
		logger = log.StandardLogger()
	}
	return &ReverseProxy{
		transport:      transport,
		forwardedProto: forwardedProto,
		trustedProxies: trustedProxies,
		mappings:       make(map[string]Mapping),
		logger:         logger,
	}
}

func (p *ReverseProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	result, exists := p.findTargetForRequest(r)
	if !exists {
		if cd := CapturedDataFromContext(r.Context()); cd != nil {
			cd.SetOrigin(OriginNoRoute)
		}
		requestID := getRequestID(r)
		web.ServeErrorPage(w, r, http.StatusNotFound, "Service Not Found",
			"The requested service could not be found. Please check the URL, try refreshing, or check if the peer is running. If that doesn't work, see our documentation for help.",
			requestID, web.ErrorStatus{Proxy: true, Destination: false})
		return
	}

	// Set the serviceId in the context for later retrieval.
	ctx := withServiceId(r.Context(), result.serviceID)
	// Set the accountId in the context for later retrieval (for middleware).
	ctx = withAccountId(ctx, result.accountID)
	// Set the accountId in the context for the roundtripper to use.
	ctx = roundtrip.WithAccountID(ctx, result.accountID)

	// Also populate captured data if it exists (allows middleware to read after handler completes).
	// This solves the problem of passing data UP the middleware chain: we put a mutable struct
	// pointer in the context, and mutate the struct here so outer middleware can read it.
	if capturedData := CapturedDataFromContext(ctx); capturedData != nil {
		capturedData.SetServiceId(result.serviceID)
		capturedData.SetAccountId(result.accountID)
	}

	rp := &httputil.ReverseProxy{
		Rewrite:      p.rewriteFunc(result.url, result.matchedPath, result.passHostHeader),
		Transport:    p.transport,
		ErrorHandler: proxyErrorHandler,
	}
	if result.rewriteRedirects {
		rp.ModifyResponse = p.rewriteLocationFunc(result.url, result.matchedPath, r) //nolint:bodyclose
	}
	rp.ServeHTTP(w, r.WithContext(ctx))
}

// rewriteFunc returns a Rewrite function for httputil.ReverseProxy that rewrites
// inbound requests to target the backend service while setting security-relevant
// forwarding headers and stripping proxy authentication credentials.
// When passHostHeader is true, the original client Host header is preserved
// instead of being rewritten to the backend's address.
func (p *ReverseProxy) rewriteFunc(target *url.URL, matchedPath string, passHostHeader bool) func(r *httputil.ProxyRequest) {
	return func(r *httputil.ProxyRequest) {
		// Strip the matched path prefix from the incoming request path before
		// SetURL joins it with the target's base path, avoiding path duplication.
		if matchedPath != "" && matchedPath != "/" {
			r.Out.URL.Path = strings.TrimPrefix(r.Out.URL.Path, matchedPath)
			if r.Out.URL.Path == "" {
				r.Out.URL.Path = "/"
			}
			r.Out.URL.RawPath = ""
		}

		r.SetURL(target)
		if passHostHeader {
			r.Out.Host = r.In.Host
		} else {
			r.Out.Host = target.Host
		}

		clientIP := extractClientIP(r.In.RemoteAddr)

		if IsTrustedProxy(clientIP, p.trustedProxies) {
			p.setTrustedForwardingHeaders(r, clientIP)
		} else {
			p.setUntrustedForwardingHeaders(r, clientIP)
		}

		stripSessionCookie(r)
		stripSessionTokenQuery(r)
	}
}

// rewriteLocationFunc returns a ModifyResponse function that rewrites Location
// headers in backend responses when they point to the backend's address,
// replacing them with the public-facing host and scheme.
func (p *ReverseProxy) rewriteLocationFunc(target *url.URL, matchedPath string, inReq *http.Request) func(*http.Response) error {
	publicHost := inReq.Host
	publicScheme := auth.ResolveProto(p.forwardedProto, inReq.TLS)

	return func(resp *http.Response) error {
		location := resp.Header.Get("Location")
		if location == "" {
			return nil
		}

		locURL, err := url.Parse(location)
		if err != nil {
			return fmt.Errorf("parse Location header %q: %w", location, err)
		}

		// Only rewrite absolute URLs that point to the backend.
		if locURL.Host == "" || !hostsEqual(locURL, target) {
			return nil
		}

		locURL.Host = publicHost
		locURL.Scheme = publicScheme

		// Re-add the stripped path prefix so the client reaches the correct route.
		// TrimRight prevents double slashes when matchedPath has a trailing slash.
		if matchedPath != "" && matchedPath != "/" {
			locURL.Path = strings.TrimRight(matchedPath, "/") + "/" + strings.TrimLeft(locURL.Path, "/")
		}

		resp.Header.Set("Location", locURL.String())
		return nil
	}
}

// hostsEqual compares two URL authorities, normalizing default ports per
// RFC 3986 Section 6.2.3 (https://443 == https, http://80 == http).
func hostsEqual(a, b *url.URL) bool {
	return normalizeHost(a) == normalizeHost(b)
}

// normalizeHost strips the port from a URL's Host field if it matches the
// scheme's default port (443 for https, 80 for http).
func normalizeHost(u *url.URL) string {
	host, port, err := net.SplitHostPort(u.Host)
	if err != nil {
		return u.Host
	}
	if (u.Scheme == "https" && port == "443") || (u.Scheme == "http" && port == "80") {
		return host
	}
	return u.Host
}

// setTrustedForwardingHeaders appends to the existing forwarding header chain
// and preserves upstream-provided headers when the direct connection is from
// a trusted proxy.
func (p *ReverseProxy) setTrustedForwardingHeaders(r *httputil.ProxyRequest, clientIP string) {
	// Append the direct connection IP to the existing X-Forwarded-For chain.
	if existing := r.In.Header.Get("X-Forwarded-For"); existing != "" {
		r.Out.Header.Set("X-Forwarded-For", existing+", "+clientIP)
	} else {
		r.Out.Header.Set("X-Forwarded-For", clientIP)
	}

	// Preserve upstream X-Real-IP if present; otherwise resolve through the chain.
	if realIP := r.In.Header.Get("X-Real-IP"); realIP != "" {
		r.Out.Header.Set("X-Real-IP", realIP)
	} else {
		resolved := ResolveClientIP(r.In.RemoteAddr, r.In.Header.Get("X-Forwarded-For"), p.trustedProxies)
		r.Out.Header.Set("X-Real-IP", resolved)
	}

	// Preserve upstream X-Forwarded-Host if present.
	if fwdHost := r.In.Header.Get("X-Forwarded-Host"); fwdHost != "" {
		r.Out.Header.Set("X-Forwarded-Host", fwdHost)
	} else {
		r.Out.Header.Set("X-Forwarded-Host", r.In.Host)
	}

	// Trust upstream X-Forwarded-Proto; fall back to local resolution.
	if fwdProto := r.In.Header.Get("X-Forwarded-Proto"); fwdProto != "" {
		r.Out.Header.Set("X-Forwarded-Proto", fwdProto)
	} else {
		r.Out.Header.Set("X-Forwarded-Proto", auth.ResolveProto(p.forwardedProto, r.In.TLS))
	}

	// Trust upstream X-Forwarded-Port; fall back to local computation.
	if fwdPort := r.In.Header.Get("X-Forwarded-Port"); fwdPort != "" {
		r.Out.Header.Set("X-Forwarded-Port", fwdPort)
	} else {
		resolvedProto := r.Out.Header.Get("X-Forwarded-Proto")
		r.Out.Header.Set("X-Forwarded-Port", extractForwardedPort(r.In.Host, resolvedProto))
	}
}

// setUntrustedForwardingHeaders strips all incoming forwarding headers and
// sets them fresh based on the direct connection. This is the default
// behavior when no trusted proxies are configured or the direct connection
// is from an untrusted source.
func (p *ReverseProxy) setUntrustedForwardingHeaders(r *httputil.ProxyRequest, clientIP string) {
	proto := auth.ResolveProto(p.forwardedProto, r.In.TLS)
	r.Out.Header.Set("X-Forwarded-For", clientIP)
	r.Out.Header.Set("X-Real-IP", clientIP)
	r.Out.Header.Set("X-Forwarded-Host", r.In.Host)
	r.Out.Header.Set("X-Forwarded-Proto", proto)
	r.Out.Header.Set("X-Forwarded-Port", extractForwardedPort(r.In.Host, proto))
}

// stripSessionCookie removes the proxy's session cookie from the outgoing
// request while preserving all other cookies.
func stripSessionCookie(r *httputil.ProxyRequest) {
	cookies := r.In.Cookies()
	r.Out.Header.Del("Cookie")
	for _, c := range cookies {
		if c.Name != auth.SessionCookieName {
			r.Out.AddCookie(c)
		}
	}
}

// stripSessionTokenQuery removes the OIDC session_token query parameter from
// the outgoing URL to prevent credential leakage to backends.
func stripSessionTokenQuery(r *httputil.ProxyRequest) {
	q := r.Out.URL.Query()
	if q.Has("session_token") {
		q.Del("session_token")
		r.Out.URL.RawQuery = q.Encode()
	}
}

// extractClientIP extracts the IP address from an http.Request.RemoteAddr
// which is always in host:port format.
func extractClientIP(remoteAddr string) string {
	ip, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return remoteAddr
	}
	return ip
}

// extractForwardedPort returns the port from the Host header if present,
// otherwise defaults to the standard port for the resolved protocol.
func extractForwardedPort(host, resolvedProto string) string {
	_, port, err := net.SplitHostPort(host)
	if err == nil && port != "" {
		return port
	}
	if resolvedProto == "https" {
		return "443"
	}
	return "80"
}

// proxyErrorHandler handles errors from the reverse proxy and serves
// user-friendly error pages instead of raw error responses.
func proxyErrorHandler(w http.ResponseWriter, r *http.Request, err error) {
	if cd := CapturedDataFromContext(r.Context()); cd != nil {
		cd.SetOrigin(OriginProxyError)
	}
	requestID := getRequestID(r)
	clientIP := getClientIP(r)
	title, message, code, status := classifyProxyError(err)

	log.Warnf("proxy error: request_id=%s client_ip=%s method=%s host=%s path=%s status=%d title=%q err=%v",
		requestID, clientIP, r.Method, r.Host, r.URL.Path, code, title, err)

	web.ServeErrorPage(w, r, code, title, message, requestID, status)
}

// getClientIP retrieves the resolved client IP from context.
func getClientIP(r *http.Request) string {
	if capturedData := CapturedDataFromContext(r.Context()); capturedData != nil {
		return capturedData.GetClientIP()
	}
	return ""
}

// getRequestID retrieves the request ID from context or returns empty string.
func getRequestID(r *http.Request) string {
	if capturedData := CapturedDataFromContext(r.Context()); capturedData != nil {
		return capturedData.GetRequestID()
	}
	return ""
}

// classifyProxyError determines the appropriate error title, message, HTTP
// status code, and component status based on the error type.
func classifyProxyError(err error) (title, message string, code int, status web.ErrorStatus) {
	switch {
	case errors.Is(err, context.DeadlineExceeded),
		isNetTimeout(err):
		return "Request Timeout",
			"The request timed out while trying to reach the service. Please refresh the page and try again.",
			http.StatusGatewayTimeout,
			web.ErrorStatus{Proxy: true, Destination: false}

	case errors.Is(err, context.Canceled):
		return "Request Canceled",
			"The request was canceled before it could be completed. Please refresh the page and try again.",
			http.StatusBadGateway,
			web.ErrorStatus{Proxy: true, Destination: false}

	case errors.Is(err, roundtrip.ErrNoAccountID):
		return "Configuration Error",
			"The request could not be processed due to a configuration issue. Please refresh the page and try again.",
			http.StatusInternalServerError,
			web.ErrorStatus{Proxy: false, Destination: false}

	case errors.Is(err, roundtrip.ErrNoPeerConnection),
		errors.Is(err, roundtrip.ErrClientStartFailed):
		return "Proxy Not Connected",
			"The proxy is not connected to the NetBird network. Please try again later or contact your administrator.",
			http.StatusBadGateway,
			web.ErrorStatus{Proxy: false, Destination: false}

	case errors.Is(err, roundtrip.ErrTooManyInflight):
		return "Service Overloaded",
			"The service is currently handling too many requests. Please try again shortly.",
			http.StatusServiceUnavailable,
			web.ErrorStatus{Proxy: true, Destination: false}

	case isConnectionRefused(err):
		return "Service Unavailable",
			"The connection to the service was refused. Please verify that the service is running and try again.",
			http.StatusBadGateway,
			web.ErrorStatus{Proxy: true, Destination: false}

	case isHostUnreachable(err):
		return "Peer Not Connected",
			"The connection to the peer could not be established. Please ensure the peer is running and connected to the NetBird network.",
			http.StatusBadGateway,
			web.ErrorStatus{Proxy: true, Destination: false}
	}

	return "Connection Error",
		"An unexpected error occurred while connecting to the service. Please try again later.",
		http.StatusBadGateway,
		web.ErrorStatus{Proxy: true, Destination: false}
}

// isConnectionRefused checks for connection refused errors by inspecting
// the inner error of a *net.OpError. This handles both standard net errors
// (where the inner error is a *os.SyscallError with "connection refused")
// and gVisor netstack errors ("connection was refused").
func isConnectionRefused(err error) bool {
	return opErrorContains(err, "refused")
}

// isHostUnreachable checks for host/network unreachable errors by inspecting
// the inner error of a *net.OpError. Covers standard net ("no route to host",
// "network is unreachable") and gVisor ("host is unreachable", etc.).
func isHostUnreachable(err error) bool {
	return opErrorContains(err, "unreachable") || opErrorContains(err, "no route to host")
}

// isNetTimeout checks whether the error is a network timeout using the
// net.Error interface.
func isNetTimeout(err error) bool {
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}

// opErrorContains extracts the inner error from a *net.OpError and checks
// whether its message contains the given substring. This handles gVisor
// netstack errors which wrap tcpip errors as plain strings rather than
// syscall.Errno values.
func opErrorContains(err error, substr string) bool {
	var opErr *net.OpError
	if errors.As(err, &opErr) && opErr.Err != nil {
		return strings.Contains(opErr.Err.Error(), substr)
	}
	return false
}
