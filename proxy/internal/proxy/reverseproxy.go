package proxy

import (
	"context"
	"errors"
	"net/http"
	"net/http/httputil"
	"strings"
	"sync"

	"github.com/netbirdio/netbird/proxy/internal/roundtrip"
	"github.com/netbirdio/netbird/proxy/web"
)

type ReverseProxy struct {
	transport   http.RoundTripper
	mappingsMux sync.RWMutex
	mappings    map[string]Mapping
}

// NewReverseProxy configures a new NetBird ReverseProxy.
// This is a wrapper around an httputil.ReverseProxy set
// to dynamically route requests based on internal mapping
// between requested URLs and targets.
// The internal mappings can be modified using the AddMapping
// and RemoveMapping functions.
func NewReverseProxy(transport http.RoundTripper) *ReverseProxy {
	return &ReverseProxy{
		transport: transport,
		mappings:  make(map[string]Mapping),
	}
}

func (p *ReverseProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	target, serviceId, accountID, exists := p.findTargetForRequest(r)
	if !exists {
		web.ServeErrorPage(w, r, http.StatusNotFound, "Service Not Found",
			"The requested service could not be found. Please check the URL, try refreshing, or check if the peer is running. If that doesn't work, see our documentation for help.")
		return
	}

	// Set the serviceId in the context for later retrieval.
	ctx := withServiceId(r.Context(), serviceId)
	// Set the accountId in the context for later retrieval (for middleware).
	ctx = withAccountId(ctx, accountID)
	// Set the accountId in the context for the roundtripper to use.
	ctx = roundtrip.WithAccountID(ctx, accountID)

	// Also populate captured data if it exists (allows middleware to read after handler completes).
	// This solves the problem of passing data UP the middleware chain: we put a mutable struct
	// pointer in the context, and mutate the struct here so outer middleware can read it.
	if capturedData := CapturedDataFromContext(ctx); capturedData != nil {
		capturedData.SetServiceId(serviceId)
		capturedData.SetAccountId(accountID)
	}

	// Set up a reverse proxy using the transport and then use it to serve the request.
	proxy := httputil.NewSingleHostReverseProxy(target)
	proxy.Transport = p.transport
	proxy.ErrorHandler = proxyErrorHandler
	proxy.ServeHTTP(w, r.WithContext(ctx))
}

// proxyErrorHandler handles errors from the reverse proxy and serves
// user-friendly error pages instead of raw error responses.
func proxyErrorHandler(w http.ResponseWriter, r *http.Request, err error) {
	title, message, code := classifyProxyError(err)
	web.ServeErrorPage(w, r, code, title, message)
}

// classifyProxyError determines the appropriate error title, message, and HTTP
// status code based on the error type.
func classifyProxyError(err error) (title, message string, code int) {
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return "Request Timeout",
			"The request timed out while trying to reach the service. Please refresh the page and try again.",
			http.StatusGatewayTimeout

	case errors.Is(err, context.Canceled):
		return "Request Canceled",
			"The request was canceled before it could be completed. Please refresh the page and try again.",
			http.StatusBadGateway

	case errors.Is(err, roundtrip.ErrNoAccountID):
		return "Configuration Error",
			"The request could not be processed due to a configuration issue. Please refresh the page and try again.",
			http.StatusInternalServerError

	case strings.Contains(err.Error(), "connection refused"):
		return "Service Unavailable",
			"The connection to the service was refused. Please verify that the service is running and try again.",
			http.StatusBadGateway

	default:
		return "Peer Not Connected",
			"The connection to the peer could not be established. Please ensure the peer is running and connected to the NetBird network.",
			http.StatusBadGateway
	}
}
