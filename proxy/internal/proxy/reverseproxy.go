package proxy

import (
	"net/http"
	"net/http/httputil"
	"sync"

	"github.com/netbirdio/netbird/proxy/internal/roundtrip"
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
		// No mapping found so return an error here.
		// TODO: prettier error page.
		http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
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
	proxy.ServeHTTP(w, r.WithContext(ctx))
}
