package proxy

import (
	"net/http"
	"net/http/httputil"
	"sync"
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
	target, serviceId, exists := p.findTargetForRequest(r)
	if !exists {
		// No mapping found so return an error here.
		// TODO: prettier error page.
		http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
		return
	}

	// Set the serviceId in the context for later retrieval.
	ctx := withServiceId(r.Context(), serviceId)

	// Set up a reverse proxy using the transport and then use it to serve the request.
	proxy := httputil.NewSingleHostReverseProxy(target)
	proxy.Transport = p.transport
	proxy.ServeHTTP(w, r.WithContext(ctx))
}
