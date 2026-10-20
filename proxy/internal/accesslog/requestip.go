package accesslog

import (
	"net/http"
	"net/netip"

	"github.com/netbirdio/netbird/trustedproxy"
)

// extractSourceIP resolves the real client IP from the request using trusted
// proxy configuration. When trustedProxies is non-empty and the direct
// connection is from a trusted source, it walks X-Forwarded-For right-to-left
// skipping trusted IPs. Otherwise it returns RemoteAddr directly.
func extractSourceIP(r *http.Request, trustedProxies *trustedproxy.List) netip.Addr {
	return trustedProxies.ResolveClientIP(r.RemoteAddr, r.Header.Get("X-Forwarded-For"))
}
