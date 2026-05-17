package client

// ServerEndpoint announces a relay server along with the transports it speaks.
// Carried via the management RelayConfig.endpoints field; falls back to a
// URL-only entry (Transports == nil, meaning "try all dialers") for back-compat
// with older management servers that only sent flat URLs.
type ServerEndpoint struct {
	URL        string
	Transports []string
}

// EndpointsFromURLs builds a list of hint-less endpoints from a flat URL list.
// Used when the management server sends only RelayConfig.urls (no per-relay
// capability metadata).
func EndpointsFromURLs(urls []string) []ServerEndpoint {
	if len(urls) == 0 {
		return nil
	}
	out := make([]ServerEndpoint, len(urls))
	for i, u := range urls {
		out[i] = ServerEndpoint{URL: u}
	}
	return out
}

// URLsFromEndpoints projects a list of endpoints back to a flat URL slice,
// preserving order. Used by call sites that don't yet consume transport hints.
func URLsFromEndpoints(endpoints []ServerEndpoint) []string {
	if len(endpoints) == 0 {
		return nil
	}
	out := make([]string, len(endpoints))
	for i, e := range endpoints {
		out[i] = e.URL
	}
	return out
}
