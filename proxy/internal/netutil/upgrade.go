package netutil

import (
	"net/http"

	"golang.org/x/net/http/httpguts"
)

// IsUpgradeRequest reports whether r is a protocol-upgrade request, using the
// same predicate httputil.ReverseProxy applies when it decides to hand the
// connection over instead of proxying normally.
//
// Matching the forwarder exactly matters for anything that inspects a request
// before it is proxied: a looser test (an Upgrade header on its own, say) marks
// a request as an upgrade and skips inspection, while the forwarder still
// delivers it to the backend as an ordinary request with its body intact. That
// gap is a body-inspection bypass reachable by adding one header.
func IsUpgradeRequest(h http.Header) bool {
	if !httpguts.HeaderValuesContainsToken(h["Connection"], "Upgrade") {
		return false
	}
	return h.Get("Upgrade") != ""
}
