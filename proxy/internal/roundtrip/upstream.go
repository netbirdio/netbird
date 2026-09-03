package roundtrip

import (
	"net/http"
	"strings"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
)

// upstreamDowngradeTTL is how long an upstream stays pinned to HTTP/1.1
// after an h2 failure that only implied it cannot serve h2. Bounded so a
// fixed or replaced backend returns to h2 without restarting the proxy.
// A pin the upstream asked for itself does not expire — see downgrade.
const upstreamDowngradeTTL = 10 * time.Minute

// downgrade is an upstream's HTTP/1.1 pin.
type downgrade struct {
	// expiry is when the pin lapses and the upstream is offered h2
	// again. The zero time means it never does: the upstream answered
	// HTTP_1_1_REQUIRED, which is a statement about how it is
	// configured, not a fault that may clear on its own. Re-probing
	// that every upstreamDowngradeTTL would buy nothing but a failed
	// request per interval, so the pin holds until the transport goes
	// away with the proxy or the account's client.
	expiry time.Time
}

// permanent reports whether the upstream asked for this pin itself.
func (d downgrade) permanent() bool {
	return d.expiry.IsZero()
}

// active reports whether the pin still stands at now.
func (d downgrade) active(now time.Time) bool {
	return d.permanent() || now.Before(d.expiry)
}

// upstreamTransport carries requests to a single upstream family (one
// TLS configuration) and implements what upstreamHTTPAuto means.
//
// ALPN already lets the upstream pick the protocol: primary offers both
// h2 and http/1.1 and the server chooses. What ALPN cannot express is
// an upstream that selects h2 and then fails to speak it — the case
// this type handles. The first h2-level failure for a host pins that
// host to fallback, an HTTP/1.1-only clone of primary, and the request
// is retried there when it can be replayed.
//
// The downgrade is per upstream host, not per transport: one broken
// backend must not drop every other backend to HTTP/1.1.
type upstreamTransport struct {
	// primary is the configured transport: h2 offered in ALPN for
	// upstreamHTTPAuto and upstreamHTTP2, HTTP/1.1-only for
	// upstreamHTTP11.
	primary *http.Transport
	// version decides whether a downgrade may happen at all. Only
	// upstreamHTTPAuto downgrades; the explicit values are absolute.
	version upstreamHTTPVersion
	logger  *log.Logger

	// fallbackMu guards the lazy fallback clone: most deployments never
	// hit a broken h2 upstream and should not pay for a second
	// connection pool.
	fallbackMu sync.Mutex
	fallback   *http.Transport

	mu sync.RWMutex
	// downgraded maps an upstream host to its HTTP/1.1 pin.
	downgraded map[string]downgrade
}

// newUpstreamTransport wraps base for the requested HTTP version. base
// must not be used directly afterwards: the wrapper owns it, including
// its connection pool.
func newUpstreamTransport(base *http.Transport, version upstreamHTTPVersion, logger *log.Logger) *upstreamTransport {
	if logger == nil {
		logger = log.StandardLogger()
	}
	applyUpstreamHTTPVersion(base, version)

	return &upstreamTransport{
		primary:    base,
		version:    version,
		logger:     logger,
		downgraded: make(map[string]downgrade),
	}
}

// RoundTrip implements http.RoundTripper.
func (t *upstreamTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if !t.mayDowngrade(req) {
		return t.primary.RoundTrip(req)
	}

	host := req.URL.Host
	if t.isDowngraded(host) {
		return t.http1().RoundTrip(req)
	}

	resp, err := t.primary.RoundTrip(req)
	if err == nil || !isHTTP2ProtocolError(err) {
		return resp, err
	}

	// HTTP_1_1_REQUIRED is the upstream saying it will not serve this
	// request over h2 however often it is asked — IIS answers it for
	// Windows Authentication and for client-certificate sites, where
	// the cause is site configuration rather than a passing fault.
	t.markDowngraded(host, isHTTP11Required(err))

	retry, ok := replayable(req)
	if !ok {
		// The body is already consumed and cannot be regenerated, so
		// this request fails. The host is pinned either way, so the
		// next one goes out over HTTP/1.1.
		return nil, err
	}
	return t.http1().RoundTrip(retry)
}

// CloseIdleConnections closes idle connections on both pools.
func (t *upstreamTransport) CloseIdleConnections() {
	t.primary.CloseIdleConnections()
	if fallback := t.existingHTTP1(); fallback != nil {
		fallback.CloseIdleConnections()
	}
}

// mayDowngrade reports whether a failed request is a downgrade
// candidate. Only upstreamHTTPAuto downgrades, and only for TLS
// upstreams: the proxy speaks no h2c, so a cleartext upstream is
// already on HTTP/1.1 and an error there says nothing about h2.
func (t *upstreamTransport) mayDowngrade(req *http.Request) bool {
	return t.version == upstreamHTTPAuto && req.URL != nil && req.URL.Scheme == "https"
}

func (t *upstreamTransport) isDowngraded(host string) bool {
	now := time.Now()

	t.mu.RLock()
	pin, ok := t.downgraded[host]
	t.mu.RUnlock()

	if !ok {
		return false
	}
	if pin.active(now) {
		return true
	}

	t.mu.Lock()
	// Re-check under the write lock: a concurrent request may have
	// re-pinned the host after the read above.
	if pin, ok := t.downgraded[host]; ok && !pin.active(time.Now()) {
		delete(t.downgraded, host)
	}
	t.mu.Unlock()

	return false
}

// markDowngraded pins host to HTTP/1.1. permanent marks a pin the
// upstream asked for; anything else lapses after upstreamDowngradeTTL so
// a repaired backend is offered h2 again.
func (t *upstreamTransport) markDowngraded(host string, permanent bool) {
	now := time.Now()
	pin := downgrade{expiry: now.Add(upstreamDowngradeTTL)}
	if permanent {
		pin = downgrade{}
	}

	t.mu.Lock()
	previous, pinned := t.downgraded[host]
	// A permanent pin is never weakened back into an expiring one: the
	// upstream has already said h2 is not on offer.
	if !pinned || !previous.permanent() {
		t.downgraded[host] = pin
	}
	for h, existing := range t.downgraded {
		if !existing.active(now) {
			delete(t.downgraded, h)
		}
	}
	t.mu.Unlock()

	if pinned {
		return
	}

	entry := t.logger.WithField("upstream", host)
	if permanent {
		entry.Warnf("upstream answered HTTP_1_1_REQUIRED, using HTTP/1.1 for it from now on")
		return
	}
	entry.Warnf("upstream negotiated HTTP/2 but failed to serve it, using HTTP/1.1 for the next %s (set %s=1.1 to pin it)",
		upstreamDowngradeTTL, EnvUpstreamHTTPVersion)
}

// http1 returns the HTTP/1.1-only clone, creating it on first use.
func (t *upstreamTransport) http1() *http.Transport {
	t.fallbackMu.Lock()
	defer t.fallbackMu.Unlock()

	if t.fallback == nil {
		fallback := t.primary.Clone()
		applyUpstreamHTTPVersion(fallback, upstreamHTTP11)
		t.fallback = fallback
	}

	return t.fallback
}

// existingHTTP1 returns the fallback transport only if it was already
// created, so housekeeping never allocates a second connection pool for
// an upstream that never needed one.
func (t *upstreamTransport) existingHTTP1() *http.Transport {
	t.fallbackMu.Lock()
	defer t.fallbackMu.Unlock()

	return t.fallback
}

// replayable returns a request that can be sent a second time, or
// ok=false when the body is gone. A RoundTripper consumes and closes
// the body it was given, so a retry needs either no body at all or
// GetBody to produce a fresh one.
func replayable(req *http.Request) (*http.Request, bool) {
	if req.Body == nil || req.Body == http.NoBody {
		return req, true
	}
	if req.GetBody == nil {
		return nil, false
	}

	body, err := req.GetBody()
	if err != nil {
		return nil, false
	}

	retry := req.Clone(req.Context())
	retry.Body = body

	return retry, true
}

// http2ErrorMarkers are the substrings that identify an HTTP/2 protocol
// failure. net/http bundles its own private copy of the http2 package,
// so its errors cannot be matched by type from here: http2.StreamError
// and friends in x/net are different types from the ones a
// bundled-h2 transport returns. The strings below are the formats those
// bundled errors print, and they are specific to h2 framing — a
// downgrade must never be triggered by an ordinary network or TLS
// error, which retrying on HTTP/1.1 would not fix.
var http2ErrorMarkers = []string{
	// Transport-level h2 failures, e.g.
	// "http2: server sent GOAWAY and closed the connection".
	"http2:",
	// http2.StreamError, e.g. "stream error: stream ID 1; PROTOCOL_ERROR".
	"stream error: stream ID",
	// http2.ConnectionError, e.g. "connection error: PROTOCOL_ERROR".
	"connection error: ",
	// The code an upstream sends to say the request must be retried
	// over HTTP/1.1, as a GOAWAY or on the stream.
	http11RequiredMarker,
}

// http11RequiredMarker is the error code an upstream sends to say the
// request belongs on HTTP/1.1. Unlike the other markers it is not a
// fault: the upstream is describing its own configuration.
const http11RequiredMarker = "HTTP_1_1_REQUIRED"

// isHTTP11Required reports whether the upstream itself asked for
// HTTP/1.1, rather than merely failing at h2.
func isHTTP11Required(err error) bool {
	return err != nil && strings.Contains(err.Error(), http11RequiredMarker)
}

// isHTTP2ProtocolError reports whether err says the upstream cannot
// serve the h2 it negotiated.
func isHTTP2ProtocolError(err error) bool {
	if err == nil {
		return false
	}

	msg := err.Error()
	for _, marker := range http2ErrorMarkers {
		if strings.Contains(msg, marker) {
			return true
		}
	}

	return false
}
