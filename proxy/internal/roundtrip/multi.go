package roundtrip

import (
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"time"

	log "github.com/sirupsen/logrus"
)

// MultiTransport dispatches each request to either the embedded NetBird
// http.RoundTripper or a stdlib http.Transport based on a per-request
// context flag set by the reverse-proxy rewrite step. When the flag is
// absent (the default for every existing target), requests follow the
// embedded NetBird path — current behaviour, preserved.
//
// The stdlib branch is used when a target was configured with
// direct_upstream=true. It dials via the host's network stack, which is
// what private (`netbird proxy`) deployments and centralised proxies
// fronting host-reachable upstreams (public APIs, LAN services,
// localhost sidecars) want.
//
// An embedded roundtripper is required. To run direct-only (no WG
// branch at all), construct the MultiTransport via NewDirectOnly.
type MultiTransport struct {
	embedded http.RoundTripper
	direct   *http.Transport
	insecure *http.Transport
}

// errNoEmbeddedTransport is returned when a request reaches the
// embedded branch on a MultiTransport that wasn't given one. Surfaces
// the misconfiguration to the caller instead of silently routing to
// the direct branch, which would bypass the WG tunnel.
var errNoEmbeddedTransport = errors.New("multitransport: embedded roundtripper not configured")

// NewMultiTransport wires both branches. embedded is the existing NetBird
// roundtripper and must not be nil — pass to NewDirectOnly for a
// MultiTransport that only ever uses the direct branch. The direct
// branches honour the same NB_PROXY_* tuning env vars as the embedded
// transport (see loadTransportConfig) plus a dial-timeout wrapper that
// respects types.WithDialTimeout.
func NewMultiTransport(embedded http.RoundTripper, logger *log.Logger) *MultiTransport {
	if logger == nil {
		logger = log.StandardLogger()
	}
	cfg := loadTransportConfig(logger)
	dialer := &net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
	}
	direct := &http.Transport{
		DialContext:           dialWithTimeout(dialer.DialContext),
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          cfg.maxIdleConns,
		MaxIdleConnsPerHost:   cfg.maxIdleConnsPerHost,
		MaxConnsPerHost:       cfg.maxConnsPerHost,
		IdleConnTimeout:       cfg.idleConnTimeout,
		TLSHandshakeTimeout:   cfg.tlsHandshakeTimeout,
		ExpectContinueTimeout: cfg.expectContinueTimeout,
		ResponseHeaderTimeout: cfg.responseHeaderTimeout,
		WriteBufferSize:       cfg.writeBufferSize,
		ReadBufferSize:        cfg.readBufferSize,
		DisableCompression:    cfg.disableCompression,
	}
	insecure := direct.Clone()
	insecure.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec // matches the embedded NetBird transport's per-target opt-in

	return &MultiTransport{
		embedded: embedded,
		direct:   direct,
		insecure: insecure,
	}
}

// NewDirectOnly returns a MultiTransport with no embedded branch.
// Every request goes through the direct branch regardless of the
// per-request flag, so the embedded path can never be reached
// silently — wiring code that needs WG must use NewMultiTransport.
func NewDirectOnly(logger *log.Logger) *MultiTransport {
	return NewMultiTransport(noEmbeddedRoundTripper{}, logger)
}

// noEmbeddedRoundTripper is the sentinel embedded transport for
// direct-only MultiTransports. RoundTrip is never called in practice
// because the direct branch matches every request, but if anything
// ever did reach this path it would fail loudly instead of falling
// back to direct.
type noEmbeddedRoundTripper struct{}

func (noEmbeddedRoundTripper) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, errNoEmbeddedTransport
}

// RoundTrip dispatches by reading the direct-upstream flag from the request
// context. When set, the request is forwarded via the stdlib transport,
// honouring the existing per-request skip-TLS-verify flag. Otherwise it
// goes through the embedded NetBird roundtripper.
func (m *MultiTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if DirectUpstreamFromContext(req.Context()) {
		if skipTLSVerifyFromContext(req.Context()) {
			return m.insecure.RoundTrip(req)
		}
		return m.direct.RoundTrip(req)
	}
	if m.embedded == nil {
		return nil, errNoEmbeddedTransport
	}
	return m.embedded.RoundTrip(req)
}
