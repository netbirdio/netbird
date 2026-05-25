package roundtrip

import (
	"crypto/tls"
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
type MultiTransport struct {
	embedded http.RoundTripper
	direct   *http.Transport
	insecure *http.Transport
}

// NewMultiTransport wires both branches. embedded is the existing NetBird
// roundtripper; the direct branches honour the same NB_PROXY_* tuning
// env vars as the embedded transport (see loadTransportConfig) plus a
// dial-timeout wrapper that respects types.WithDialTimeout.
// Pass embedded=nil to disable the WG branch entirely (every request
// will route direct, regardless of the context flag).
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

// RoundTrip dispatches by reading the direct-upstream flag from the request
// context. When set, the request is forwarded via the stdlib transport,
// honouring the existing per-request skip-TLS-verify flag. Otherwise it
// goes through the embedded NetBird roundtripper.
func (m *MultiTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if DirectUpstreamFromContext(req.Context()) || m.embedded == nil {
		if skipTLSVerifyFromContext(req.Context()) {
			return m.insecure.RoundTrip(req)
		}
		return m.direct.RoundTrip(req)
	}
	return m.embedded.RoundTrip(req)
}
