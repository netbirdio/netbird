package roundtrip

import (
	"bytes"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"sort"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
)

// upstreamLogBodyMax caps the request body bytes copied into the
// debug log line so a giant prompt or streamed payload doesn't fill the
// log. The body itself is always restored to the request unchanged.
const upstreamLogBodyMax = 4096

// MultiTransport dispatches each request to either the embedded NetBird
// http.RoundTripper or a stdlib http.Transport based on a per-request
// context flag set by the reverse-proxy rewrite step. When the flag is
// absent (the default for every existing target), requests follow the
// embedded NetBird path — current behaviour, preserved.
//
// The stdlib branch is used when a target was configured with
// `direct_upstream=true`. It dials via the host's network stack, which
// is what private (`netbird proxy`) deployments and centralised proxies
// fronting host-reachable upstreams (public APIs, LAN services,
// localhost sidecars) want.
type MultiTransport struct {
	embedded http.RoundTripper
	direct   *http.Transport
	insecure *http.Transport
	logger   *log.Logger
}

// NewMultiTransport wires both branches. embedded is the existing NetBird
// roundtripper; the direct branches are constructed here with sensible
// defaults that mirror Go's stdlib defaults plus a dial-timeout wrapper
// honouring the per-request value attached via types.WithDialTimeout.
// Pass embedded=nil to disable the WG branch entirely (every request
// will route direct, regardless of the context flag). logger may be
// nil; when nil the transport falls back to the logrus default
// instance.
func NewMultiTransport(embedded http.RoundTripper, logger *log.Logger) *MultiTransport {
	dialer := &net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
	}
	direct := &http.Transport{
		DialContext:           dialWithTimeout(dialer.DialContext),
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}
	insecure := direct.Clone()
	insecure.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec // matches the embedded NetBird transport's per-target opt-in

	if logger == nil {
		logger = log.StandardLogger()
	}

	return &MultiTransport{
		embedded: embedded,
		direct:   direct,
		insecure: insecure,
		logger:   logger,
	}
}

// RoundTrip dispatches by reading the direct-upstream flag from the request
// context. When set, the request is forwarded via the stdlib transport,
// honouring the existing per-request skip-TLS-verify flag. Otherwise it
// goes through the embedded NetBird roundtripper.
func (m *MultiTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	m.logUpstreamRequest(req)
	if DirectUpstreamFromContext(req.Context()) || m.embedded == nil {
		if skipTLSVerifyFromContext(req.Context()) {
			return m.insecure.RoundTrip(req)
		}
		return m.direct.RoundTrip(req)
	}
	return m.embedded.RoundTrip(req)
}

// logUpstreamRequest emits the outbound request method, URL, headers,
// and a (capped) body snippet at info level for debugging. The body is
// read, copied into a snippet, and restored on the request so the
// actual upstream call sees it unchanged.
func (m *MultiTransport) logUpstreamRequest(req *http.Request) {
	if req == nil {
		return
	}
	body := snapshotRequestBody(req)
	m.logger.Debugf("upstream request: method=%s url=%s host=%s body_length=%d headers=%s body=%s",
		req.Method, req.URL.String(), req.Host, req.ContentLength, formatHeaders(req.Header), body)
}

// formatHeaders renders the headers as a deterministic single-line
// string. Multi-valued headers are joined with commas. Sensitive
// header values (the upstream Authorization NetBird just stamped, plus
// any cookie jar that survived) are redacted so logs don't leak the
// provider API key.
func formatHeaders(h http.Header) string {
	if len(h) == 0 {
		return "{}"
	}
	keys := make([]string, 0, len(h))
	for k := range h {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var sb strings.Builder
	sb.WriteByte('{')
	for i, k := range keys {
		if i > 0 {
			sb.WriteByte(' ')
		}
		sb.WriteString(k)
		sb.WriteByte('=')
		sb.WriteString(redactHeaderValue(k, h.Values(k)))
	}
	sb.WriteByte('}')
	return sb.String()
}

// redactHeaderValue replaces sensitive credentials with a placeholder.
// All other header values are joined with commas verbatim.
func redactHeaderValue(name string, values []string) string {
	switch strings.ToLower(name) {
	case "authorization", "proxy-authorization", "x-api-key", "api-key", "cookie":
		return "[redacted]"
	}
	return strings.Join(values, ",")
}

// snapshotRequestBody returns a printable snippet of the request body
// (capped to upstreamLogBodyMax) and restores the body so downstream
// transports can still read it. Returns the empty string when there's
// no body or it can't be read.
func snapshotRequestBody(req *http.Request) string {
	if req.Body == nil || req.Body == http.NoBody {
		return ""
	}
	raw, err := io.ReadAll(req.Body)
	if err != nil {
		return ""
	}
	req.Body = io.NopCloser(bytes.NewReader(raw))
	// Restore GetBody so transports performing redirects or retries
	// still get a fresh reader.
	req.GetBody = func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(raw)), nil
	}
	if len(raw) > upstreamLogBodyMax {
		return string(raw[:upstreamLogBodyMax]) + "...[truncated]"
	}
	return string(raw)
}
