package metrics

import (
	"context"
	"net/http"
	"sync"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"

	"github.com/netbirdio/netbird/proxy/internal/proxy"
	"github.com/netbirdio/netbird/proxy/internal/responsewriter"
	"github.com/netbirdio/netbird/proxy/internal/types"
)

// Metrics collects OpenTelemetry metrics for the proxy.
type Metrics struct {
	ctx                      context.Context
	requestsTotal            metric.Int64Counter
	activeRequests           metric.Int64UpDownCounter
	configuredDomains        metric.Int64UpDownCounter
	totalPaths               metric.Int64UpDownCounter
	requestDuration          metric.Int64Histogram
	backendDuration          metric.Int64Histogram
	certificateIssueDuration metric.Int64Histogram

	// L4 service-level metrics.
	l4Services metric.Int64UpDownCounter

	// L4 TCP connection-level metrics.
	tcpActiveConns  metric.Int64UpDownCounter
	tcpConnsTotal   metric.Int64Counter
	tcpConnDuration metric.Int64Histogram
	tcpBytesTotal   metric.Int64Counter

	// L4 UDP session-level metrics.
	udpActiveSess    metric.Int64UpDownCounter
	udpSessionsTotal metric.Int64Counter
	udpPacketsTotal  metric.Int64Counter
	udpBytesTotal    metric.Int64Counter

	mappingsMux  sync.Mutex
	mappingPaths map[string]int
}

// New creates a Metrics instance using the given OpenTelemetry meter.
func New(ctx context.Context, meter metric.Meter) (*Metrics, error) {
	m := &Metrics{
		ctx:          ctx,
		mappingPaths: make(map[string]int),
	}

	if err := m.initHTTPMetrics(meter); err != nil {
		return nil, err
	}
	if err := m.initL4Metrics(meter); err != nil {
		return nil, err
	}

	return m, nil
}

func (m *Metrics) initHTTPMetrics(meter metric.Meter) error {
	var err error

	m.requestsTotal, err = meter.Int64Counter(
		"proxy.http.request.counter",
		metric.WithUnit("1"),
		metric.WithDescription("Total number of requests made to the netbird proxy"),
	)
	if err != nil {
		return err
	}

	m.activeRequests, err = meter.Int64UpDownCounter(
		"proxy.http.active_requests",
		metric.WithUnit("1"),
		metric.WithDescription("Current in-flight requests handled by the netbird proxy"),
	)
	if err != nil {
		return err
	}

	m.configuredDomains, err = meter.Int64UpDownCounter(
		"proxy.domains.count",
		metric.WithUnit("1"),
		metric.WithDescription("Current number of domains configured on the netbird proxy"),
	)
	if err != nil {
		return err
	}

	m.totalPaths, err = meter.Int64UpDownCounter(
		"proxy.paths.count",
		metric.WithUnit("1"),
		metric.WithDescription("Total number of paths configured on the netbird proxy"),
	)
	if err != nil {
		return err
	}

	m.requestDuration, err = meter.Int64Histogram(
		"proxy.http.request.duration.ms",
		metric.WithUnit("milliseconds"),
		metric.WithDescription("Duration of requests made to the netbird proxy"),
	)
	if err != nil {
		return err
	}

	m.backendDuration, err = meter.Int64Histogram(
		"proxy.backend.duration.ms",
		metric.WithUnit("milliseconds"),
		metric.WithDescription("Duration of peer round trip time from the netbird proxy"),
	)
	if err != nil {
		return err
	}

	m.certificateIssueDuration, err = meter.Int64Histogram(
		"proxy.certificate.issue.duration.ms",
		metric.WithUnit("milliseconds"),
		metric.WithDescription("Duration of ACME certificate issuance"),
	)
	return err
}

func (m *Metrics) initL4Metrics(meter metric.Meter) error {
	var err error

	m.l4Services, err = meter.Int64UpDownCounter(
		"proxy.l4.services.count",
		metric.WithUnit("1"),
		metric.WithDescription("Current number of configured L4 services (TCP/TLS/UDP) by mode"),
	)
	if err != nil {
		return err
	}

	m.tcpActiveConns, err = meter.Int64UpDownCounter(
		"proxy.tcp.active_connections",
		metric.WithUnit("1"),
		metric.WithDescription("Current number of active TCP/TLS relay connections"),
	)
	if err != nil {
		return err
	}

	m.tcpConnsTotal, err = meter.Int64Counter(
		"proxy.tcp.connections.total",
		metric.WithUnit("1"),
		metric.WithDescription("Total TCP/TLS relay connections by result and account"),
	)
	if err != nil {
		return err
	}

	m.tcpConnDuration, err = meter.Int64Histogram(
		"proxy.tcp.connection.duration.ms",
		metric.WithUnit("milliseconds"),
		metric.WithDescription("Duration of TCP/TLS relay connections"),
	)
	if err != nil {
		return err
	}

	m.tcpBytesTotal, err = meter.Int64Counter(
		"proxy.tcp.bytes.total",
		metric.WithUnit("bytes"),
		metric.WithDescription("Total bytes transferred through TCP/TLS relay by direction"),
	)
	if err != nil {
		return err
	}

	m.udpActiveSess, err = meter.Int64UpDownCounter(
		"proxy.udp.active_sessions",
		metric.WithUnit("1"),
		metric.WithDescription("Current number of active UDP relay sessions"),
	)
	if err != nil {
		return err
	}

	m.udpSessionsTotal, err = meter.Int64Counter(
		"proxy.udp.sessions.total",
		metric.WithUnit("1"),
		metric.WithDescription("Total UDP relay sessions by result and account"),
	)
	if err != nil {
		return err
	}

	m.udpPacketsTotal, err = meter.Int64Counter(
		"proxy.udp.packets.total",
		metric.WithUnit("1"),
		metric.WithDescription("Total UDP packets relayed by direction"),
	)
	if err != nil {
		return err
	}

	m.udpBytesTotal, err = meter.Int64Counter(
		"proxy.udp.bytes.total",
		metric.WithUnit("bytes"),
		metric.WithDescription("Total bytes transferred through UDP relay by direction"),
	)
	return err
}

type responseInterceptor struct {
	*responsewriter.PassthroughWriter
	status int
	size   int
}

func (w *responseInterceptor) WriteHeader(status int) {
	w.status = status
	w.PassthroughWriter.WriteHeader(status)
}

func (w *responseInterceptor) Write(b []byte) (int, error) {
	size, err := w.PassthroughWriter.Write(b)
	w.size += size
	return size, err
}

// Unwrap returns the underlying ResponseWriter so http.ResponseController
// can reach through to the original writer for Hijack/Flush operations.
func (w *responseInterceptor) Unwrap() http.ResponseWriter {
	return w.PassthroughWriter
}

// Middleware wraps an HTTP handler with request metrics.
func (m *Metrics) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		m.requestsTotal.Add(m.ctx, 1)
		m.activeRequests.Add(m.ctx, 1)

		interceptor := &responseInterceptor{PassthroughWriter: responsewriter.New(w)}

		start := time.Now()
		defer func() {
			duration := time.Since(start)
			m.activeRequests.Add(m.ctx, -1)
			m.requestDuration.Record(m.ctx, duration.Milliseconds())
		}()

		next.ServeHTTP(interceptor, r)
	})
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

// RoundTripper wraps an http.RoundTripper with backend duration metrics.
func (m *Metrics) RoundTripper(next http.RoundTripper) http.RoundTripper {
	return roundTripperFunc(func(req *http.Request) (*http.Response, error) {
		start := time.Now()
		res, err := next.RoundTrip(req)
		duration := time.Since(start)

		m.backendDuration.Record(m.ctx, duration.Milliseconds())

		return res, err
	})
}

// AddMapping records that a domain mapping was added.
func (m *Metrics) AddMapping(mapping proxy.Mapping) {
	m.mappingsMux.Lock()
	defer m.mappingsMux.Unlock()

	newPathCount := len(mapping.Paths)
	oldPathCount, exists := m.mappingPaths[mapping.Host]

	if !exists {
		m.configuredDomains.Add(m.ctx, 1)
	}

	pathDelta := newPathCount - oldPathCount
	if pathDelta != 0 {
		m.totalPaths.Add(m.ctx, int64(pathDelta))
	}

	m.mappingPaths[mapping.Host] = newPathCount
}

// RemoveMapping records that a domain mapping was removed.
func (m *Metrics) RemoveMapping(mapping proxy.Mapping) {
	m.mappingsMux.Lock()
	defer m.mappingsMux.Unlock()

	oldPathCount, exists := m.mappingPaths[mapping.Host]
	if !exists {
		return
	}

	m.configuredDomains.Add(m.ctx, -1)
	m.totalPaths.Add(m.ctx, -int64(oldPathCount))

	delete(m.mappingPaths, mapping.Host)
}

// RecordCertificateIssuance records the duration of a certificate issuance.
func (m *Metrics) RecordCertificateIssuance(duration time.Duration) {
	m.certificateIssueDuration.Record(m.ctx, duration.Milliseconds())
}

// L4ServiceAdded increments the L4 service gauge for the given mode.
func (m *Metrics) L4ServiceAdded(mode types.ServiceMode) {
	m.l4Services.Add(m.ctx, 1, metric.WithAttributes(attribute.String("mode", string(mode))))
}

// L4ServiceRemoved decrements the L4 service gauge for the given mode.
func (m *Metrics) L4ServiceRemoved(mode types.ServiceMode) {
	m.l4Services.Add(m.ctx, -1, metric.WithAttributes(attribute.String("mode", string(mode))))
}

// TCPRelayStarted records a new TCP relay connection starting.
func (m *Metrics) TCPRelayStarted(accountID types.AccountID) {
	acct := attribute.String("account_id", string(accountID))
	m.tcpActiveConns.Add(m.ctx, 1, metric.WithAttributes(acct))
	m.tcpConnsTotal.Add(m.ctx, 1, metric.WithAttributes(acct, attribute.String("result", "success")))
}

// TCPRelayEnded records a TCP relay connection ending and accumulates bytes and duration.
func (m *Metrics) TCPRelayEnded(accountID types.AccountID, duration time.Duration, srcToDst, dstToSrc int64) {
	acct := attribute.String("account_id", string(accountID))
	m.tcpActiveConns.Add(m.ctx, -1, metric.WithAttributes(acct))
	m.tcpConnDuration.Record(m.ctx, duration.Milliseconds(), metric.WithAttributes(acct))
	m.tcpBytesTotal.Add(m.ctx, srcToDst, metric.WithAttributes(attribute.String("direction", "client_to_backend")))
	m.tcpBytesTotal.Add(m.ctx, dstToSrc, metric.WithAttributes(attribute.String("direction", "backend_to_client")))
}

// TCPRelayDialError records a dial failure for a TCP relay.
func (m *Metrics) TCPRelayDialError(accountID types.AccountID) {
	m.tcpConnsTotal.Add(m.ctx, 1, metric.WithAttributes(
		attribute.String("account_id", string(accountID)),
		attribute.String("result", "dial_error"),
	))
}

// TCPRelayRejected records a rejected TCP relay (semaphore full).
func (m *Metrics) TCPRelayRejected(accountID types.AccountID) {
	m.tcpConnsTotal.Add(m.ctx, 1, metric.WithAttributes(
		attribute.String("account_id", string(accountID)),
		attribute.String("result", "rejected"),
	))
}

// UDPSessionStarted records a new UDP session starting.
func (m *Metrics) UDPSessionStarted(accountID types.AccountID) {
	acct := attribute.String("account_id", string(accountID))
	m.udpActiveSess.Add(m.ctx, 1, metric.WithAttributes(acct))
	m.udpSessionsTotal.Add(m.ctx, 1, metric.WithAttributes(acct, attribute.String("result", "success")))
}

// UDPSessionEnded records a UDP session ending.
func (m *Metrics) UDPSessionEnded(accountID types.AccountID) {
	m.udpActiveSess.Add(m.ctx, -1, metric.WithAttributes(attribute.String("account_id", string(accountID))))
}

// UDPSessionDialError records a dial failure for a UDP session.
func (m *Metrics) UDPSessionDialError(accountID types.AccountID) {
	m.udpSessionsTotal.Add(m.ctx, 1, metric.WithAttributes(
		attribute.String("account_id", string(accountID)),
		attribute.String("result", "dial_error"),
	))
}

// UDPSessionRejected records a rejected UDP session (limit or rate limited).
func (m *Metrics) UDPSessionRejected(accountID types.AccountID) {
	m.udpSessionsTotal.Add(m.ctx, 1, metric.WithAttributes(
		attribute.String("account_id", string(accountID)),
		attribute.String("result", "rejected"),
	))
}

// UDPPacketRelayed records a packet relayed in the given direction with its size in bytes.
func (m *Metrics) UDPPacketRelayed(direction types.RelayDirection, bytes int) {
	dir := attribute.String("direction", string(direction))
	m.udpPacketsTotal.Add(m.ctx, 1, metric.WithAttributes(dir))
	m.udpBytesTotal.Add(m.ctx, int64(bytes), metric.WithAttributes(dir))
}
