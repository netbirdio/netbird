package metrics

import (
	"net/http"
	"strconv"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"github.com/netbirdio/netbird/proxy/internal/proxy"
	"github.com/netbirdio/netbird/proxy/internal/responsewriter"
	"github.com/netbirdio/netbird/proxy/internal/types"
)

// Metrics collects Prometheus metrics for the proxy.
type Metrics struct {
	requestsTotal     prometheus.Counter
	activeRequests    prometheus.Gauge
	configuredDomains prometheus.Gauge
	pathsPerDomain    *prometheus.GaugeVec
	requestDuration   *prometheus.HistogramVec
	backendDuration   *prometheus.HistogramVec
	l4Services        *prometheus.GaugeVec

	// L4 connection-level metrics.
	tcpActiveConns   *prometheus.GaugeVec
	tcpConnsTotal    *prometheus.CounterVec
	tcpConnDuration  *prometheus.HistogramVec
	tcpBytesTotal    *prometheus.CounterVec
	udpActiveSess    *prometheus.GaugeVec
	udpSessionsTotal *prometheus.CounterVec
	udpPacketsTotal  *prometheus.CounterVec
	udpBytesTotal    *prometheus.CounterVec
}

// New creates a Metrics instance registered with the given registerer.
func New(reg prometheus.Registerer) *Metrics {
	promFactory := promauto.With(reg)
	return &Metrics{
		requestsTotal: promFactory.NewCounter(prometheus.CounterOpts{
			Name: "netbird_proxy_requests_total",
			Help: "Total number of requests made to the netbird proxy",
		}),
		activeRequests: promFactory.NewGauge(prometheus.GaugeOpts{
			Name: "netbird_proxy_active_requests_count",
			Help: "Current in-flight requests handled by the netbird proxy",
		}),
		configuredDomains: promFactory.NewGauge(prometheus.GaugeOpts{
			Name: "netbird_proxy_domains_count",
			Help: "Current number of domains configured on the netbird proxy",
		}),
		pathsPerDomain: promFactory.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "netbird_proxy_paths_count",
				Help: "Current number of paths configured on the netbird proxy labelled by domain",
			},
			[]string{"domain"},
		),
		requestDuration: promFactory.NewHistogramVec(
			prometheus.HistogramOpts{
				Name:    "netbird_proxy_request_duration_seconds",
				Help:    "Duration of requests made to the netbird proxy",
				Buckets: []float64{0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10},
			},
			[]string{"status", "size", "method", "host", "path"},
		),
		backendDuration: promFactory.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "netbird_proxy_backend_duration_seconds",
			Help:    "Duration of peer round trip time from the netbird proxy",
			Buckets: []float64{0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10},
		},
			[]string{"status", "size", "method", "host", "path"},
		),
		l4Services: promFactory.NewGaugeVec(prometheus.GaugeOpts{
			Name: "netbird_proxy_l4_services_count",
			Help: "Current number of configured L4 services (TCP/TLS/UDP) by mode",
		}, []string{"mode"}),

		tcpActiveConns: promFactory.NewGaugeVec(prometheus.GaugeOpts{
			Name: "netbird_proxy_tcp_active_connections",
			Help: "Current number of active TCP/TLS relay connections",
		}, []string{"account_id"}),
		tcpConnsTotal: promFactory.NewCounterVec(prometheus.CounterOpts{
			Name: "netbird_proxy_tcp_connections_total",
			Help: "Total TCP/TLS relay connections by result and account",
		}, []string{"account_id", "result"}),
		tcpConnDuration: promFactory.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "netbird_proxy_tcp_connection_duration_seconds",
			Help:    "Duration of TCP/TLS relay connections by account",
			Buckets: []float64{1, 5, 15, 30, 60, 120, 300, 600, 1800, 3600},
		}, []string{"account_id"}),
		tcpBytesTotal: promFactory.NewCounterVec(prometheus.CounterOpts{
			Name: "netbird_proxy_tcp_bytes_total",
			Help: "Total bytes transferred through TCP/TLS relay by direction",
		}, []string{"direction"}),

		udpActiveSess: promFactory.NewGaugeVec(prometheus.GaugeOpts{
			Name: "netbird_proxy_udp_active_sessions",
			Help: "Current number of active UDP relay sessions",
		}, []string{"account_id"}),
		udpSessionsTotal: promFactory.NewCounterVec(prometheus.CounterOpts{
			Name: "netbird_proxy_udp_sessions_total",
			Help: "Total UDP relay sessions by result and account",
		}, []string{"account_id", "result"}),
		udpPacketsTotal: promFactory.NewCounterVec(prometheus.CounterOpts{
			Name: "netbird_proxy_udp_packets_total",
			Help: "Total UDP packets relayed by direction",
		}, []string{"direction"}),
		udpBytesTotal: promFactory.NewCounterVec(prometheus.CounterOpts{
			Name: "netbird_proxy_udp_bytes_total",
			Help: "Total bytes transferred through UDP relay by direction",
		}, []string{"direction"}),
	}
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
		m.requestsTotal.Inc()
		m.activeRequests.Inc()

		interceptor := &responseInterceptor{PassthroughWriter: responsewriter.New(w)}

		start := time.Now()
		next.ServeHTTP(interceptor, r)
		duration := time.Since(start)

		m.activeRequests.Dec()
		m.requestDuration.With(prometheus.Labels{
			"status": strconv.Itoa(interceptor.status),
			"size":   strconv.Itoa(interceptor.size),
			"method": r.Method,
			"host":   r.Host,
			"path":   r.URL.Path,
		}).Observe(duration.Seconds())
	})
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

// RoundTripper wraps an http.RoundTripper with backend duration metrics.
func (m *Metrics) RoundTripper(next http.RoundTripper) http.RoundTripper {
	return roundTripperFunc(func(req *http.Request) (*http.Response, error) {
		labels := prometheus.Labels{
			"method": req.Method,
			"host":   req.Host,
			// Fill potentially empty labels with default values to avoid cardinality issues.
			"path":   "/",
			"status": "0",
			"size":   "0",
		}
		if req.URL != nil {
			labels["path"] = req.URL.Path
		}

		start := time.Now()
		res, err := next.RoundTrip(req)
		duration := time.Since(start)

		// Not all labels will be available if there was an error.
		if res != nil {
			labels["status"] = strconv.Itoa(res.StatusCode)
			labels["size"] = strconv.Itoa(int(res.ContentLength))
		}

		m.backendDuration.With(labels).Observe(duration.Seconds())

		return res, err
	})
}

// AddMapping records that a domain mapping was added.
func (m *Metrics) AddMapping(mapping proxy.Mapping) {
	m.configuredDomains.Inc()
	m.pathsPerDomain.With(prometheus.Labels{
		"domain": mapping.Host,
	}).Set(float64(len(mapping.Paths)))
}

// RemoveMapping records that a domain mapping was removed.
func (m *Metrics) RemoveMapping(mapping proxy.Mapping) {
	m.configuredDomains.Dec()
	m.pathsPerDomain.With(prometheus.Labels{
		"domain": mapping.Host,
	}).Set(0)
}

// L4ServiceAdded increments the L4 service gauge for the given mode.
func (m *Metrics) L4ServiceAdded(mode types.ServiceMode) {
	m.l4Services.With(prometheus.Labels{"mode": string(mode)}).Inc()
}

// L4ServiceRemoved decrements the L4 service gauge for the given mode.
func (m *Metrics) L4ServiceRemoved(mode types.ServiceMode) {
	m.l4Services.With(prometheus.Labels{"mode": string(mode)}).Dec()
}

// TCPRelayStarted records a new TCP relay connection starting.
func (m *Metrics) TCPRelayStarted(accountID string) {
	m.tcpActiveConns.With(prometheus.Labels{"account_id": accountID}).Inc()
	m.tcpConnsTotal.With(prometheus.Labels{"account_id": accountID, "result": "success"}).Inc()
}

// TCPRelayEnded records a TCP relay connection ending and accumulates bytes and duration.
func (m *Metrics) TCPRelayEnded(accountID string, duration time.Duration, srcToDst, dstToSrc int64) {
	m.tcpActiveConns.With(prometheus.Labels{"account_id": accountID}).Dec()
	m.tcpConnDuration.With(prometheus.Labels{"account_id": accountID}).Observe(duration.Seconds())
	m.tcpBytesTotal.With(prometheus.Labels{"direction": "client_to_backend"}).Add(float64(srcToDst))
	m.tcpBytesTotal.With(prometheus.Labels{"direction": "backend_to_client"}).Add(float64(dstToSrc))
}

// TCPRelayDialError records a dial failure for a TCP relay.
func (m *Metrics) TCPRelayDialError(accountID string) {
	m.tcpConnsTotal.With(prometheus.Labels{"account_id": accountID, "result": "dial_error"}).Inc()
}

// TCPRelayRejected records a rejected TCP relay (semaphore full).
func (m *Metrics) TCPRelayRejected(accountID string) {
	m.tcpConnsTotal.With(prometheus.Labels{"account_id": accountID, "result": "rejected"}).Inc()
}

// UDPSessionStarted records a new UDP session starting.
func (m *Metrics) UDPSessionStarted(accountID string) {
	m.udpActiveSess.With(prometheus.Labels{"account_id": accountID}).Inc()
	m.udpSessionsTotal.With(prometheus.Labels{"account_id": accountID, "result": "success"}).Inc()
}

// UDPSessionEnded records a UDP session ending.
func (m *Metrics) UDPSessionEnded(accountID string) {
	m.udpActiveSess.With(prometheus.Labels{"account_id": accountID}).Dec()
}

// UDPSessionDialError records a dial failure for a UDP session.
func (m *Metrics) UDPSessionDialError(accountID string) {
	m.udpSessionsTotal.With(prometheus.Labels{"account_id": accountID, "result": "dial_error"}).Inc()
}

// UDPSessionRejected records a rejected UDP session (limit or rate limited).
func (m *Metrics) UDPSessionRejected(accountID string) {
	m.udpSessionsTotal.With(prometheus.Labels{"account_id": accountID, "result": "rejected"}).Inc()
}

// UDPPacketRelayed records a packet relayed in the given direction with its size in bytes.
func (m *Metrics) UDPPacketRelayed(direction types.RelayDirection, bytes int) {
	d := string(direction)
	m.udpPacketsTotal.With(prometheus.Labels{"direction": d}).Inc()
	m.udpBytesTotal.With(prometheus.Labels{"direction": d}).Add(float64(bytes))
}
