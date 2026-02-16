package metrics

import (
	"net/http"
	"strconv"
	"time"

	"github.com/netbirdio/netbird/proxy/internal/proxy"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

type Metrics struct {
	requestsTotal     prometheus.Counter
	activeRequests    prometheus.Gauge
	configuredDomains prometheus.Gauge
	pathsPerDomain    *prometheus.GaugeVec
	requestDuration   *prometheus.HistogramVec
	backendDuration   *prometheus.HistogramVec
}

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
	}
}

type responseInterceptor struct {
	http.ResponseWriter
	status int
	size   int
}

func (w *responseInterceptor) WriteHeader(status int) {
	w.status = status
	w.ResponseWriter.WriteHeader(status)
}

func (w *responseInterceptor) Write(b []byte) (int, error) {
	size, err := w.ResponseWriter.Write(b)
	w.size += size
	return size, err
}

func (m *Metrics) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		m.requestsTotal.Inc()
		m.activeRequests.Inc()

		interceptor := &responseInterceptor{ResponseWriter: w}

		start := time.Now()
		next.ServeHTTP(interceptor, r)
		duration := time.Since(start)

		m.activeRequests.Desc()
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

func (m *Metrics) AddMapping(mapping proxy.Mapping) {
	m.configuredDomains.Inc()
	m.pathsPerDomain.With(prometheus.Labels{
		"domain": mapping.Host,
	}).Set(float64(len(mapping.Paths)))
}

func (m *Metrics) RemoveMapping(mapping proxy.Mapping) {
	m.configuredDomains.Dec()
	m.pathsPerDomain.With(prometheus.Labels{
		"domain": mapping.Host,
	}).Set(0)
}
