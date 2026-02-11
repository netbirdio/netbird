package metrics

import (
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

type Metrics struct {
	requestsTotal   prometheus.Counter
	requestDuration prometheus.Histogram
	activeRequests  prometheus.Counter
	backendDuration prometheus.Histogram
}

func New(reg prometheus.Registerer) *Metrics {
	return &Metrics{
		requestsTotal: promauto.With(reg).NewCounter(prometheus.CounterOpts{
			Name: "netbird_proxy_requests_total",
			Help: "Total number of requests made to the netbird proxy",
		}),
		requestDuration: promauto.With(reg).NewHistogram(prometheus.HistogramOpts{
			Name:    "netbird_proxy_request_duration_seconds",
			Help:    "Duration of requests made to the netbird proxy",
			Buckets: []float64{0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10},
		}),
		activeRequests: promauto.With(reg).NewCounter(prometheus.CounterOpts{
			Name: "netbird_proxy_active_requests_total",
			Help: "Current in-flight requests handled by the netbird proxy",
		}),
		backendDuration: promauto.With(reg).NewHistogram(prometheus.HistogramOpts{
			Name:    "netbird_proxy_backend_duration_seconds",
			Help:    "Duration of peer round trip time from the netbird proxy",
			Buckets: []float64{0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10},
		}),
	}
}

func (m *Metrics) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		m.requestsTotal.Inc()
		m.activeRequests.Inc()

		start := time.Now()
		next.ServeHTTP(w, r)

		m.activeRequests.Desc()
		m.requestDuration.Observe(time.Since(start).Seconds())
	})
}

func (m *Metrics) CompleteRoundTrip(t time.Duration) {
	m.backendDuration.Observe(t.Seconds())
}
