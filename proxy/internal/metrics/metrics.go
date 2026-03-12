package metrics

import (
	"context"
	"net/http"
	"sync"
	"time"

	"go.opentelemetry.io/otel/metric"

	"github.com/netbirdio/netbird/proxy/internal/proxy"
	"github.com/netbirdio/netbird/proxy/internal/responsewriter"
)

type Metrics struct {
	ctx                      context.Context
	requestsTotal            metric.Int64Counter
	activeRequests           metric.Int64UpDownCounter
	configuredDomains        metric.Int64UpDownCounter
	totalPaths               metric.Int64UpDownCounter
	requestDuration          metric.Int64Histogram
	backendDuration          metric.Int64Histogram
	certificateIssueDuration metric.Int64Histogram

	mappingsMux  sync.Mutex
	mappingPaths map[string]int
}

func New(ctx context.Context, meter metric.Meter) (*Metrics, error) {
	requestsTotal, err := meter.Int64Counter(
		"proxy.http.request.counter",
		metric.WithUnit("1"),
		metric.WithDescription("Total number of requests made to the netbird proxy"),
	)
	if err != nil {
		return nil, err
	}

	activeRequests, err := meter.Int64UpDownCounter(
		"proxy.http.active_requests",
		metric.WithUnit("1"),
		metric.WithDescription("Current in-flight requests handled by the netbird proxy"),
	)
	if err != nil {
		return nil, err
	}

	configuredDomains, err := meter.Int64UpDownCounter(
		"proxy.domains.count",
		metric.WithUnit("1"),
		metric.WithDescription("Current number of domains configured on the netbird proxy"),
	)
	if err != nil {
		return nil, err
	}

	totalPaths, err := meter.Int64UpDownCounter(
		"proxy.paths.count",
		metric.WithUnit("1"),
		metric.WithDescription("Total number of paths configured on the netbird proxy"),
	)
	if err != nil {
		return nil, err
	}

	requestDuration, err := meter.Int64Histogram(
		"proxy.http.request.duration.ms",
		metric.WithUnit("milliseconds"),
		metric.WithDescription("Duration of requests made to the netbird proxy"),
	)
	if err != nil {
		return nil, err
	}

	backendDuration, err := meter.Int64Histogram(
		"proxy.backend.duration.ms",
		metric.WithUnit("milliseconds"),
		metric.WithDescription("Duration of peer round trip time from the netbird proxy"),
	)
	if err != nil {
		return nil, err
	}

	certificateIssueDuration, err := meter.Int64Histogram(
		"proxy.certificate.issue.duration.ms",
		metric.WithUnit("milliseconds"),
		metric.WithDescription("Duration of ACME certificate issuance"),
	)
	if err != nil {
		return nil, err
	}

	return &Metrics{
		ctx:                      ctx,
		requestsTotal:            requestsTotal,
		activeRequests:           activeRequests,
		configuredDomains:        configuredDomains,
		totalPaths:               totalPaths,
		requestDuration:          requestDuration,
		backendDuration:          backendDuration,
		certificateIssueDuration: certificateIssueDuration,
		mappingPaths:             make(map[string]int),
	}, nil
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

func (m *Metrics) RoundTripper(next http.RoundTripper) http.RoundTripper {
	return roundTripperFunc(func(req *http.Request) (*http.Response, error) {
		start := time.Now()
		res, err := next.RoundTrip(req)
		duration := time.Since(start)

		m.backendDuration.Record(m.ctx, duration.Milliseconds())

		return res, err
	})
}

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

func (m *Metrics) RemoveMapping(mapping proxy.Mapping) {
	m.mappingsMux.Lock()
	defer m.mappingsMux.Unlock()

	oldPathCount, exists := m.mappingPaths[mapping.Host]
	if !exists {
		// Nothing to remove
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
