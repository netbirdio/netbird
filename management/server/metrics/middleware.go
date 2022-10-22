package metrics

import (
	"context"
	"fmt"
	log "github.com/sirupsen/logrus"
	"go.opentelemetry.io/otel/metric/instrument"
	"go.opentelemetry.io/otel/metric/instrument/syncint64"
	"hash/fnv"
	"net/http"
	"strings"
)

const (
	httpRequestCounterPrefix  = "management.http.request.counter"
	httpResponseCounterPrefix = "management.http.response.counter"
)

// WrappedResponseWriter is a wrapper for http.ResponseWriter that allows the
// written HTTP status code to be captured for metrics reporting or logging purposes.
type WrappedResponseWriter struct {
	http.ResponseWriter
	status      int
	wroteHeader bool
}

// WrapResponseWriter wraps original http.ResponseWriter
func WrapResponseWriter(w http.ResponseWriter) *WrappedResponseWriter {
	return &WrappedResponseWriter{ResponseWriter: w}
}

// Status returns response status
func (rw *WrappedResponseWriter) Status() int {
	return rw.status
}

// WriteHeader wraps http.ResponseWriter.WriteHeader method
func (rw *WrappedResponseWriter) WriteHeader(code int) {
	if rw.wroteHeader {
		return
	}

	rw.status = code
	rw.ResponseWriter.WriteHeader(code)
	rw.wroteHeader = true
}

// MetricsMiddleware handler used to collect metrics of every request/response coming to the API.
// Also adds request tracing (logging).
type MetricsMiddleware struct {
	appMetrics *AppMetrics
	ctx        context.Context
	// endpoint & method
	httpRequestCounters map[string]syncint64.Counter
	// endpoint & method & status code
	httpResponseCounters map[string]syncint64.Counter
	// all HTTP requests
	totalHTTPRequestsCounter syncint64.Counter
	// all HTTP responses
	totalHTTPResponseCounter syncint64.Counter
	// all HTTP responses by status code
	totalHTTPResponseCodeCounters map[int]syncint64.Counter
}

// AddHTTPRequestResponseCounter adds a new meter for an HTTP endpoint and Method (GET, POST, etc)
// Creates one request counter and multiple response counters (one per http response status code).
func (m *MetricsMiddleware) AddHTTPRequestResponseCounter(endpoint string, method string) error {
	meterKey := getRequestCounterKey(endpoint, method)
	httpReqCounter, err := m.appMetrics.Meter.SyncInt64().Counter(meterKey, instrument.WithUnit("1"))
	if err != nil {
		return err
	}
	m.httpRequestCounters[meterKey] = httpReqCounter
	respCodes := []int{200, 204, 400, 401, 403, 404, 500, 502, 503}
	for _, code := range respCodes {
		meterKey = getResponseCounterKey(endpoint, method, code)
		httpRespCounter, err := m.appMetrics.Meter.SyncInt64().Counter(meterKey, instrument.WithUnit("1"))
		if err != nil {
			return err
		}
		m.httpResponseCounters[meterKey] = httpRespCounter

		meterKey = fmt.Sprintf("%s_%d_total", httpResponseCounterPrefix, code)
		totalHTTPResponseCodeCounter, err := m.appMetrics.Meter.SyncInt64().Counter(meterKey, instrument.WithUnit("1"))
		if err != nil {
			return err
		}
		m.totalHTTPResponseCodeCounters[code] = totalHTTPResponseCodeCounter
	}

	return nil
}

// NewMetricsMiddleware creates a new MetricsMiddleware
func NewMetricsMiddleware(ctx context.Context, appMetrics *AppMetrics) (*MetricsMiddleware, error) {

	totalHTTPRequestsCounter, err := appMetrics.Meter.SyncInt64().Counter(
		fmt.Sprintf("%s_total", httpRequestCounterPrefix),
		instrument.WithUnit("1"))
	if err != nil {
		return nil, err
	}
	totalHTTPResponseCounter, err := appMetrics.Meter.SyncInt64().Counter(
		fmt.Sprintf("%s_total", httpResponseCounterPrefix),
		instrument.WithUnit("1"))
	if err != nil {
		return nil, err
	}
	return &MetricsMiddleware{
			ctx:                           ctx,
			httpRequestCounters:           map[string]syncint64.Counter{},
			httpResponseCounters:          map[string]syncint64.Counter{},
			totalHTTPResponseCodeCounters: map[int]syncint64.Counter{},
			appMetrics:                    appMetrics,
			totalHTTPRequestsCounter:      totalHTTPRequestsCounter,
			totalHTTPResponseCounter:      totalHTTPResponseCounter,
		},
		nil
}

func getRequestCounterKey(endpoint, method string) string {
	return fmt.Sprintf("%s%s_%s", httpRequestCounterPrefix,
		strings.ReplaceAll(endpoint, "/", "_"), method)
}

func getResponseCounterKey(endpoint, method string, status int) string {
	return fmt.Sprintf("%s%s_%s_%d", httpResponseCounterPrefix,
		strings.ReplaceAll(endpoint, "/", "_"), method, status)
}

// Handler logs every request and response and adds the, to metrics.
func (m *MetricsMiddleware) Handler(h http.Handler) http.Handler {
	fn := func(rw http.ResponseWriter, r *http.Request) {
		traceID := hash(fmt.Sprintf("%v", r))
		log.Tracef("HTTP request %v: %v %v", traceID, r.Method, r.URL)

		metricKey := getRequestCounterKey(r.URL.Path, r.Method)

		if c, ok := m.httpRequestCounters[metricKey]; ok {
			c.Add(m.ctx, 1)
		}
		m.totalHTTPRequestsCounter.Add(m.ctx, 1)

		w := WrapResponseWriter(rw)

		h.ServeHTTP(w, r)

		if w.Status() > 399 {
			log.Errorf("HTTP response %v: %v %v status %v", traceID, r.Method, r.URL, w.Status())
		} else {
			log.Tracef("HTTP response %v: %v %v status %v", traceID, r.Method, r.URL, w.Status())
		}

		metricKey = getResponseCounterKey(r.URL.Path, r.Method, w.Status())
		if c, ok := m.httpResponseCounters[metricKey]; ok {
			c.Add(m.ctx, 1)
		}

		m.totalHTTPResponseCounter.Add(m.ctx, 1)
		if c, ok := m.totalHTTPResponseCodeCounters[w.Status()]; ok {
			c.Add(m.ctx, 1)
		}
	}

	return http.HandlerFunc(fn)
}

func hash(s string) uint32 {
	h := fnv.New32a()
	_, err := h.Write([]byte(s))
	if err != nil {
		panic(err)
	}
	return h.Sum32()
}
