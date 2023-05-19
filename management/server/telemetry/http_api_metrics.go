package telemetry

import (
	"context"
	"fmt"
	"hash/fnv"
	"net/http"
	"strings"
	time "time"

	log "github.com/sirupsen/logrus"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/metric/instrument"
	"go.opentelemetry.io/otel/metric/instrument/syncint64"
)

const (
	httpRequestCounterPrefix       = "management.http.request.counter"
	httpResponseCounterPrefix      = "management.http.response.counter"
	httpRequestDurationPrefix      = "management.http.request.duration.ms"
	httpWriteRequestDurationPrefix = "management.http.request.write.duration.ms"
	httpReadRequestDurationPrefix  = "management.http.request.read.duration.ms"
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

// HTTPMiddleware handler used to collect metrics of every request/response coming to the API.
// Also adds request tracing (logging).
type HTTPMiddleware struct {
	meter metric.Meter
	ctx   context.Context
	// all HTTP requests by endpoint & method
	httpRequestCounters map[string]syncint64.Counter
	// all HTTP responses by endpoint & method & status code
	httpResponseCounters map[string]syncint64.Counter
	// all HTTP requests
	totalHTTPRequestsCounter syncint64.Counter
	// all HTTP responses
	totalHTTPResponseCounter syncint64.Counter
	// all HTTP responses by status code
	totalHTTPResponseCodeCounters map[int]syncint64.Counter
	// all HTTP requests durations by endpoint and method
	httpRequestDurations map[string]syncint64.Histogram
	// all HTTP requests durations
	totalHTTPRequestDuration syncint64.Histogram
}

// NewMetricsMiddleware creates a new HTTPMiddleware
func NewMetricsMiddleware(ctx context.Context, meter metric.Meter) (*HTTPMiddleware, error) {

	totalHTTPRequestsCounter, err := meter.SyncInt64().Counter(
		fmt.Sprintf("%s_total", httpRequestCounterPrefix),
		instrument.WithUnit("1"))
	if err != nil {
		return nil, err
	}
	totalHTTPResponseCounter, err := meter.SyncInt64().Counter(
		fmt.Sprintf("%s_total", httpResponseCounterPrefix),
		instrument.WithUnit("1"))
	if err != nil {
		return nil, err
	}

	totalHTTPRequestDuration, err := meter.SyncInt64().Histogram(
		fmt.Sprintf("%s_total", httpRequestDurationPrefix),
		instrument.WithUnit("milliseconds"))

	if err != nil {
		return nil, err
	}

	return &HTTPMiddleware{
			ctx:                           ctx,
			httpRequestCounters:           map[string]syncint64.Counter{},
			httpResponseCounters:          map[string]syncint64.Counter{},
			httpRequestDurations:          map[string]syncint64.Histogram{},
			totalHTTPResponseCodeCounters: map[int]syncint64.Counter{},
			meter:                         meter,
			totalHTTPRequestsCounter:      totalHTTPRequestsCounter,
			totalHTTPResponseCounter:      totalHTTPResponseCounter,
			totalHTTPRequestDuration:      totalHTTPRequestDuration,
		},
		nil
}

// AddHTTPRequestResponseCounter adds a new meter for an HTTP defaultEndpoint and Method (GET, POST, etc)
// Creates one request counter and multiple response counters (one per http response status code).
func (m *HTTPMiddleware) AddHTTPRequestResponseCounter(endpoint string, method string) error {
	meterKey := getRequestCounterKey(endpoint, method)
	httpReqCounter, err := m.meter.SyncInt64().Counter(meterKey, instrument.WithUnit("1"))
	if err != nil {
		return err
	}
	m.httpRequestCounters[meterKey] = httpReqCounter
	durationKey := getRequestDurationKey(endpoint, method)
	requestDuration, err := m.meter.SyncInt64().Histogram(durationKey, instrument.WithUnit("milliseconds"))
	if err != nil {
		return err
	}
	m.httpRequestDurations[durationKey] = requestDuration
	respCodes := []int{200, 204, 400, 401, 403, 404, 500, 502, 503}
	for _, code := range respCodes {
		meterKey = getResponseCounterKey(endpoint, method, code)
		httpRespCounter, err := m.meter.SyncInt64().Counter(meterKey, instrument.WithUnit("1"))
		if err != nil {
			return err
		}
		m.httpResponseCounters[meterKey] = httpRespCounter

		meterKey = fmt.Sprintf("%s_%d_total", httpResponseCounterPrefix, code)
		totalHTTPResponseCodeCounter, err := m.meter.SyncInt64().Counter(meterKey, instrument.WithUnit("1"))
		if err != nil {
			return err
		}
		m.totalHTTPResponseCodeCounters[code] = totalHTTPResponseCodeCounter
	}

	return nil
}

func getRequestCounterKey(endpoint, method string) string {
	return fmt.Sprintf("%s%s_%s", httpRequestCounterPrefix,
		strings.ReplaceAll(endpoint, "/", "_"), method)
}

func getRequestDurationKey(endpoint, method string) string {
	return fmt.Sprintf("%s%s_%s", httpRequestDurationPrefix,
		strings.ReplaceAll(endpoint, "/", "_"), method)
}

func getResponseCounterKey(endpoint, method string, status int) string {
	return fmt.Sprintf("%s%s_%s_%d", httpResponseCounterPrefix,
		strings.ReplaceAll(endpoint, "/", "_"), method, status)
}

// Handler logs every request and response and adds the, to metrics.
func (m *HTTPMiddleware) Handler(h http.Handler) http.Handler {
	fn := func(rw http.ResponseWriter, r *http.Request) {
		reqStart := time.Now()
		defer func() {
			tookMs := time.Since(reqStart).Milliseconds()
			m.totalHTTPRequestDuration.Record(m.ctx, tookMs)

			if r.Method == http.MethodPut || r.Method == http.MethodPost || r.Method == http.MethodDelete {
				m.totalHTTPRequestDuration.Record(m.ctx, tookMs, attribute.String("type", "write"))
			} else {
				m.totalHTTPRequestDuration.Record(m.ctx, tookMs, attribute.String("type", "read"))
			}
		}()
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

		durationKey := getRequestDurationKey(r.URL.Path, r.Method)
		reqTook := time.Since(reqStart)
		if c, ok := m.httpRequestDurations[durationKey]; ok {
			c.Record(m.ctx, reqTook.Milliseconds())
		}
		log.Debugf("request %s %s took %d ms", r.Method, r.URL.Path, reqTook.Milliseconds())

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
