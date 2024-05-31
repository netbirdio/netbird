package telemetry

import (
	"context"
	"fmt"
	"hash/fnv"
	"net/http"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

const (
	httpRequestCounterPrefix  = "management.http.request.counter"
	httpResponseCounterPrefix = "management.http.response.counter"
	httpRequestDurationPrefix = "management.http.request.duration.ms"
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
	httpRequestCounters map[string]metric.Int64Counter
	// all HTTP responses by endpoint & method & status code
	httpResponseCounters map[string]metric.Int64Counter
	// all HTTP requests
	totalHTTPRequestsCounter metric.Int64Counter
	// all HTTP responses
	totalHTTPResponseCounter metric.Int64Counter
	// all HTTP responses by status code
	totalHTTPResponseCodeCounters map[int]metric.Int64Counter
	// all HTTP requests durations by endpoint and method
	httpRequestDurations map[string]metric.Int64Histogram
	// all HTTP requests durations
	totalHTTPRequestDuration metric.Int64Histogram
}

// NewMetricsMiddleware creates a new HTTPMiddleware
func NewMetricsMiddleware(ctx context.Context, meter metric.Meter) (*HTTPMiddleware, error) {
	totalHTTPRequestsCounter, err := meter.Int64Counter(fmt.Sprintf("%s_total", httpRequestCounterPrefix), metric.WithUnit("1"))
	if err != nil {
		return nil, err
	}

	totalHTTPResponseCounter, err := meter.Int64Counter(fmt.Sprintf("%s_total", httpResponseCounterPrefix), metric.WithUnit("1"))
	if err != nil {
		return nil, err
	}

	totalHTTPRequestDuration, err := meter.Int64Histogram(fmt.Sprintf("%s_total", httpRequestDurationPrefix), metric.WithUnit("milliseconds"))
	if err != nil {
		return nil, err
	}

	return &HTTPMiddleware{
			ctx:                           ctx,
			httpRequestCounters:           map[string]metric.Int64Counter{},
			httpResponseCounters:          map[string]metric.Int64Counter{},
			httpRequestDurations:          map[string]metric.Int64Histogram{},
			totalHTTPResponseCodeCounters: map[int]metric.Int64Counter{},
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
	httpReqCounter, err := m.meter.Int64Counter(meterKey, metric.WithUnit("1"))
	if err != nil {
		return err
	}
	m.httpRequestCounters[meterKey] = httpReqCounter

	durationKey := getRequestDurationKey(endpoint, method)
	requestDuration, err := m.meter.Int64Histogram(durationKey, metric.WithUnit("milliseconds"))
	if err != nil {
		return err
	}
	m.httpRequestDurations[durationKey] = requestDuration

	respCodes := []int{200, 204, 400, 401, 403, 404, 500, 502, 503}
	for _, code := range respCodes {
		meterKey = getResponseCounterKey(endpoint, method, code)
		httpRespCounter, err := m.meter.Int64Counter(meterKey, metric.WithUnit("1"))
		if err != nil {
			return err
		}
		m.httpResponseCounters[meterKey] = httpRespCounter

		meterKey = fmt.Sprintf("%s_%d_total", httpResponseCounterPrefix, code)
		totalHTTPResponseCodeCounter, err := m.meter.Int64Counter(meterKey, metric.WithUnit("1"))
		if err != nil {
			return err
		}
		m.totalHTTPResponseCodeCounters[code] = totalHTTPResponseCodeCounter
	}

	return nil
}

func replaceEndpointChars(endpoint string) string {
	endpoint = strings.ReplaceAll(endpoint, "/", "_")
	endpoint = strings.ReplaceAll(endpoint, "{", "")
	endpoint = strings.ReplaceAll(endpoint, "}", "")
	return endpoint
}

func getRequestCounterKey(endpoint, method string) string {
	endpoint = replaceEndpointChars(endpoint)
	return fmt.Sprintf("%s%s_%s", httpRequestCounterPrefix, endpoint, method)
}

func getRequestDurationKey(endpoint, method string) string {
	endpoint = replaceEndpointChars(endpoint)
	return fmt.Sprintf("%s%s_%s", httpRequestDurationPrefix, endpoint, method)
}

func getResponseCounterKey(endpoint, method string, status int) string {
	endpoint = replaceEndpointChars(endpoint)
	return fmt.Sprintf("%s%s_%s_%d", httpResponseCounterPrefix, endpoint, method, status)
}

// Handler logs every request and response and adds the, to metrics.
func (m *HTTPMiddleware) Handler(h http.Handler) http.Handler {
	fn := func(rw http.ResponseWriter, r *http.Request) {
		reqStart := time.Now()
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
		log.Debugf("request %s %s took %d ms and finished with status %d", r.Method, r.URL.Path, reqTook.Milliseconds(), w.Status())

		if w.Status() == 200 && (r.Method == http.MethodPut || r.Method == http.MethodPost || r.Method == http.MethodDelete) {
			opts := metric.WithAttributeSet(attribute.NewSet(attribute.String("type", "write")))
			m.totalHTTPRequestDuration.Record(m.ctx, reqTook.Milliseconds(), opts)
		} else {
			opts := metric.WithAttributeSet(attribute.NewSet(attribute.String("type", "read")))
			m.totalHTTPRequestDuration.Record(m.ctx, reqTook.Milliseconds(), opts)
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
