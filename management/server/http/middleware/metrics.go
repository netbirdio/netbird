package middleware

import (
	"context"
	"fmt"
	log "github.com/sirupsen/logrus"
	"go.opentelemetry.io/otel/exporters/prometheus"
	metric2 "go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/metric/instrument"
	"go.opentelemetry.io/otel/metric/instrument/syncint64"
	"go.opentelemetry.io/otel/sdk/metric"
	"hash/fnv"
	"net/http"
	"reflect"
	"strings"
)

const httpRequestCounterPrefix = "management.http.request.counter"

// WrappedResponseWriter is a wrapper for http.ResponseWriter that allows the
// written HTTP status code to be captured for metrics reporting or logging purposes.
type WrappedResponseWriter struct {
	http.ResponseWriter
	status      int
	wroteHeader bool
}

func WrapResponseWriter(w http.ResponseWriter) *WrappedResponseWriter {
	return &WrappedResponseWriter{ResponseWriter: w}
}

func (rw *WrappedResponseWriter) Status() int {
	return rw.status
}

func (rw *WrappedResponseWriter) WriteHeader(code int) {
	if rw.wroteHeader {
		return
	}

	rw.status = code
	rw.ResponseWriter.WriteHeader(code)
	rw.wroteHeader = true
}

type MetricsMiddleware struct {
	meter                metric2.Meter
	ctx                  context.Context
	httpRequestCounters  map[string]syncint64.Counter
	httpResponseCounters map[string]syncint64.Counter
}

func (m *MetricsMiddleware) AddHttpRequestResponseMeter(endpoint string, method string) error {
	meterKey := fmt.Sprintf("%s%s.%s", httpRequestCounterPrefix, strings.ReplaceAll(endpoint, "/", "."), method)
	httpReqCounter, err := m.meter.SyncInt64().Counter(meterKey, instrument.WithUnit("1"))
	if err != nil {
		return err
	}
	m.httpRequestCounters[meterKey] = httpReqCounter
	respCodes := []int{200, 204, 400, 401, 403, 500, 502, 503}
	for _, code := range respCodes {
		meterKey := fmt.Sprintf("%s%s.%s.%d", httpRequestCounterPrefix,
			strings.ReplaceAll(endpoint, "/", "."), method, code)
		httpRespCounter, err := m.meter.SyncInt64().Counter(meterKey, instrument.WithUnit("1"))
		if err != nil {
			return err
		}
		m.httpResponseCounters[meterKey] = httpRespCounter
	}

	return nil
}

func NewMetricsMiddleware(ctx context.Context) (*MetricsMiddleware, error) {
	exporter, err := prometheus.New()
	if err != nil {
		return nil, err
	}
	pkg := reflect.TypeOf(MetricsMiddleware{}).PkgPath()
	provider := metric.NewMeterProvider(metric.WithReader(exporter))
	meter := provider.Meter(pkg)
	log.Infof("metrics enabled for package %v", pkg)
	return &MetricsMiddleware{
			ctx:                  ctx,
			httpRequestCounters:  map[string]syncint64.Counter{},
			httpResponseCounters: map[string]syncint64.Counter{},
			meter:                meter,
		},
		nil
}

func (m *MetricsMiddleware) Handler(h http.Handler) http.Handler {
	fn := func(rw http.ResponseWriter, r *http.Request) {
		traceID := hash(fmt.Sprintf("%v", r))
		log.Tracef("HTTP request %v: %v %v", traceID, r.Method, r.URL)

		metricKey := fmt.Sprintf("%s%s.%s", httpRequestCounterPrefix, strings.ReplaceAll(r.URL.Path, "/", "."), r.Method)

		if c, ok := m.httpRequestCounters[metricKey]; ok {
			c.Add(m.ctx, 1)
		}

		w := WrapResponseWriter(rw)

		h.ServeHTTP(w, r)

		if !(w.Status() >= 200 || w.Status() < 300) {
			log.Errorf("HTTP response %v: %v %v status %v", traceID, r.Method, r.URL, w.Status())
		} else {
			log.Tracef("HTTP response %v: %v %v status %v", traceID, r.Method, r.URL, w.Status())
		}

		metricKey = fmt.Sprintf("%s%s.%s.%d", httpRequestCounterPrefix,
			strings.ReplaceAll(r.URL.Path, "/", "."), r.Method, w.Status())
		if c, ok := m.httpResponseCounters[metricKey]; ok {
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
