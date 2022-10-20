package middleware

import (
	"context"
	"fmt"
	log "github.com/sirupsen/logrus"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/prometheus"
	"go.opentelemetry.io/otel/metric/instrument"
	"go.opentelemetry.io/otel/metric/instrument/syncint64"
	"go.opentelemetry.io/otel/sdk/metric"
	"hash/fnv"
	"net/http"
	"reflect"
)

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
	httpRequestCounter  syncint64.Counter
	httpResponseCounter syncint64.Counter
	ctx                 context.Context
}

func NewMetricsMiddleware(ctx context.Context) (*MetricsMiddleware, error) {
	exporter, err := prometheus.New()
	if err != nil {
		return nil, err
	}
	pkg := reflect.TypeOf(MetricsMiddleware{}).PkgPath()
	provider := metric.NewMeterProvider(metric.WithReader(exporter))
	meter := provider.Meter(pkg)
	httpRequestCounter, err := meter.SyncInt64().Counter("management.http.request.counter", instrument.WithUnit("1"))
	if err != nil {
		return nil, err
	}
	httpResponseCounter, err := meter.SyncInt64().Counter("management.http.response.counter", instrument.WithUnit("1"))
	if err != nil {
		return nil, err
	}
	log.Infof("metrics enabled for package %v", pkg)
	return &MetricsMiddleware{
			httpRequestCounter:  httpRequestCounter,
			httpResponseCounter: httpResponseCounter,
			ctx:                 ctx},
		nil
}

func (m *MetricsMiddleware) Handler(h http.Handler) http.Handler {
	fn := func(rw http.ResponseWriter, r *http.Request) {
		traceID := hash(fmt.Sprintf("%v", r))
		log.Tracef("HTTP request %v: %v %v", traceID, r.Method, r.URL)
		m.httpRequestCounter.Add(m.ctx, 1,
			attribute.String("method", r.Method),
			attribute.String("endpoint", r.URL.Path))
		w := WrapResponseWriter(rw)

		h.ServeHTTP(w, r)

		log.Tracef("HTTP response %v: %v %v status %v", traceID, r.Method, r.URL, w.Status())
		m.httpResponseCounter.Add(m.ctx, 1,
			attribute.String("method", r.Method),
			attribute.Int("status", w.Status()),
			attribute.String("endpoint", r.URL.Path))
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
