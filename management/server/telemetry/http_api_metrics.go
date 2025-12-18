package telemetry

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gorilla/mux"
	"github.com/rs/xid"
	log "github.com/sirupsen/logrus"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"

	"github.com/netbirdio/netbird/formatter/hook"
	nbContext "github.com/netbirdio/netbird/management/server/context"
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
	ctx context.Context
	// all HTTP requests by endpoint & method
	httpRequestCounter metric.Int64Counter
	// all HTTP responses by endpoint & method & status code
	httpResponseCounter metric.Int64Counter
	// all HTTP requests
	totalHTTPRequestsCounter metric.Int64Counter
	// all HTTP responses
	totalHTTPResponseCounter metric.Int64Counter
	// all HTTP responses by status code
	totalHTTPResponseCodeCounter metric.Int64Counter
	// all HTTP requests durations by endpoint and method
	httpRequestDuration metric.Int64Histogram
	// all HTTP requests durations
	totalHTTPRequestDuration metric.Int64Histogram
}

// NewMetricsMiddleware creates a new HTTPMiddleware
func NewMetricsMiddleware(ctx context.Context, meter metric.Meter) (*HTTPMiddleware, error) {
	httpRequestCounter, err := meter.Int64Counter(httpRequestCounterPrefix,
		metric.WithUnit("1"),
		metric.WithDescription("Number of incoming HTTP requests by endpoint and method"),
	)
	if err != nil {
		return nil, err
	}

	httpResponseCounter, err := meter.Int64Counter(httpResponseCounterPrefix,
		metric.WithUnit("1"),
		metric.WithDescription("Number of outgoing HTTP responses by endpoint, method and returned status code"),
	)
	if err != nil {
		return nil, err
	}

	totalHTTPRequestsCounter, err := meter.Int64Counter(fmt.Sprintf("%s.total", httpRequestCounterPrefix),
		metric.WithUnit("1"),
		metric.WithDescription("Number of incoming HTTP requests"),
	)
	if err != nil {
		return nil, err
	}

	totalHTTPResponseCounter, err := meter.Int64Counter(fmt.Sprintf("%s.total", httpResponseCounterPrefix),
		metric.WithUnit("1"),
		metric.WithDescription("Number of outgoing HTTP responses"),
	)
	if err != nil {
		return nil, err
	}

	totalHTTPResponseCodeCounter, err := meter.Int64Counter(fmt.Sprintf("%s.code.total", httpResponseCounterPrefix),
		metric.WithUnit("1"),
		metric.WithDescription("Number of outgoing HTTP responses by status code"),
	)
	if err != nil {
		return nil, err
	}

	httpRequestDuration, err := meter.Int64Histogram(httpRequestDurationPrefix,
		metric.WithUnit("milliseconds"),
		metric.WithDescription("Duration of incoming HTTP requests by endpoint and method"),
	)
	if err != nil {
		return nil, err
	}

	totalHTTPRequestDuration, err := meter.Int64Histogram(fmt.Sprintf("%s.total", httpRequestDurationPrefix),
		metric.WithUnit("milliseconds"),
		metric.WithDescription("Duration of incoming HTTP requests"),
	)
	if err != nil {
		return nil, err
	}

	return &HTTPMiddleware{
			ctx:                          ctx,
			httpRequestCounter:           httpRequestCounter,
			httpResponseCounter:          httpResponseCounter,
			httpRequestDuration:          httpRequestDuration,
			totalHTTPResponseCodeCounter: totalHTTPResponseCodeCounter,
			totalHTTPRequestsCounter:     totalHTTPRequestsCounter,
			totalHTTPResponseCounter:     totalHTTPResponseCounter,
			totalHTTPRequestDuration:     totalHTTPRequestDuration,
		},
		nil
}

func replaceEndpointChars(endpoint string) string {
	endpoint = strings.ReplaceAll(endpoint, "{", "")
	endpoint = strings.ReplaceAll(endpoint, "}", "")
	return endpoint
}

func getEndpointMetricAttr(r *http.Request) string {
	var endpoint string
	route := mux.CurrentRoute(r)
	if route != nil {
		pathTmpl, err := route.GetPathTemplate()
		if err == nil {
			endpoint = replaceEndpointChars(pathTmpl)
		}
	}
	return endpoint
}

// Handler logs every request and response and adds the, to metrics.
func (m *HTTPMiddleware) Handler(h http.Handler) http.Handler {
	fn := func(rw http.ResponseWriter, r *http.Request) {
		reqStart := time.Now()

		//nolint
		ctx := context.WithValue(r.Context(), hook.ExecutionContextKey, hook.HTTPSource)

		reqID := xid.New().String()
		//nolint
		ctx = context.WithValue(ctx, nbContext.RequestIDKey, reqID)

		log.WithContext(ctx).Tracef("HTTP request %v: %v %v", reqID, r.Method, r.URL)

		endpointAttr := attribute.String("endpoint", getEndpointMetricAttr(r))
		methodAttr := attribute.String("method", r.Method)

		m.httpRequestCounter.Add(m.ctx, 1, metric.WithAttributes(endpointAttr, methodAttr))
		m.totalHTTPRequestsCounter.Add(m.ctx, 1)

		w := WrapResponseWriter(rw)

		h.ServeHTTP(w, r.WithContext(ctx))

		userAuth, err := nbContext.GetUserAuthFromContext(r.Context())
		if err == nil {
			if userAuth.AccountId != "" {
				//nolint
				ctx = context.WithValue(ctx, nbContext.AccountIDKey, userAuth.AccountId)
			}
			if userAuth.UserId != "" {
				//nolint
				ctx = context.WithValue(ctx, nbContext.UserIDKey, userAuth.UserId)
			}
		}

		if w.Status() > 399 {
			log.WithContext(ctx).Errorf("HTTP response %v: %v %v status %v", reqID, r.Method, r.URL, w.Status())
		} else {
			log.WithContext(ctx).Tracef("HTTP response %v: %v %v status %v", reqID, r.Method, r.URL, w.Status())
		}

		statusCodeAttr := attribute.Int("code", w.Status())

		m.httpResponseCounter.Add(m.ctx, 1, metric.WithAttributes(endpointAttr, methodAttr, statusCodeAttr))
		m.totalHTTPResponseCounter.Add(m.ctx, 1)
		m.totalHTTPResponseCodeCounter.Add(m.ctx, 1, metric.WithAttributes(statusCodeAttr))

		reqTook := time.Since(reqStart)
		m.httpRequestDuration.Record(m.ctx, reqTook.Milliseconds(), metric.WithAttributes(endpointAttr, methodAttr))
		log.WithContext(ctx).Debugf("request %s %s took %d ms and finished with status %d", r.Method, r.URL.Path, reqTook.Milliseconds(), w.Status())

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
