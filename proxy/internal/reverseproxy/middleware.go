package reverseproxy

import (
	"net/http"
	"strings"
	"time"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	log "github.com/sirupsen/logrus"
)

// RequestDataCallback is called for each request that passes through the proxy
type RequestDataCallback func(data *RequestData)

// RequestData contains metadata about a proxied request
type RequestData struct {
	ServiceID    string
	Host         string
	Path         string
	DurationMs   int64
	Method       string
	ResponseCode int32
	SourceIP     string
}

// MetricsMiddleware wraps a handler to capture request metrics
type MetricsMiddleware struct {
	Next      caddyhttp.Handler
	ServiceID string
	Callback  RequestDataCallback
}

// ServeHTTP implements caddyhttp.MiddlewareHandler
func (m *MetricsMiddleware) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	// Record start time
	startTime := time.Now()

	// Wrap the response writer to capture status code
	wrappedWriter := &responseWriterWrapper{
		ResponseWriter: w,
		statusCode:     http.StatusOK, // Default to 200
	}

	// Call the next handler (Caddy's reverse proxy)
	err := next.ServeHTTP(wrappedWriter, r)

	// Calculate duration
	duration := time.Since(startTime)

	// Extract source IP (handle X-Forwarded-For or direct connection)
	sourceIP := extractSourceIP(r)

	// Create request data
	data := &RequestData{
		ServiceID:    m.ServiceID,
		Path:         r.URL.Path,
		DurationMs:   duration.Milliseconds(),
		Method:       r.Method,
		ResponseCode: int32(wrappedWriter.statusCode),
		SourceIP:     sourceIP,
	}

	// Call callback if set
	if m.Callback != nil {
		go func() {
			// Run callback in goroutine to avoid blocking response
			m.Callback(data)
		}()
	}

	log.WithFields(log.Fields{
		"service_id":  data.ServiceID,
		"method":      data.Method,
		"path":        data.Path,
		"status":      data.ResponseCode,
		"duration_ms": data.DurationMs,
		"source_ip":   data.SourceIP,
	}).Debug("Request proxied")

	return err
}

// responseWriterWrapper wraps http.ResponseWriter to capture status code
type responseWriterWrapper struct {
	http.ResponseWriter
	statusCode int
	written    bool
}

// WriteHeader captures the status code
func (w *responseWriterWrapper) WriteHeader(statusCode int) {
	if !w.written {
		w.statusCode = statusCode
		w.written = true
	}
	w.ResponseWriter.WriteHeader(statusCode)
}

// Write ensures we capture status if WriteHeader wasn't called explicitly
func (w *responseWriterWrapper) Write(b []byte) (int, error) {
	if !w.written {
		w.written = true
		// Status code defaults to 200 if not explicitly set
	}
	return w.ResponseWriter.Write(b)
}

// extractSourceIP extracts the real client IP from the request
func extractSourceIP(r *http.Request) string {
	// Check X-Forwarded-For header first (if behind a proxy)
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		// X-Forwarded-For can be a comma-separated list, take the first one
		parts := strings.Split(xff, ",")
		if len(parts) > 0 {
			return strings.TrimSpace(parts[0])
		}
	}

	// Check X-Real-IP header
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}

	// Fall back to RemoteAddr
	// RemoteAddr is in format "IP:port", so we need to strip the port
	if idx := strings.LastIndex(r.RemoteAddr, ":"); idx != -1 {
		return r.RemoteAddr[:idx]
	}

	return r.RemoteAddr
}
