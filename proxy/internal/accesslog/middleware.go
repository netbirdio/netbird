package accesslog

import (
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/rs/xid"

	"github.com/netbirdio/netbird/proxy/internal/proxy"
	"github.com/netbirdio/netbird/proxy/internal/responsewriter"
	"github.com/netbirdio/netbird/proxy/web"
)

// Middleware wraps an HTTP handler to log access entries and resolve client IPs.
func (l *Logger) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Skip logging for internal proxy assets (CSS, JS, etc.)
		if strings.HasPrefix(r.URL.Path, web.PathPrefix+"/") {
			next.ServeHTTP(w, r)
			return
		}

		// Generate request ID early so it can be used by error pages and log correlation.
		requestID := xid.New().String()

		l.logger.Debugf("request: request_id=%s method=%s host=%s path=%s", requestID, r.Method, r.Host, r.URL.Path)

		// Use a response writer wrapper so we can access the status code later.
		sw := &statusWriter{
			PassthroughWriter: responsewriter.New(w),
			status:            http.StatusOK,
		}

		var bytesRead int64
		if r.Body != nil {
			r.Body = &bodyCounter{
				ReadCloser: r.Body,
				bytesRead:  &bytesRead,
			}
		}

		// Resolve the source IP using trusted proxy configuration before passing
		// the request on, as the proxy will modify forwarding headers.
		sourceIp := extractSourceIP(r, l.trustedProxies)

		// Create a mutable struct to capture data from downstream handlers.
		// We pass a pointer in the context - the pointer itself flows down immutably,
		// but the struct it points to can be mutated by inner handlers.
		capturedData := proxy.NewCapturedData(requestID)
		capturedData.SetClientIP(sourceIp)

		ctx := proxy.WithCapturedData(r.Context(), capturedData)

		start := time.Now()
		next.ServeHTTP(sw, r.WithContext(ctx))
		duration := time.Since(start)

		host, _, err := net.SplitHostPort(r.Host)
		if err != nil {
			// Fallback to just using the full host value.
			host = r.Host
		}

		bytesUpload := bytesRead
		bytesDownload := sw.bytesWritten

		entry := logEntry{
			ID:            requestID,
			ServiceID:     capturedData.GetServiceID(),
			AccountID:     capturedData.GetAccountID(),
			Host:          host,
			Path:          r.URL.Path,
			DurationMs:    duration.Milliseconds(),
			Method:        r.Method,
			ResponseCode:  int32(sw.status),
			SourceIP:      sourceIp,
			AuthMechanism: capturedData.GetAuthMethod(),
			UserID:        capturedData.GetUserID(),
			AuthSuccess:   sw.status != http.StatusUnauthorized && sw.status != http.StatusForbidden,
			BytesUpload:   bytesUpload,
			BytesDownload: bytesDownload,
			Protocol:      ProtocolHTTP,
			Metadata:      capturedData.GetMetadata(),
		}
		l.logger.Debugf("response: request_id=%s method=%s host=%s path=%s status=%d duration=%dms source=%s origin=%s service=%s account=%s",
			requestID, r.Method, host, r.URL.Path, sw.status, duration.Milliseconds(), sourceIp, capturedData.GetOrigin(), capturedData.GetServiceID(), capturedData.GetAccountID())

		l.log(entry)

		// Track usage for cost monitoring (upload + download) by domain
		l.trackUsage(host, bytesUpload+bytesDownload)
	})
}
