package accesslog

import (
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/rs/xid"

	"github.com/netbirdio/netbird/proxy/internal/proxy"
	"github.com/netbirdio/netbird/proxy/web"
)

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
			w:      w,
			status: http.StatusOK,
		}

		// Resolve the source IP using trusted proxy configuration before passing
		// the request on, as the proxy will modify forwarding headers.
		sourceIp := extractSourceIP(r, l.trustedProxies)

		// Create a mutable struct to capture data from downstream handlers.
		// We pass a pointer in the context - the pointer itself flows down immutably,
		// but the struct it points to can be mutated by inner handlers.
		capturedData := &proxy.CapturedData{RequestID: requestID}
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

		entry := logEntry{
			ID:            requestID,
			ServiceId:     capturedData.GetServiceId(),
			AccountID:     string(capturedData.GetAccountId()),
			Host:          host,
			Path:          r.URL.Path,
			DurationMs:    duration.Milliseconds(),
			Method:        r.Method,
			ResponseCode:  int32(sw.status),
			SourceIp:      sourceIp,
			AuthMechanism: capturedData.GetAuthMethod(),
			UserId:        capturedData.GetUserID(),
			AuthSuccess:   sw.status != http.StatusUnauthorized && sw.status != http.StatusForbidden,
		}
		l.logger.Debugf("response: request_id=%s method=%s host=%s path=%s status=%d duration=%dms source=%s origin=%s service=%s account=%s",
			requestID, r.Method, host, r.URL.Path, sw.status, duration.Milliseconds(), sourceIp, capturedData.GetOrigin(), capturedData.GetServiceId(), capturedData.GetAccountId())

		l.log(r.Context(), entry)
	})
}
