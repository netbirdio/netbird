package accesslog

import (
	"net"
	"net/http"
	"time"

	"github.com/rs/xid"

	"github.com/netbirdio/netbird/proxy/internal/auth"
	"github.com/netbirdio/netbird/proxy/internal/proxy"
)

func (l *Logger) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Use a response writer wrapper so we can access the status code later.
		sw := &statusWriter{
			w:      w,
			status: http.StatusOK, // Default status is OK unless otherwise modified.
		}

		// Get the source IP before passing the request on as the proxy will modify
		// headers that we wish to use to gather that information on the request.
		sourceIp := extractSourceIP(r)

		// Create a mutable struct to capture data from downstream handlers.
		// We pass a pointer in the context - the pointer itself flows down immutably,
		// but the struct it points to can be mutated by inner handlers.
		capturedData := &proxy.CapturedData{}
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
			ID:            xid.New().String(),
			ServiceId:     capturedData.GetServiceId(),
			AccountID:     string(capturedData.GetAccountId()),
			Host:          host,
			Path:          r.URL.Path,
			DurationMs:    duration.Milliseconds(),
			Method:        r.Method,
			ResponseCode:  int32(sw.status),
			SourceIp:      sourceIp,
			AuthMechanism: auth.MethodFromContext(r.Context()).String(),
			UserId:        auth.UserFromContext(r.Context()),
			AuthSuccess:   sw.status != http.StatusUnauthorized && sw.status != http.StatusForbidden,
		}
		l.log(r.Context(), entry)
	})
}
