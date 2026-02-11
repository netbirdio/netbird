package proxy

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	nbgrpc "github.com/netbirdio/netbird/management/internals/shared/grpc"
)

func TestAuthCallbackHandler_RateLimiting(t *testing.T) {
	handler := NewAuthCallbackHandler(&nbgrpc.ProxyServiceServer{})
	require.NotNil(t, handler.rateLimiter, "Rate limiter should be initialized")

	req := httptest.NewRequest(http.MethodGet, "/callback?state=test&code=test", nil)
	req.RemoteAddr = "192.168.1.100:12345"

	t.Run("allows requests under limit", func(t *testing.T) {
		for i := 0; i < 15; i++ {
			allowed := handler.rateLimiter.Allow("192.168.1.100")
			assert.True(t, allowed, "Request %d should be allowed", i+1)
		}
	})

	t.Run("blocks requests over limit", func(t *testing.T) {
		handler.rateLimiter.Reset("192.168.1.200")

		for i := 0; i < 15; i++ {
			handler.rateLimiter.Allow("192.168.1.200")
		}

		allowed := handler.rateLimiter.Allow("192.168.1.200")
		assert.False(t, allowed, "Request over limit should be blocked")
	})

	t.Run("different IPs have separate limits", func(t *testing.T) {
		ip1 := "192.168.1.201"
		ip2 := "192.168.1.202"

		handler.rateLimiter.Reset(ip1)
		handler.rateLimiter.Reset(ip2)

		for i := 0; i < 15; i++ {
			handler.rateLimiter.Allow(ip1)
		}

		assert.False(t, handler.rateLimiter.Allow(ip1), "IP1 should be blocked")

		assert.True(t, handler.rateLimiter.Allow(ip2), "IP2 should be allowed")
	})
}

func TestAuthCallbackHandler_RateLimitInHandleCallback(t *testing.T) {
	handler := NewAuthCallbackHandler(&nbgrpc.ProxyServiceServer{})
	testIP := "10.0.0.50"

	handler.rateLimiter.Reset(testIP)

	t.Run("returns 429 when rate limited", func(t *testing.T) {
		for i := 0; i < 15; i++ {
			handler.rateLimiter.Allow(testIP)
		}

		req := httptest.NewRequest(http.MethodGet, "/callback?state=test&code=test", nil)
		req.RemoteAddr = testIP + ":12345"

		rr := httptest.NewRecorder()
		handler.handleCallback(rr, req)

		assert.Equal(t, http.StatusTooManyRequests, rr.Code, "Should return 429 status code")
		assert.Contains(t, rr.Body.String(), "Too many requests", "Should contain rate limit message")
	})
}

func TestGetClientIP(t *testing.T) {
	tests := []struct {
		name          string
		remoteAddr    string
		xForwardedFor string
		xRealIP       string
		expectedIP    string
	}{
		{
			name:       "extract from RemoteAddr",
			remoteAddr: "192.168.1.100:12345",
			expectedIP: "192.168.1.100",
		},
		{
			name:          "extract from X-Forwarded-For single IP",
			remoteAddr:    "10.0.0.1:54321",
			xForwardedFor: "203.0.113.195",
			expectedIP:    "203.0.113.195",
		},
		{
			name:          "extract from X-Forwarded-For multiple IPs",
			remoteAddr:    "10.0.0.1:54321",
			xForwardedFor: "203.0.113.195, 70.41.3.18, 150.172.238.178",
			expectedIP:    "203.0.113.195",
		},
		{
			name:       "extract from X-Real-IP",
			remoteAddr: "10.0.0.1:54321",
			xRealIP:    "198.51.100.42",
			expectedIP: "198.51.100.42",
		},
		{
			name:          "X-Forwarded-For takes precedence over X-Real-IP",
			remoteAddr:    "10.0.0.1:54321",
			xForwardedFor: "203.0.113.195",
			xRealIP:       "198.51.100.42",
			expectedIP:    "203.0.113.195",
		},
		{
			name:       "handle RemoteAddr without port",
			remoteAddr: "192.168.1.100",
			expectedIP: "192.168.1.100",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/test", nil)
			req.RemoteAddr = tt.remoteAddr

			if tt.xForwardedFor != "" {
				req.Header.Set("X-Forwarded-For", tt.xForwardedFor)
			}
			if tt.xRealIP != "" {
				req.Header.Set("X-Real-IP", tt.xRealIP)
			}

			ip := getClientIP(req)
			assert.Equal(t, tt.expectedIP, ip, "Extracted IP should match expected")
		})
	}
}

func TestAuthCallbackHandler_RateLimiterConfiguration(t *testing.T) {
	handler := NewAuthCallbackHandler(&nbgrpc.ProxyServiceServer{})

	require.NotNil(t, handler.rateLimiter, "Rate limiter should be initialized")

	testIP := "192.168.1.250"
	handler.rateLimiter.Reset(testIP)

	for i := 0; i < 15; i++ {
		allowed := handler.rateLimiter.Allow(testIP)
		assert.True(t, allowed, "Should allow request %d within burst limit", i+1)
	}

	allowed := handler.rateLimiter.Allow(testIP)
	assert.False(t, allowed, "Should block request that exceeds burst limit")
}
