package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestAPIRateLimiter_Allow(t *testing.T) {
	rl := NewAPIRateLimiter(&RateLimiterConfig{
		RequestsPerMinute: 60, // 1 per second
		Burst:             2,
		CleanupInterval:   time.Minute,
		LimiterTTL:        time.Minute,
	})
	defer rl.Stop()

	// First two requests should be allowed (burst)
	assert.True(t, rl.Allow("test-key"))
	assert.True(t, rl.Allow("test-key"))

	// Third request should be denied (exceeded burst)
	assert.False(t, rl.Allow("test-key"))

	// Different key should be allowed
	assert.True(t, rl.Allow("different-key"))
}

func TestAPIRateLimiter_Middleware(t *testing.T) {
	rl := NewAPIRateLimiter(&RateLimiterConfig{
		RequestsPerMinute: 60, // 1 per second
		Burst:             2,
		CleanupInterval:   time.Minute,
		LimiterTTL:        time.Minute,
	})
	defer rl.Stop()

	// Create a simple handler that returns 200 OK
	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// Wrap with rate limiter middleware
	handler := rl.Middleware(nextHandler)

	// First two requests should pass (burst)
	for i := 0; i < 2; i++ {
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req.RemoteAddr = "192.168.1.1:12345"
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		assert.Equal(t, http.StatusOK, rr.Code, "request %d should be allowed", i+1)
	}

	// Third request should be rate limited
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.RemoteAddr = "192.168.1.1:12345"
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusTooManyRequests, rr.Code)
}

func TestAPIRateLimiter_Middleware_DifferentIPs(t *testing.T) {
	rl := NewAPIRateLimiter(&RateLimiterConfig{
		RequestsPerMinute: 60,
		Burst:             1,
		CleanupInterval:   time.Minute,
		LimiterTTL:        time.Minute,
	})
	defer rl.Stop()

	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := rl.Middleware(nextHandler)

	// Request from first IP
	req1 := httptest.NewRequest(http.MethodGet, "/test", nil)
	req1.RemoteAddr = "192.168.1.1:12345"
	rr1 := httptest.NewRecorder()
	handler.ServeHTTP(rr1, req1)
	assert.Equal(t, http.StatusOK, rr1.Code)

	// Second request from first IP should be rate limited
	req2 := httptest.NewRequest(http.MethodGet, "/test", nil)
	req2.RemoteAddr = "192.168.1.1:12345"
	rr2 := httptest.NewRecorder()
	handler.ServeHTTP(rr2, req2)
	assert.Equal(t, http.StatusTooManyRequests, rr2.Code)

	// Request from different IP should be allowed
	req3 := httptest.NewRequest(http.MethodGet, "/test", nil)
	req3.RemoteAddr = "192.168.1.2:12345"
	rr3 := httptest.NewRecorder()
	handler.ServeHTTP(rr3, req3)
	assert.Equal(t, http.StatusOK, rr3.Code)
}

func TestGetClientIP(t *testing.T) {
	tests := []struct {
		name       string
		remoteAddr string
		expected   string
	}{
		{
			name:       "remote addr with port",
			remoteAddr: "192.168.1.1:12345",
			expected:   "192.168.1.1",
		},
		{
			name:       "remote addr without port",
			remoteAddr: "192.168.1.1",
			expected:   "192.168.1.1",
		},
		{
			name:       "IPv6 with port",
			remoteAddr: "[::1]:12345",
			expected:   "::1",
		},
		{
			name:       "IPv6 without port",
			remoteAddr: "::1",
			expected:   "::1",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/test", nil)
			req.RemoteAddr = tc.remoteAddr
			assert.Equal(t, tc.expected, getClientIP(req))
		})
	}
}

func TestAPIRateLimiter_Reset(t *testing.T) {
	rl := NewAPIRateLimiter(&RateLimiterConfig{
		RequestsPerMinute: 60,
		Burst:             1,
		CleanupInterval:   time.Minute,
		LimiterTTL:        time.Minute,
	})
	defer rl.Stop()

	// Use up the burst
	assert.True(t, rl.Allow("test-key"))
	assert.False(t, rl.Allow("test-key"))

	// Reset the limiter
	rl.Reset("test-key")

	// Should be allowed again
	assert.True(t, rl.Allow("test-key"))
}
