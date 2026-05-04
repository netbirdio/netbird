package middleware

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
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

func TestAPIRateLimiter_SetEnabled(t *testing.T) {
	rl := NewAPIRateLimiter(&RateLimiterConfig{
		RequestsPerMinute: 60,
		Burst:             1,
		CleanupInterval:   time.Minute,
		LimiterTTL:        time.Minute,
	})
	defer rl.Stop()

	assert.True(t, rl.Allow("key"))
	assert.False(t, rl.Allow("key"), "burst exhausted while enabled")

	rl.SetEnabled(false)
	assert.False(t, rl.Enabled())
	for i := 0; i < 5; i++ {
		assert.True(t, rl.Allow("key"), "disabled limiter must always allow")
	}

	rl.SetEnabled(true)
	assert.True(t, rl.Enabled())
	assert.False(t, rl.Allow("key"), "re-enabled limiter retains prior bucket state")
}

func TestAPIRateLimiter_UpdateConfig(t *testing.T) {
	rl := NewAPIRateLimiter(&RateLimiterConfig{
		RequestsPerMinute: 60,
		Burst:             2,
		CleanupInterval:   time.Minute,
		LimiterTTL:        time.Minute,
	})
	defer rl.Stop()

	assert.True(t, rl.Allow("k1"))
	assert.True(t, rl.Allow("k1"))
	assert.False(t, rl.Allow("k1"), "burst=2 exhausted")

	rl.UpdateConfig(&RateLimiterConfig{
		RequestsPerMinute: 60,
		Burst:             10,
		CleanupInterval:   time.Minute,
		LimiterTTL:        time.Minute,
	})

	// New burst applies to existing keys in place; bucket refills up to new burst over time,
	// but importantly newly-added keys use the updated config immediately.
	assert.True(t, rl.Allow("k2"))
	for i := 0; i < 9; i++ {
		assert.True(t, rl.Allow("k2"))
	}
	assert.False(t, rl.Allow("k2"), "new burst=10 exhausted")
}

func TestAPIRateLimiter_UpdateConfig_NilIgnored(t *testing.T) {
	rl := NewAPIRateLimiter(&RateLimiterConfig{
		RequestsPerMinute: 60,
		Burst:             1,
		CleanupInterval:   time.Minute,
		LimiterTTL:        time.Minute,
	})
	defer rl.Stop()

	rl.UpdateConfig(nil) // must not panic or zero the config

	assert.True(t, rl.Allow("k"))
	assert.False(t, rl.Allow("k"))
}

func TestAPIRateLimiter_UpdateConfig_NonPositiveIgnored(t *testing.T) {
	rl := NewAPIRateLimiter(&RateLimiterConfig{
		RequestsPerMinute: 60,
		Burst:             1,
		CleanupInterval:   time.Minute,
		LimiterTTL:        time.Minute,
	})
	defer rl.Stop()

	assert.True(t, rl.Allow("k"))
	assert.False(t, rl.Allow("k"))

	rl.UpdateConfig(&RateLimiterConfig{RequestsPerMinute: 0, Burst: 0, CleanupInterval: time.Minute, LimiterTTL: time.Minute})
	rl.UpdateConfig(&RateLimiterConfig{RequestsPerMinute: -1, Burst: 5, CleanupInterval: time.Minute, LimiterTTL: time.Minute})
	rl.UpdateConfig(&RateLimiterConfig{RequestsPerMinute: 60, Burst: -1, CleanupInterval: time.Minute, LimiterTTL: time.Minute})

	rl.Reset("k")
	assert.True(t, rl.Allow("k"))
	assert.False(t, rl.Allow("k"), "burst should still be 1 — invalid UpdateConfig calls were ignored")
}

func TestAPIRateLimiter_ConcurrentAllowAndUpdate(t *testing.T) {
	rl := NewAPIRateLimiter(&RateLimiterConfig{
		RequestsPerMinute: 600,
		Burst:             10,
		CleanupInterval:   time.Minute,
		LimiterTTL:        time.Minute,
	})
	defer rl.Stop()

	var wg sync.WaitGroup
	stop := make(chan struct{})

	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			key := fmt.Sprintf("k%d", id)
			for {
				select {
				case <-stop:
					return
				default:
					rl.Allow(key)
				}
			}
		}(i)
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 200; i++ {
			select {
			case <-stop:
				return
			default:
				rl.UpdateConfig(&RateLimiterConfig{
					RequestsPerMinute: float64(30 + (i % 90)),
					Burst:             1 + (i % 20),
					CleanupInterval:   time.Minute,
					LimiterTTL:        time.Minute,
				})
				rl.SetEnabled(i%2 == 0)
			}
		}
	}()

	time.Sleep(100 * time.Millisecond)
	close(stop)
	wg.Wait()
}

func TestRateLimiterConfigFromEnv(t *testing.T) {
	t.Setenv(RateLimitingEnabledEnv, "true")
	t.Setenv(RateLimitingRPMEnv, "42")
	t.Setenv(RateLimitingBurstEnv, "7")

	cfg, enabled := RateLimiterConfigFromEnv()
	assert.True(t, enabled)
	assert.Equal(t, float64(42), cfg.RequestsPerMinute)
	assert.Equal(t, 7, cfg.Burst)

	t.Setenv(RateLimitingEnabledEnv, "false")
	_, enabled = RateLimiterConfigFromEnv()
	assert.False(t, enabled)

	t.Setenv(RateLimitingEnabledEnv, "")
	t.Setenv(RateLimitingRPMEnv, "")
	t.Setenv(RateLimitingBurstEnv, "")
	cfg, enabled = RateLimiterConfigFromEnv()
	assert.False(t, enabled)
	assert.Equal(t, float64(defaultAPIRPM), cfg.RequestsPerMinute)
	assert.Equal(t, defaultAPIBurst, cfg.Burst)

	t.Setenv(RateLimitingRPMEnv, "0")
	t.Setenv(RateLimitingBurstEnv, "-5")
	cfg, _ = RateLimiterConfigFromEnv()
	assert.Equal(t, float64(defaultAPIRPM), cfg.RequestsPerMinute, "non-positive rpm must fall back to default")
	assert.Equal(t, defaultAPIBurst, cfg.Burst, "non-positive burst must fall back to default")
}
