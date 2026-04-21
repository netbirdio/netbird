package middleware

import (
	"context"
	"net"
	"net/http"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	log "github.com/sirupsen/logrus"
	"golang.org/x/time/rate"

	"github.com/netbirdio/netbird/shared/management/http/util"
)

const (
	RateLimitingEnabledEnv = "NB_API_RATE_LIMITING_ENABLED"
	RateLimitingBurstEnv   = "NB_API_RATE_LIMITING_BURST"
	RateLimitingRPMEnv     = "NB_API_RATE_LIMITING_RPM"

	defaultAPIRPM   = 6
	defaultAPIBurst = 500
)

// RateLimiterConfig holds configuration for the API rate limiter
type RateLimiterConfig struct {
	// RequestsPerMinute defines the rate at which tokens are replenished
	RequestsPerMinute float64
	// Burst defines the maximum number of requests that can be made in a burst
	Burst int
	// CleanupInterval defines how often to clean up old limiters (how often garbage collection runs)
	CleanupInterval time.Duration
	// LimiterTTL defines how long a limiter should be kept after last use (age threshold for removal)
	LimiterTTL time.Duration
}

// DefaultRateLimiterConfig returns a default configuration
func DefaultRateLimiterConfig() *RateLimiterConfig {
	return &RateLimiterConfig{
		RequestsPerMinute: 100,
		Burst:             120,
		CleanupInterval:   5 * time.Minute,
		LimiterTTL:        10 * time.Minute,
	}
}

func RateLimiterConfigFromEnv() (cfg *RateLimiterConfig, enabled bool) {
	rpm := defaultAPIRPM
	if v := os.Getenv(RateLimitingRPMEnv); v != "" {
		value, err := strconv.Atoi(v)
		if err != nil {
			log.Warnf("parsing %s env var: %v, using default %d", RateLimitingRPMEnv, err, rpm)
		} else {
			rpm = value
		}
	}
	if rpm <= 0 {
		log.Warnf("%s=%d is non-positive, using default %d", RateLimitingRPMEnv, rpm, defaultAPIRPM)
		rpm = defaultAPIRPM
	}

	burst := defaultAPIBurst
	if v := os.Getenv(RateLimitingBurstEnv); v != "" {
		value, err := strconv.Atoi(v)
		if err != nil {
			log.Warnf("parsing %s env var: %v, using default %d", RateLimitingBurstEnv, err, burst)
		} else {
			burst = value
		}
	}
	if burst <= 0 {
		log.Warnf("%s=%d is non-positive, using default %d", RateLimitingBurstEnv, burst, defaultAPIBurst)
		burst = defaultAPIBurst
	}

	return &RateLimiterConfig{
		RequestsPerMinute: float64(rpm),
		Burst:             burst,
		CleanupInterval:   6 * time.Hour,
		LimiterTTL:        24 * time.Hour,
	}, os.Getenv(RateLimitingEnabledEnv) == "true"
}

// limiterEntry holds a rate limiter and its last access time
type limiterEntry struct {
	limiter    *rate.Limiter
	lastAccess time.Time
}

// APIRateLimiter manages rate limiting for API tokens
type APIRateLimiter struct {
	config   *RateLimiterConfig
	limiters map[string]*limiterEntry
	mu       sync.RWMutex
	stopChan chan struct{}
	enabled  atomic.Bool
}

// NewAPIRateLimiter creates a new API rate limiter with the given configuration
func NewAPIRateLimiter(config *RateLimiterConfig) *APIRateLimiter {
	if config == nil {
		config = DefaultRateLimiterConfig()
	}

	rl := &APIRateLimiter{
		config:   config,
		limiters: make(map[string]*limiterEntry),
		stopChan: make(chan struct{}),
	}
	rl.enabled.Store(true)

	go rl.cleanupLoop()

	return rl
}

func (rl *APIRateLimiter) SetEnabled(enabled bool) {
	rl.enabled.Store(enabled)
}

func (rl *APIRateLimiter) Enabled() bool {
	return rl.enabled.Load()
}

func (rl *APIRateLimiter) UpdateConfig(config *RateLimiterConfig) {
	if config == nil {
		return
	}
	if config.RequestsPerMinute <= 0 || config.Burst <= 0 {
		log.Warnf("UpdateConfig: ignoring invalid rpm=%v burst=%d", config.RequestsPerMinute, config.Burst)
		return
	}

	newRPS := rate.Limit(config.RequestsPerMinute / 60.0)
	newBurst := config.Burst

	rl.mu.Lock()
	rl.config.RequestsPerMinute = config.RequestsPerMinute
	rl.config.Burst = newBurst
	snapshot := make([]*rate.Limiter, 0, len(rl.limiters))
	for _, entry := range rl.limiters {
		snapshot = append(snapshot, entry.limiter)
	}
	rl.mu.Unlock()

	for _, l := range snapshot {
		l.SetLimit(newRPS)
		l.SetBurst(newBurst)
	}
}

// Allow checks if a request for the given key (token) is allowed
func (rl *APIRateLimiter) Allow(key string) bool {
	if !rl.enabled.Load() {
		return true
	}
	limiter := rl.getLimiter(key)
	return limiter.Allow()
}

// Wait blocks until the rate limiter allows another request for the given key
// Returns an error if the context is canceled
func (rl *APIRateLimiter) Wait(ctx context.Context, key string) error {
	if !rl.enabled.Load() {
		return nil
	}
	limiter := rl.getLimiter(key)
	return limiter.Wait(ctx)
}

// getLimiter retrieves or creates a rate limiter for the given key
func (rl *APIRateLimiter) getLimiter(key string) *rate.Limiter {
	rl.mu.RLock()
	entry, exists := rl.limiters[key]
	rl.mu.RUnlock()

	if exists {
		rl.mu.Lock()
		entry.lastAccess = time.Now()
		rl.mu.Unlock()
		return entry.limiter
	}

	rl.mu.Lock()
	defer rl.mu.Unlock()

	if entry, exists := rl.limiters[key]; exists {
		entry.lastAccess = time.Now()
		return entry.limiter
	}

	requestsPerSecond := rl.config.RequestsPerMinute / 60.0
	limiter := rate.NewLimiter(rate.Limit(requestsPerSecond), rl.config.Burst)
	rl.limiters[key] = &limiterEntry{
		limiter:    limiter,
		lastAccess: time.Now(),
	}

	return limiter
}

// cleanupLoop periodically removes old limiters that haven't been used recently
func (rl *APIRateLimiter) cleanupLoop() {
	ticker := time.NewTicker(rl.config.CleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			rl.cleanup()
		case <-rl.stopChan:
			return
		}
	}
}

// cleanup removes limiters that haven't been used within the TTL period
func (rl *APIRateLimiter) cleanup() {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	for key, entry := range rl.limiters {
		if now.Sub(entry.lastAccess) > rl.config.LimiterTTL {
			delete(rl.limiters, key)
		}
	}
}

// Stop stops the cleanup goroutine
func (rl *APIRateLimiter) Stop() {
	close(rl.stopChan)
}

// Reset removes the rate limiter for a specific key
func (rl *APIRateLimiter) Reset(key string) {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	delete(rl.limiters, key)
}

// Middleware returns an HTTP middleware that rate limits requests by client IP.
// Returns 429 Too Many Requests if the rate limit is exceeded.
func (rl *APIRateLimiter) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !rl.enabled.Load() {
			next.ServeHTTP(w, r)
			return
		}
		clientIP := getClientIP(r)
		if !rl.Allow(clientIP) {
			util.WriteErrorResponse("rate limit exceeded, please try again later", http.StatusTooManyRequests, w)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// getClientIP extracts the client IP address from the request.
func getClientIP(r *http.Request) string {
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return ip
}
