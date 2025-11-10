package security

import (
	"context"
	"net/http"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

// RateLimiter implements a token bucket rate limiter
// It supports both IP-based and per-user rate limiting
// and includes protection against rapid resets
//
// Example usage:
//
//	limiter := NewRateLimiter(100, time.Minute, 5*time.Minute)
//	handler := limiter.Middleware(yourHandler)
//
// This will limit each IP to 100 requests per minute,
// with a ban duration of 5 minutes if the limit is exceeded
type RateLimiter struct {
	// Number of requests allowed per window
	maxRequests int

	// Time window for rate limiting (e.g., 1 minute)
	window time.Duration

	// Ban duration after rate limit is exceeded
	banDuration time.Duration

	// Cleanup interval for old entries
	cleanupInterval time.Duration

	// IP-based rate limiting
	ipLimits map[string]*rateLimit

	// User ID based rate limiting (if authenticated)
	userLimits map[string]*rateLimit

	// Banned IPs
	bannedIPs map[string]time.Time

	// Banned users
	bannedUsers map[string]time.Time

	// Mutex for thread safety
	mu sync.RWMutex

	// Context for cleanup goroutine
	ctx        context.Context
	cancelFunc context.CancelFunc

	// Logger
	logger *logrus.Logger
}

type rateLimit struct {
	count     int
	firstSeen time.Time
	lastSeen  time.Time
}

// NewRateLimiter creates a new RateLimiter instance
// maxRequests: maximum number of requests allowed per window
// window: time window for rate limiting (e.g., 1 minute)
// banDuration: duration to ban an IP/user after rate limit is exceeded
// cleanupInterval: how often to clean up old entries (0 = no cleanup)
func NewRateLimiter(maxRequests int, window, banDuration time.Duration) *RateLimiter {
	if maxRequests <= 0 {
		maxRequests = 100 // Default to 100 requests per window
	}

	if window <= 0 {
		window = time.Minute // Default to 1 minute window
	}

	if banDuration <= 0 {
		banDuration = 5 * time.Minute // Default to 5 minute ban
	}

	// Set cleanup interval to 10% of window, but at least 1 second
	cleanupInterval := window / 10
	if cleanupInterval < time.Second {
		cleanupInterval = time.Second
	}

	ctx, cancel := context.WithCancel(context.Background())

	r := &RateLimiter{
		maxRequests:     maxRequests,
		window:         window,
		banDuration:    banDuration,
		cleanupInterval: cleanupInterval,
		ipLimits:       make(map[string]*rateLimit),
		userLimits:     make(map[string]*rateLimit),
		bannedIPs:      make(map[string]time.Time),
		bannedUsers:    make(map[string]time.Time),
		ctx:            ctx,
		cancelFunc:     cancel,
		logger:         logrus.StandardLogger(),
	}

	// Start cleanup goroutine
	if r.cleanupInterval > 0 {
		go r.cleanup()
	}

	return r
}

// cleanup periodically removes old entries from the rate limiter
func (r *RateLimiter) cleanup() {
	ticker := time.NewTicker(r.cleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-r.ctx.Done():
			return
		case <-ticker.C:
			r.cleanupOldEntries()
		}
	}
}

// cleanupOldEntries removes old entries from the rate limiter
func (r *RateLimiter) cleanupOldEntries() {
	r.mu.Lock()
	defer r.mu.Unlock()

	now := time.Now()

	// Clean up old IP rate limits
	for ip, limit := range r.ipLimits {
		if now.Sub(limit.lastSeen) > r.window*2 {
			delete(r.ipLimits, ip)
		}
	}

	// Clean up old user rate limits
	for userID, limit := range r.userLimits {
		if now.Sub(limit.lastSeen) > r.window*2 {
			delete(r.userLimits, userID)
		}
	}

	// Clean up expired bans
	for ip, banTime := range r.bannedIPs {
		if now.Sub(banTime) > r.banDuration {
			delete(r.bannedIPs, ip)
		}
	}

	for userID, banTime := range r.bannedUsers {
		if now.Sub(banTime) > r.banDuration {
			delete(r.bannedUsers, userID)
		}
	}
}

// Allow checks if the request is allowed
// Returns true if the request is allowed, false if rate limited
// If userID is not empty, rate limiting is applied per user instead of per IP
func (r *RateLimiter) Allow(ip, userID string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	now := time.Now()

	// Check if IP is banned
	if banTime, banned := r.bannedIPs[ip]; banned {
		if now.Sub(banTime) < r.banDuration {
			return false
		}
		// Ban expired
		delete(r.bannedIPs, ip)
	}

	// Check if user is banned
	if userID != "" {
		if banTime, banned := r.bannedUsers[userID]; banned {
			if now.Sub(banTime) < r.banDuration {
				return false
			}
			// Ban expired
			delete(r.bannedUsers, userID)
		}
	}

	// Get or create rate limit entry
	var limit *rateLimit
	var ok bool

	if userID != "" {
		// User-based rate limiting
		limit, ok = r.userLimits[userID]
		if !ok {
			limit = &rateLimit{
				firstSeen: now,
				lastSeen:  now,
			}
			r.userLimits[userID] = limit
		}
	} else {
		// IP-based rate limiting
		limit, ok = r.ipLimits[ip]
		if !ok {
			limit = &rateLimit{
				firstSeen: now,
				lastSeen:  now,
			}
			r.ipLimits[ip] = limit
		}
	}

	// Check if window has expired
	if now.Sub(limit.firstSeen) > r.window {
		// Reset counter
		limit.count = 1
		limit.firstSeen = now
		limit.lastSeen = now
		return true
	}

	// Increment counter
	limit.count++
	limit.lastSeen = now

	// Check if rate limit exceeded
	if limit.count > r.maxRequests {
		// Ban the IP/user
		if userID != "" {
			r.bannedUsers[userID] = now
			r.logger.WithFields(logrus.Fields{
				"user_id": userID,
				"count":   limit.count,
			}).Warn("User rate limit exceeded, banned")
		} else {
			r.bannedIPs[ip] = now
			r.logger.WithFields(logrus.Fields{
				"ip":    ip,
				"count": limit.count,
			}).Warn("IP rate limit exceeded, banned")
		}
		return false
	}

	return true
}

// Middleware returns an HTTP middleware that enforces rate limiting
func (r *RateLimiter) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		// Get client IP
		ip := getClientIP(req)

		// Get user ID from context if available
		var userID string
		if user := req.Context().Value("user"); user != nil {
			if u, ok := user.(map[string]interface{}); ok {
				if id, ok := u["sub"].(string); ok {
					userID = id
				}
			}
		}

		// Check rate limit
		if !r.Allow(ip, userID) {
			http.Error(w, "Too many requests", http.StatusTooManyRequests)
			return
		}

		// Call the next handler
		next.ServeHTTP(w, req)
	})
}

// getClientIP extracts the client IP from the request
func getClientIP(r *http.Request) string {
	// Check for X-Forwarded-For header first
	if forwardedFor := r.Header.Get("X-Forwarded-For"); forwardedFor != "" {
		// X-Forwarded-For can be a comma-separated list of IPs
		// The first IP is the original client, the rest are proxies
		ips := strings.Split(forwardedFor, ",")
		if len(tips) > 0 {
			return strings.TrimSpace(tips[0])
		}
	}

	// Fall back to RemoteAddr if X-Forwarded-For is not set
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}

	return host
}

// Close stops the cleanup goroutine
func (r *RateLimiter) Close() {
	r.cancelFunc()
}

// GetRateLimitHeaders returns rate limit headers for the response
func (r *RateLimiter) GetRateLimitHeaders(ip, userID string) http.Header {
	headers := make(http.Header)
	headers.Set("X-RateLimit-Limit", strconv.Itoa(r.maxRequests))
	headers.Set("X-RateLimit-Window", r.window.String())

	r.mu.RLock()
	defer r.mu.RUnlock()

	now := time.Now()

	// Check IP rate limit
	if limit, ok := r.ipLimits[ip]; ok {
		remaining := r.maxRequests - limit.count
		if remaining < 0 {
			remaining = 0
		}
		headers.Set("X-RateLimit-Remaining", strconv.Itoa(remaining))
		headers.Set("X-RateLimit-Reset", strconv.FormatInt(limit.firstSeen.Add(r.window).Unix(), 10))
	}

	// Check user rate limit
	if userID != "" {
		if limit, ok := r.userLimits[userID]; ok {
			remaining := r.maxRequests - limit.count
			if remaining < 0 {
				remaining = 0
			}
			headers.Set("X-User-RateLimit-Remaining", strconv.Itoa(remaining))
			headers.Set("X-User-RateLimit-Reset", strconv.FormatInt(limit.firstSeen.Add(r.window).Unix(), 10))
		}
	}

	return headers
}
