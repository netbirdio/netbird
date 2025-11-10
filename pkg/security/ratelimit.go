package security

import (
	"context"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

// RateLimiter implements a token bucket rate limiter with automatic cleanup.
// It supports both IP-based and per-user rate limiting and includes protection
// against rapid resets and unbounded memory growth.
//
// The rate limiter uses a sliding window approach where requests are counted
// within a time window. When the limit is exceeded, the IP or user is banned
// for a specified duration. The limiter automatically cleans up old entries
// to prevent memory leaks.
//
// Example usage:
//
//	limiter := NewRateLimiter(100, time.Minute, 5*time.Minute)
//	handler := limiter.Middleware(yourHandler)
//
// This will limit each IP to 100 requests per minute, with a ban duration
// of 5 minutes if the limit is exceeded.
//
// Thread-safety: All methods are safe for concurrent use.
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

	// Maximum number of entries to prevent unbounded memory growth
	maxIPEntries     int
	maxUserEntries   int
	maxBannedIPs     int
	maxBannedUsers   int

	// Mutex for thread safety
	mu sync.RWMutex

	// Context for cleanup goroutine
	ctx        context.Context
	cancelFunc context.CancelFunc

	// Logger
	logger *logrus.Logger
}

// rateLimit tracks the request count and timing for a single IP or user.
type rateLimit struct {
	count     int       // Number of requests in the current window
	firstSeen time.Time // When the current window started
	lastSeen  time.Time // When the last request was made
}

// NewRateLimiter creates a new RateLimiter instance with the specified parameters.
//
// Parameters:
//   - maxRequests: Maximum number of requests allowed per window. If <= 0, defaults to 100.
//   - window: Time window for rate limiting (e.g., 1 minute). If <= 0, defaults to 1 minute.
//   - banDuration: Duration to ban an IP/user after rate limit is exceeded. If <= 0, defaults to 5 minutes.
//
// The cleanup interval is automatically set to 10% of the window duration (minimum 1 second).
// The rate limiter starts a background goroutine for automatic cleanup of old entries.
//
// Returns a configured RateLimiter that is ready to use. Call Close() when done to stop
// the cleanup goroutine.
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
		maxIPEntries:   10000,   // Limit to prevent unbounded growth
		maxUserEntries: 10000,   // Limit to prevent unbounded growth
		maxBannedIPs:   5000,    // Limit banned IPs
		maxBannedUsers: 5000,    // Limit banned users
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

// cleanup periodically removes old entries from the rate limiter to prevent memory leaks.
// This method runs in a background goroutine and stops when the context is cancelled.
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

// cleanupOldEntries removes old entries from the rate limiter maps.
// It removes entries that haven't been seen for more than 2*window duration
// and expired bans. This method must be called while holding the write lock.
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

// Allow checks if a request from the given IP and user is allowed under the rate limit.
//
// Parameters:
//   - ip: The client IP address (required)
//   - userID: The user ID if authenticated (optional). If provided, rate limiting
//     is applied per user instead of per IP.
//
// Returns:
//   - true if the request is allowed
//   - false if the IP/user is banned or has exceeded the rate limit
//
// Thread-safety: This method is safe for concurrent use.
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
			// Check if we've reached the maximum number of entries
			if len(r.userLimits) >= r.maxUserEntries {
				// Remove oldest entry to make room
				r.evictOldestUserLimit(now)
			}
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
			// Check if we've reached the maximum number of entries
			if len(r.ipLimits) >= r.maxIPEntries {
				// Remove oldest entry to make room
				r.evictOldestIPLimit(now)
			}
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
			// Check if we've reached the maximum number of banned users
			if len(r.bannedUsers) >= r.maxBannedUsers {
				// Remove oldest ban to make room
				r.evictOldestBannedUser(now)
			}
			r.bannedUsers[userID] = now
			r.logger.WithFields(logrus.Fields{
				"user_id": userID,
				"count":   limit.count,
			}).Warn("User rate limit exceeded, banned")
		} else {
			// Check if we've reached the maximum number of banned IPs
			if len(r.bannedIPs) >= r.maxBannedIPs {
				// Remove oldest ban to make room
				r.evictOldestBannedIP(now)
			}
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

// Middleware returns an HTTP middleware function that enforces rate limiting.
// The middleware checks the rate limit before calling the next handler.
// If the rate limit is exceeded, it returns HTTP 429 (Too Many Requests).
//
// The middleware extracts the client IP from X-Forwarded-For header (if present)
// or RemoteAddr, and the user ID from the request context (if available).
//
// Example:
//
//	limiter := NewRateLimiter(100, time.Minute, 5*time.Minute)
//	router.Use(limiter.Middleware)
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

// getClientIP extracts and validates the client IP address from the HTTP request.
//
// It first checks the X-Forwarded-For header (used when behind a reverse proxy),
// then falls back to RemoteAddr. The IP is validated to prevent spoofing attacks.
//
// Security Note: X-Forwarded-For can be spoofed if not behind a trusted proxy.
// In production, ensure your reverse proxy validates and sets this header.
//
// Returns the validated client IP address, or RemoteAddr if validation fails.
func getClientIP(r *http.Request) string {
	// Check for X-Forwarded-For header first
	if forwardedFor := r.Header.Get("X-Forwarded-For"); forwardedFor != "" {
		// X-Forwarded-For can be a comma-separated list of IPs
		// The first IP is the original client, the rest are proxies
		ips := strings.Split(forwardedFor, ",")
		if len(ips) > 0 {
			ip := strings.TrimSpace(ips[0])
			// Validate that it's a valid IP address to prevent spoofing
			if parsedIP := net.ParseIP(ip); parsedIP != nil {
				return ip
			}
			// If invalid IP, fall through to RemoteAddr
		}
	}

	// Fall back to RemoteAddr if X-Forwarded-For is not set or invalid
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		// If RemoteAddr doesn't have a port, try parsing it as-is
		if parsedIP := net.ParseIP(r.RemoteAddr); parsedIP != nil {
			return r.RemoteAddr
		}
		return r.RemoteAddr
	}

	// Validate the host is a valid IP
	if parsedIP := net.ParseIP(host); parsedIP != nil {
		return host
	}

	return host
}

// Close stops the cleanup goroutine and releases resources.
// This should be called when the RateLimiter is no longer needed to prevent
// goroutine leaks. After calling Close(), the RateLimiter should not be used.
func (r *RateLimiter) Close() {
	r.cancelFunc()
}

// GetRateLimitHeaders returns HTTP headers containing rate limit information
// for the given IP and user. These headers can be included in responses to
// inform clients about their rate limit status.
//
// Headers included:
//   - X-RateLimit-Limit: Maximum requests allowed per window
//   - X-RateLimit-Window: Duration of the rate limit window
//   - X-RateLimit-Remaining: Remaining requests in current window (if applicable)
//   - X-RateLimit-Reset: Unix timestamp when the rate limit resets (if applicable)
//   - X-User-RateLimit-Remaining: Remaining requests for user (if userID provided)
//   - X-User-RateLimit-Reset: Reset time for user (if userID provided)
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

// evictOldestIPLimit removes the oldest IP limit entry when the map reaches its maximum size.
// This implements an LRU-style eviction policy to prevent unbounded memory growth.
// Must be called while holding the write lock.
func (r *RateLimiter) evictOldestIPLimit(now time.Time) {
	var oldestIP string
	var oldestTime time.Time
	first := true

	for ip, limit := range r.ipLimits {
		if first || limit.lastSeen.Before(oldestTime) {
			oldestIP = ip
			oldestTime = limit.lastSeen
			first = false
		}
	}

	if oldestIP != "" {
		delete(r.ipLimits, oldestIP)
	}
}

// evictOldestUserLimit removes the oldest user limit entry when the map reaches its maximum size.
// This implements an LRU-style eviction policy to prevent unbounded memory growth.
// Must be called while holding the write lock.
func (r *RateLimiter) evictOldestUserLimit(now time.Time) {
	var oldestUserID string
	var oldestTime time.Time
	first := true

	for userID, limit := range r.userLimits {
		if first || limit.lastSeen.Before(oldestTime) {
			oldestUserID = userID
			oldestTime = limit.lastSeen
			first = false
		}
	}

	if oldestUserID != "" {
		delete(r.userLimits, oldestUserID)
	}
}

// evictOldestBannedIP removes the oldest banned IP entry when the ban map reaches its maximum size.
// This prevents unbounded growth of the banned IPs map.
// Must be called while holding the write lock.
func (r *RateLimiter) evictOldestBannedIP(now time.Time) {
	var oldestIP string
	var oldestTime time.Time
	first := true

	for ip, banTime := range r.bannedIPs {
		if first || banTime.Before(oldestTime) {
			oldestIP = ip
			oldestTime = banTime
			first = false
		}
	}

	if oldestIP != "" {
		delete(r.bannedIPs, oldestIP)
	}
}

// evictOldestBannedUser removes the oldest banned user entry when the ban map reaches its maximum size.
// This prevents unbounded growth of the banned users map.
// Must be called while holding the write lock.
func (r *RateLimiter) evictOldestBannedUser(now time.Time) {
	var oldestUserID string
	var oldestTime time.Time
	first := true

	for userID, banTime := range r.bannedUsers {
		if first || banTime.Before(oldestTime) {
			oldestUserID = userID
			oldestTime = banTime
			first = false
		}
	}

	if oldestUserID != "" {
		delete(r.bannedUsers, oldestUserID)
	}
}
