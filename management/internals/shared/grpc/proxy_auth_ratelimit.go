package grpc

import (
	"context"
	"net"
	"sync"
	"time"

	"github.com/grpc-ecosystem/go-grpc-middleware/v2/interceptors/realip"
	"golang.org/x/time/rate"
	"google.golang.org/grpc/peer"
)

const (
	// proxyAuthFailureBurst is the maximum number of failed attempts before rate limiting kicks in.
	proxyAuthFailureBurst = 5
	// proxyAuthLimiterCleanup is how often stale limiters are removed.
	proxyAuthLimiterCleanup = 5 * time.Minute
	// proxyAuthLimiterTTL is how long a limiter is kept after the last failure.
	proxyAuthLimiterTTL = 15 * time.Minute
)

// defaultProxyAuthFailureRate is the token replenishment rate for failed auth attempts.
// One token every 12 seconds = 5 per minute.
var defaultProxyAuthFailureRate = rate.Every(12 * time.Second)

// clientIP identifies a client by its IP address for rate limiting purposes.
type clientIP = string

type limiterEntry struct {
	limiter    *rate.Limiter
	lastAccess time.Time
}

// authFailureLimiter tracks per-IP rate limits for failed proxy authentication attempts.
type authFailureLimiter struct {
	mu          sync.Mutex
	limiters    map[clientIP]*limiterEntry
	failureRate rate.Limit
	cancel      context.CancelFunc
}

func newAuthFailureLimiter() *authFailureLimiter {
	return newAuthFailureLimiterWithRate(defaultProxyAuthFailureRate)
}

func newAuthFailureLimiterWithRate(failureRate rate.Limit) *authFailureLimiter {
	ctx, cancel := context.WithCancel(context.Background())
	l := &authFailureLimiter{
		limiters:    make(map[clientIP]*limiterEntry),
		failureRate: failureRate,
		cancel:      cancel,
	}
	go l.cleanupLoop(ctx)
	return l
}

// isLimited returns true if the given IP has exhausted its failure budget.
func (l *authFailureLimiter) isLimited(ip clientIP) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	entry, exists := l.limiters[ip]
	if !exists {
		return false
	}

	return entry.limiter.Tokens() < 1
}

// recordFailure consumes a token from the rate limiter for the given IP.
func (l *authFailureLimiter) recordFailure(ip clientIP) {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := time.Now()
	entry, exists := l.limiters[ip]
	if !exists {
		entry = &limiterEntry{
			limiter: rate.NewLimiter(l.failureRate, proxyAuthFailureBurst),
		}
		l.limiters[ip] = entry
	}
	entry.lastAccess = now
	entry.limiter.Allow()
}

func (l *authFailureLimiter) cleanupLoop(ctx context.Context) {
	ticker := time.NewTicker(proxyAuthLimiterCleanup)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			l.cleanup()
		case <-ctx.Done():
			return
		}
	}
}

func (l *authFailureLimiter) cleanup() {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := time.Now()
	for ip, entry := range l.limiters {
		if now.Sub(entry.lastAccess) > proxyAuthLimiterTTL {
			delete(l.limiters, ip)
		}
	}
}

func (l *authFailureLimiter) stop() {
	l.cancel()
}

// peerIPFromContext extracts the client IP from the gRPC context.
// Uses realip (from trusted proxy headers) first, falls back to the transport peer address.
func peerIPFromContext(ctx context.Context) clientIP {
	if addr, ok := realip.FromContext(ctx); ok {
		return addr.String()
	}

	if p, ok := peer.FromContext(ctx); ok {
		host, _, err := net.SplitHostPort(p.Addr.String())
		if err != nil {
			return p.Addr.String()
		}
		return host
	}

	return ""
}
