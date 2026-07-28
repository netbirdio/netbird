package grpc

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/time/rate"
)

func TestAuthFailureLimiter_NotLimitedInitially(t *testing.T) {
	l := newAuthFailureLimiter()
	defer l.stop()

	assert.False(t, l.isLimited("192.168.1.1"), "new IP should not be rate limited")
}

func TestAuthFailureLimiter_LimitedAfterBurst(t *testing.T) {
	l := newAuthFailureLimiter()
	defer l.stop()

	ip := "192.168.1.1"
	for i := 0; i < proxyAuthFailureBurst; i++ {
		l.recordFailure(ip)
	}

	assert.True(t, l.isLimited(ip), "IP should be limited after exhausting burst")
}

func TestAuthFailureLimiter_DifferentIPsIndependent(t *testing.T) {
	l := newAuthFailureLimiter()
	defer l.stop()

	for i := 0; i < proxyAuthFailureBurst; i++ {
		l.recordFailure("192.168.1.1")
	}

	assert.True(t, l.isLimited("192.168.1.1"))
	assert.False(t, l.isLimited("192.168.1.2"), "different IP should not be affected")
}

func TestAuthFailureLimiter_RecoveryOverTime(t *testing.T) {
	l := newAuthFailureLimiterWithRate(rate.Limit(100)) // 100 tokens/sec for fast recovery
	defer l.stop()

	ip := "10.0.0.1"

	// Exhaust burst
	for i := 0; i < proxyAuthFailureBurst; i++ {
		l.recordFailure(ip)
	}
	require.True(t, l.isLimited(ip))

	// Wait for token replenishment
	time.Sleep(50 * time.Millisecond)

	assert.False(t, l.isLimited(ip), "should recover after tokens replenish")
}

func TestAuthFailureLimiter_Cleanup(t *testing.T) {
	l := newAuthFailureLimiter()
	defer l.stop()

	l.recordFailure("10.0.0.1")

	l.mu.Lock()
	require.Len(t, l.limiters, 1)
	// Backdate the entry so it looks stale
	l.limiters["10.0.0.1"].lastAccess = time.Now().Add(-proxyAuthLimiterTTL - time.Minute)
	l.mu.Unlock()

	l.cleanup()

	l.mu.Lock()
	assert.Empty(t, l.limiters, "stale entries should be cleaned up")
	l.mu.Unlock()
}

func TestAuthFailureLimiter_CleanupKeepsFresh(t *testing.T) {
	l := newAuthFailureLimiter()
	defer l.stop()

	l.recordFailure("10.0.0.1")
	l.recordFailure("10.0.0.2")

	l.mu.Lock()
	// Only backdate one entry
	l.limiters["10.0.0.1"].lastAccess = time.Now().Add(-proxyAuthLimiterTTL - time.Minute)
	l.mu.Unlock()

	l.cleanup()

	l.mu.Lock()
	assert.Len(t, l.limiters, 1, "only stale entries should be removed")
	assert.Contains(t, l.limiters, "10.0.0.2")
	l.mu.Unlock()
}
