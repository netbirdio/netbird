package auth

import (
	"net/netip"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/proxy/internal/types"
)

func TestCredentialLimiterCooldown(t *testing.T) {
	l := newCredentialLimiter()
	now := time.Now()
	l.now = func() time.Time { return now }
	key := credentialSourceKey{service: credentialServiceKey{"account", "service"}, ip: netip.MustParseAddr("192.0.2.1")}
	for range credentialFailureLimit {
		attempt, retry := l.begin(key)
		require.Zero(t, retry, "initial guesses must reach verification")
		l.finish(attempt, credentialRejected)
	}
	_, retry := l.begin(key)
	assert.Equal(t, credentialBlockDuration, retry, "five failures must start a fifteen-minute block")
	now = now.Add(credentialBlockDuration - time.Second)
	_, retry = l.begin(key)
	assert.Equal(t, time.Second, retry, "blocked requests must not extend the deadline")
	now = now.Add(time.Second)
	attempt, retry := l.begin(key)
	require.Zero(t, retry, "the source must recover when its block expires")
	l.finish(attempt, credentialAccepted)
}

func TestCredentialLimiterFailureWindowAndSuccess(t *testing.T) {
	for _, outcome := range []credentialOutcome{credentialAccepted, credentialUnavailable} {
		t.Run(map[credentialOutcome]string{credentialAccepted: "success", credentialUnavailable: "infrastructure error"}[outcome], func(t *testing.T) {
			l := newCredentialLimiter()
			now := time.Now()
			l.now = func() time.Time { return now }
			key := credentialSourceKey{service: credentialServiceKey{"account", "service"}, ip: netip.MustParseAddr("192.0.2.1")}
			for range 4 {
				attempt, retry := l.begin(key)
				require.Zero(t, retry, "four failures must fit the budget")
				l.finish(attempt, credentialRejected)
			}
			attempt, retry := l.begin(key)
			require.Zero(t, retry, "fifth check must be allowed")
			l.finish(attempt, outcome)
			now = now.Add(credentialCheckInterval)
			attempt, retry = l.begin(key)
			require.Zero(t, retry, "success or infrastructure error must not start a block")
			l.finish(attempt, credentialRejected)
			now = now.Add(credentialCheckInterval)
			attempt, retry = l.begin(key)
			if outcome == credentialUnavailable {
				assert.Greater(t, retry, time.Duration(0), "infrastructure errors must preserve earlier failures")
				return
			}
			require.Zero(t, retry, "success must clear earlier failures")
			l.finish(attempt, credentialRejected)
			now = now.Add(credentialFailureWindow)
			for range credentialFailureLimit {
				attempt, retry = l.begin(key)
				require.Zero(t, retry, "old failures must expire")
				l.finish(attempt, credentialRejected)
			}
		})
	}
}

func TestCredentialLimiterRollingWindow(t *testing.T) {
	l := newCredentialLimiter()
	now := time.Now()
	l.now = func() time.Time { return now }
	key := credentialSourceKey{service: credentialServiceKey{"account", "service"}, ip: netip.MustParseAddr("192.0.2.1")}
	attempt, retry := l.begin(key)
	require.Zero(t, retry, "the first failure starts the history")
	l.finish(attempt, credentialRejected)
	now = now.Add(4 * time.Minute)
	for range 3 {
		attempt, retry = l.begin(key)
		require.Zero(t, retry, "three more failures must fit the budget")
		l.finish(attempt, credentialRejected)
	}
	now = now.Add(time.Minute + time.Second)
	for range 2 {
		attempt, retry = l.begin(key)
		require.Zero(t, retry, "only the oldest failure must have expired")
		l.finish(attempt, credentialRejected)
	}
	_, retry = l.begin(key)
	assert.Equal(t, credentialBlockDuration, retry, "five recent failures must block even across the first window boundary")
}

func TestCredentialLimiterServiceBudget(t *testing.T) {
	l := newCredentialLimiter()
	now := time.Now()
	l.now = func() time.Time { return now }
	key := credentialSourceKey{service: credentialServiceKey{"account", "service"}, ip: netip.MustParseAddr("192.0.2.1")}
	for range credentialCheckBurst {
		attempt, retry := l.begin(key)
		require.Zero(t, retry, "initial checks must fit the service burst")
		l.finish(attempt, credentialAccepted)
		key.ip = key.ip.Next()
	}
	_, retry := l.begin(key)
	assert.Equal(t, credentialCheckInterval, retry, "changing IP must not bypass the service budget")
	other := key
	other.service.accountID = "another-account"
	attempt, retry := l.begin(other)
	require.Zero(t, retry, "accounts must have separate budgets")
	l.finish(attempt, credentialAccepted)
	other = key
	other.service.serviceID = "another-service"
	attempt, retry = l.begin(other)
	require.Zero(t, retry, "services must have separate budgets")
	l.finish(attempt, credentialAccepted)
	now = now.Add(credentialCheckInterval)
	attempt, retry = l.begin(key)
	require.Zero(t, retry, "one check must refill every six seconds")
	l.finish(attempt, credentialAccepted)
	_, retry = l.begin(key)
	assert.Equal(t, credentialCheckInterval, retry, "refill must only grant one new check")
}

func TestCredentialLimiterConcurrentReservations(t *testing.T) {
	l := newCredentialLimiter()
	now := time.Now()
	l.now = func() time.Time { return now }
	key := credentialSourceKey{service: credentialServiceKey{"account", "service"}, ip: netip.MustParseAddr("192.0.2.1")}
	var attempts []*credentialSource
	for range credentialFailureLimit {
		attempt, retry := l.begin(key)
		require.Zero(t, retry, "initial requests must reserve the failure budget")
		attempts = append(attempts, attempt)
	}
	// Refill the service budget while earlier verification calls are still running.
	now = now.Add(time.Minute)
	var admitted atomic.Int32
	var wg sync.WaitGroup
	for range 100 {
		wg.Go(func() {
			attempt, retry := l.begin(key)
			if retry == 0 {
				admitted.Add(1)
				l.finish(attempt, credentialRejected)
			}
		})
	}
	wg.Wait()
	assert.Zero(t, admitted.Load(), "in-flight guesses must reserve the failure budget despite a refilled service budget")
	for _, attempt := range attempts {
		wg.Go(func() { l.finish(attempt, credentialRejected) })
	}
	wg.Wait()
	_, retry := l.begin(key)
	assert.Equal(t, credentialBlockDuration, retry, "concurrent failures must activate the block")
}

func TestCredentialLimiterCapacityAndCleanup(t *testing.T) {
	for _, fullSources := range []bool{true, false} {
		t.Run(map[bool]string{true: "sources", false: "services"}[fullSources], func(t *testing.T) {
			l := newCredentialLimiter()
			now := time.Now()
			l.now = func() time.Time { return now }
			key := credentialSourceKey{service: credentialServiceKey{"account", "service"}, ip: netip.MustParseAddr("192.0.2.1")}
			if fullSources {
				ip := netip.MustParseAddr("198.18.0.1")
				for range credentialMaxSources {
					l.sources[credentialSourceKey{service: key.service, ip: ip}] = &credentialSource{expiresAt: now.Add(credentialBlockDuration), blockedUntil: now.Add(credentialBlockDuration)}
					ip = ip.Next()
				}
			} else {
				for i := range credentialMaxServices {
					l.services[credentialServiceKey{serviceID: key.service.serviceID, accountID: types.AccountID(strconv.Itoa(i))}] = &credentialService{lastUsed: now}
				}
			}
			_, retry := l.begin(key)
			assert.Positive(t, retry, "full state must deny new checks without evicting active entries")
			now = now.Add(credentialBlockDuration)
			attempt, retry := l.begin(key)
			require.Zero(t, retry, "expired state must release capacity")
			l.finish(attempt, credentialAccepted)
		})
	}
}
