package peer

import (
	"sync"
	"time"

	"github.com/cenkalti/backoff/v4"
)

const (
	// DefaultP2PRetryMax is the built-in fallback when the management
	// server has not pushed a p2p_retry_max_seconds value (Proto wire
	// value 0 = "not set"). Phase 3 of #5989.
	DefaultP2PRetryMax = 15 * time.Minute

	iceBackoffInitialInterval     = 1 * time.Minute
	iceBackoffMultiplier          = 2.0
	iceBackoffRandomizationFactor = 0.1

	// networkChangeGracePeriod is the window after Reset() (signal/relay
	// reconnect, network-change event) during which markFailure caps the
	// suspend delay at networkChangeRetryDelay. Phase 3.7f of #5989.
	//
	// Rationale: the first ICE pair-check after a network change often
	// fails on stale NAT mappings, even when subsequent attempts succeed.
	// Falling back to the normal 1-minute initial backoff after that
	// single failure leaves the peer on relay for far longer than the
	// underlying connectivity actually warrants. A short fixed delay
	// inside the grace window lets follow-up attempts run while the new
	// LTE/Wi-Fi mapping is still fresh; outside the window the normal
	// exponential schedule applies as before.
	//
	// Phase 3.7h widened the window from 30 s to 60 s and reduced the
	// retry delay from 5 s to 2 s after observing real-world LTE-bounce
	// behaviour: cold NAT mappings often need 3-4 ICE attempts to prime,
	// and the previous 30 s window only fit ~2 attempts (each pair-check
	// is ~12-15 s) before the schedule jumped to a 1-minute exponential
	// suspend. The wider window plus shorter delay typically fits ~4-5
	// attempts and recovers within ~50 s for peers behind a single NAT
	// instead of 2-3 minutes.
	networkChangeGracePeriod = 60 * time.Second
	networkChangeRetryDelay  = 2 * time.Second
)

// iceBackoffState tracks per-peer ICE-failure backoff in p2p-dynamic
// mode. Phase 3 of #5989.
type iceBackoffState struct {
	mu          sync.Mutex
	bo          *backoff.ExponentialBackOff
	failures    int
	nextRetry   time.Time
	suspended   bool
	maxBackoff  time.Duration
	lastResetAt time.Time
}

// BackoffSnapshot is a read-only view used by the status output.
type BackoffSnapshot struct {
	Failures  int
	NextRetry time.Time
	Suspended bool
}

func newIceBackoff(maxBackoff time.Duration) *iceBackoffState {
	return &iceBackoffState{
		bo:         buildBackoff(maxBackoff),
		maxBackoff: maxBackoff,
	}
}

func buildBackoff(maxBackoff time.Duration) *backoff.ExponentialBackOff {
	bo := backoff.NewExponentialBackOff()
	bo.InitialInterval = iceBackoffInitialInterval
	bo.Multiplier = iceBackoffMultiplier
	bo.RandomizationFactor = iceBackoffRandomizationFactor
	bo.MaxInterval = maxBackoff
	bo.MaxElapsedTime = 0
	bo.Reset()
	return bo
}

func (s *iceBackoffState) IsSuspended() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.suspended {
		return false
	}
	if time.Now().After(s.nextRetry) {
		return false
	}
	return true
}

// markFailure increments the failure counter and computes the next retry
// time. Returns the delay so callers can log it. If maxBackoff is 0
// (= disabled), returns 0 and does not modify state.
//
// Phase 3.7f of #5989: while we are still inside networkChangeGracePeriod
// after the most recent Reset() (typically a srReconnect / network-change
// event), the suspend delay is capped at networkChangeRetryDelay and the
// long-term exponential schedule is NOT advanced. Once the grace window
// elapses, normal exponential backoff applies. This lets the second ICE
// pair-check run while a fresh LTE/Wi-Fi NAT mapping is still warm,
// without flooding signaling for chronically broken peers.
func (s *iceBackoffState) markFailure() time.Duration {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.maxBackoff == 0 {
		return 0
	}
	s.failures++

	var delay time.Duration
	if !s.lastResetAt.IsZero() && time.Since(s.lastResetAt) < networkChangeGracePeriod {
		delay = networkChangeRetryDelay
	} else {
		delay = s.bo.NextBackOff()
	}

	s.nextRetry = time.Now().Add(delay)
	s.suspended = true
	return delay
}

func (s *iceBackoffState) Snapshot() BackoffSnapshot {
	s.mu.Lock()
	defer s.mu.Unlock()
	return BackoffSnapshot{
		Failures:  s.failures,
		NextRetry: s.nextRetry,
		Suspended: s.suspended && time.Now().Before(s.nextRetry),
	}
}

// markSuccess clears the failure counter and resets the internal backoff
// to its initial interval. Called when pion reports ConnectionStateConnected.
func (s *iceBackoffState) markSuccess() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.failures = 0
	s.suspended = false
	s.bo.Reset()
}

// Reset is the hard reset triggered by interface-change or mode-push.
// In addition to clearing the failure counter and exponential schedule,
// it stamps lastResetAt so that markFailure can apply the
// post-network-change grace period (Phase 3.7f).
func (s *iceBackoffState) Reset() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.failures = 0
	s.suspended = false
	s.bo.Reset()
	s.lastResetAt = time.Now()
}

// SetMaxBackoff updates the cap. Called from ConnMgr.UpdatedRemotePeerConfig
// when the server pushes a new value. Rebuilds the internal backoff with
// the new schedule but preserves the failure counter.
func (s *iceBackoffState) SetMaxBackoff(d time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if d == s.maxBackoff {
		return
	}
	s.maxBackoff = d
	s.bo = buildBackoff(d)
}
