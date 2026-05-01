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
)

// iceBackoffState tracks per-peer ICE-failure backoff in p2p-dynamic
// mode. Phase 3 of #5989.
type iceBackoffState struct {
	mu         sync.Mutex
	bo         *backoff.ExponentialBackOff
	failures   int
	nextRetry  time.Time
	suspended  bool
	maxBackoff time.Duration
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
func (s *iceBackoffState) markFailure() time.Duration {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.maxBackoff == 0 {
		return 0
	}
	s.failures++
	delay := s.bo.NextBackOff()
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
// Functionally identical to markSuccess but semantically distinct so
// the caller's intent is visible at call sites.
func (s *iceBackoffState) Reset() {
	s.markSuccess()
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
