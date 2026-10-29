package server

import (
	"context"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
)

// healthProbeRunner runs the full, expensive probe (network round-trips to
// management, signal and the relays) and reports whether every component was
// healthy. ctx cancels the probe when the caller gives up. Satisfied by
// *internal.Engine.
type healthProbeRunner interface {
	RunHealthProbes(ctx context.Context, waitForResult bool) bool
}

// statsRefresher does the cheap WireGuard-stats refresh callers fall back to
// when a fresh probe isn't warranted. Satisfied by *peer.Status.
type statsRefresher interface {
	RefreshWireGuardStats() error
}

// probeThrottle rate-limits and single-flights the daemon's health probes.
//
// Health probes are expensive (network round-trips to management, signal and
// the relays), while Status(GetFullPeerStatus=true) RPCs can arrive frequently
// and concurrently — the desktop UI alone issues one per connect/disconnect.
// probeThrottle keeps that load bounded with two rules:
//
//   - Single-flight: only one probe runs at a time. Callers that pile up while
//     a probe is in flight share its result instead of each launching another,
//     even when that probe failed. A failed probe therefore does not make every
//     waiter re-probe in turn; the next, non-overlapping caller can try again.
//   - Throttle: after a fully successful probe the result is cached for
//     interval. While any component is unhealthy the cache is not advanced, so
//     later callers keep probing frequently and notice recovery quickly — the
//     intentional "probe often while unhealthy" behaviour from the original
//     design.
type probeThrottle struct {
	interval time.Duration

	mu          sync.Mutex
	lastOK      time.Time // last fully-successful probe; drives the throttle window
	completedAt time.Time // when the most recent probe finished; drives single-flight sharing
}

func newProbeThrottle(interval time.Duration) *probeThrottle {
	return &probeThrottle{interval: interval}
}

// Run decides whether to run a fresh health probe or serve the most recent
// result. It serialises concurrent callers: at most one runner.RunHealthProbes
// executes at a time and the rest call refresher.RefreshWireGuardStats and read
// the snapshot it produced.
//
// Both calls run while the throttle's lock is held, so a slow probe blocks
// other callers until it completes — that blocking is the single-flight
// guarantee. ctx is forwarded to RunHealthProbes so a caller that gives up
// cancels the in-flight probe (and any caller still queued on the lock falls
// through quickly once it acquires it, since the probe ctx is already done).
func (t *probeThrottle) Run(ctx context.Context, runner healthProbeRunner, refresher statsRefresher, waitForResult bool) {
	entered := time.Now()

	t.mu.Lock()
	defer t.mu.Unlock()

	// A probe that finished after we entered ran while we were waiting on the
	// lock — i.e. a peer in the same burst already probed for us, so share its
	// result rather than launch another. This holds even when that probe
	// failed, so a failed probe doesn't make every waiter re-probe in turn.
	sharedRecentProbe := t.completedAt.After(entered)
	throttled := time.Since(t.lastOK) <= t.interval

	if sharedRecentProbe || throttled {
		if err := refresher.RefreshWireGuardStats(); err != nil {
			log.Debugf("failed to refresh WireGuard stats: %v", err)
		}
		return
	}

	healthy := runner.RunHealthProbes(ctx, waitForResult)
	t.completedAt = time.Now()
	if healthy {
		t.lastOK = t.completedAt
	}
}
