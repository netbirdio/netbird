package guard

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/internal/peer/ice"
	"github.com/netbirdio/netbird/client/netstate"
)

// newTestGuardWithNetState builds a guard with a realistic MaxInterval: the
// backoff must be able to grow well past the outage, as it does in production
// where the timeout is seconds to minutes.
func newTestGuardWithNetState(status connStatusFunc, netState *netstate.State) *Guard {
	srw := NewSRWatcher(nil, nil, nil, ice.Config{})
	return NewGuard(log.WithField("test", "guard"), status, 30*time.Second, srw, netState)
}

// TestGuard_RecoversAfterOfflineToOnline covers a peer that stays disconnected
// across a network outage while neither signal nor relay reports an event —
// both stayed up, as on a short airplane mode toggle over Wi-Fi.
//
// Every tick taken while offline is skipped, but it still advances the
// exponential backoff, so by the time the network returns the next tick can be
// tens of seconds away. Without an explicit reaction to the transition the
// peer waits out that interval for a recovery that could start immediately.
func TestGuard_RecoversAfterOfflineToOnline(t *testing.T) {
	netState := netstate.New()

	var attempts atomic.Int32
	g := newTestGuardWithNetState(func() ConnStatus { return ConnStatusDisconnected }, netState)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	// Start from the reconnect ticker (800ms initial interval), the state a
	// peer is in after it loses its connection.
	go g.Start(ctx, func() { attempts.Add(1) })
	g.SetRelayedConnDisconnected()

	// Let the backoff climb: 0.8s, 1.6s, 3.2s, 6.4s ... every tick is skipped
	// while offline, but each one doubles the wait for the next.
	netState.Set(false)
	time.Sleep(8 * time.Second)

	offlineAttempts := attempts.Load()
	if offlineAttempts != 0 {
		t.Fatalf("callback ran %d times while offline, want 0", offlineAttempts)
	}

	netState.Set(true)

	// The next organic tick is now several seconds out, so anything within
	// this window can only come from reacting to the transition itself.
	select {
	case <-time.After(2 * time.Second):
		t.Fatal("peer was not retried within 2s of the network coming back, " +
			"with neither a signal nor a relay event to fall back on")
	case <-pollUntil(func() bool { return attempts.Load() > 0 }):
	}
}

// TestGuard_OfflineTransitionDoesNotRetry checks the other direction: going
// offline must not itself trigger an attempt.
func TestGuard_OfflineTransitionDoesNotRetry(t *testing.T) {
	netState := netstate.New()

	var attempts atomic.Int32
	g := newTestGuardWithNetState(func() ConnStatus { return ConnStatusDisconnected }, netState)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go g.Start(ctx, func() { attempts.Add(1) })

	netState.Set(false)
	time.Sleep(5 * time.Second)

	if got := attempts.Load(); got != 0 {
		t.Fatalf("callback ran %d times after going offline, want 0", got)
	}
}

func pollUntil(cond func() bool) <-chan struct{} {
	done := make(chan struct{})
	go func() {
		for {
			if cond() {
				close(done)
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
	}()
	return done
}
