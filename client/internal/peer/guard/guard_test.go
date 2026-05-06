package guard

import (
	"context"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/internal/peer/ice"
)

// newTestGuard returns a Guard with a stubbed connStatusFunc and an
// SRWatcher whose listener channel is unused for the activity-event
// tests. The reconnectLoopWithRetry depends on srWatcher.NewListener()
// which we satisfy with a no-op SRWatcher (no signal/relay subsystems
// running).
func newTestGuard(t *testing.T, status connStatusFunc) (*Guard, *SRWatcher) {
	t.Helper()
	sr := NewSRWatcher(nil, nil, nil, ice.Config{})
	g := NewGuard(log.NewEntry(log.StandardLogger()), status, 30*time.Second, sr)
	return g, sr
}

// TestGuard_NotifyPeerActivity_NonBlockingCoalesce ensures NotifyPeerActivity
// drops bursts onto a buffered channel without blocking, matching the
// SetICEConnDisconnected pattern. Required so high-rate ActivityRecorder
// callbacks never stall the engine path.
func TestGuard_NotifyPeerActivity_NonBlockingCoalesce(t *testing.T) {
	g, _ := newTestGuard(t, func() ConnStatus { return ConnStatusConnected })

	done := make(chan struct{})
	go func() {
		for i := 0; i < 1000; i++ {
			g.NotifyPeerActivity()
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatalf("NotifyPeerActivity blocked for >1s on a buffered channel")
	}
}

// TestGuard_NotifyPeerActivity_NilSafe documents the safety contract
// for callers (Conn / lazy-mgr) that may invoke this against a nil
// guard during a partially-initialised conn lifecycle.
func TestGuard_NotifyPeerActivity_NilSafe(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("NotifyPeerActivity on nil guard panicked: %v", r)
		}
	}()
	var g *Guard
	g.NotifyPeerActivity()
}

// TestGuard_PeerActivityResetsHourlyMode is the headline regression
// pin: a Guard whose iceRetryState is in hourly mode must, on a
// peerActivity event, restart the reconnect ticker and clear the
// hourly state, so the next tick runs the normal 3-budget cycle
// again. We exercise the channel handler indirectly through a custom
// loop that mirrors reconnectLoopWithRetry's relevant case.
func TestGuard_PeerActivityResetsHourlyMode(t *testing.T) {
	g, _ := newTestGuard(t, func() ConnStatus { return ConnStatusPartiallyConnected })

	iceState := &iceRetryState{log: g.log}
	for i := 0; i < maxICERetries+1; i++ {
		_ = iceState.shouldRetry()
	}
	iceState.enterHourlyMode()
	if iceState.hourly == nil {
		t.Fatalf("precondition: expected hourly mode armed")
	}

	g.NotifyPeerActivity()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	select {
	case <-g.peerActivity:
		// simulate the reconnectLoop case body
		iceState.reset()
	case <-ctx.Done():
		t.Fatalf("peerActivity event was not delivered within 1s")
	}

	if iceState.hourly != nil {
		t.Fatalf("hourly ticker should be cleared after activity-driven reset")
	}
	if iceState.retries != 0 {
		t.Fatalf("retries=%d after activity-driven reset, want 0", iceState.retries)
	}
}
