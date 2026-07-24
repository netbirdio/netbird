package client

import (
	"context"
	"testing"
	"time"
)

// TestCleanUpUnusedRelays_DoesNotBlockOnRealHangingDial drives a real, hanging foreign
// relay dial and asserts the foreign store cleanup does not stall behind it.
func TestCleanUpUnusedRelays_DoesNotBlockOnRealHangingDial(t *testing.T) {
	serverAddr, accepted := stallingRelayListener(t)

	mCtx, mCancel := context.WithCancel(context.Background())
	t.Cleanup(mCancel)

	m := NewManager(mCtx, nil, "alice", 1280)

	dialDone := make(chan struct{})
	go func() {
		defer close(dialDone)
		_, _ = m.foreign.OpenConn(mCtx, "peerKey", RelayServer{Addr: serverAddr})
	}()

	select {
	case <-accepted:
	case <-time.After(5 * time.Second):
		t.Fatal("relay dial did not reach the listener")
	}

	cleanupDone := make(chan struct{})
	go func() {
		defer close(cleanupDone)
		m.foreign.cleanupUnused()
	}()

	select {
	case <-cleanupDone:
	case <-time.After(2 * time.Second):
		t.Fatal("cleanupUnused blocked on an in-progress relay dial")
	}

	// Release the hanging dial so the goroutine can exit cleanly.
	mCancel()
	select {
	case <-dialDone:
	case <-time.After(5 * time.Second):
		t.Fatal("foreign OpenConn did not return after context cancellation")
	}
}
