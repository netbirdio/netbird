package client

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// TestCleanUpUnusedRelays_DoesNotBlockOnRealHangingDial drives a real, hanging foreign
// relay dial and asserts cleanUpUnusedRelays does not stall behind it.
func TestCleanUpUnusedRelays_DoesNotBlockOnRealHangingDial(t *testing.T) {
	serverAddr := stallingRelayListener(t)

	mCtx, mCancel := context.WithCancel(context.Background())
	t.Cleanup(mCancel)

	m := NewManager(mCtx, nil, "alice", 1280)

	dialDone := make(chan struct{})
	go func() {
		defer close(dialDone)
		_, _ = m.openConnVia(mCtx, serverAddr, "peerKey", netip.Addr{})
	}()

	// The track appears in the map once the dial is in flight.
	require.Eventually(t, func() bool {
		m.relayClientsMutex.RLock()
		defer m.relayClientsMutex.RUnlock()
		_, ok := m.relayClients[serverAddr]
		return ok
	}, 5*time.Second, 5*time.Millisecond, "relay dial did not start")

	cleanupDone := make(chan struct{})
	go func() {
		defer close(cleanupDone)
		m.cleanUpUnusedRelays()
	}()

	select {
	case <-cleanupDone:
	case <-time.After(2 * time.Second):
		t.Fatal("cleanUpUnusedRelays blocked on an in-progress relay dial while holding the relay map lock")
	}

	m.relayClientsMutex.RLock()
	_, stillTracked := m.relayClients[serverAddr]
	m.relayClientsMutex.RUnlock()
	require.True(t, stillTracked, "an in-progress relay dial must not be evicted by cleanup")

	// Release the hanging dial so the goroutine can exit cleanly.
	mCancel()
	select {
	case <-dialDone:
	case <-time.After(5 * time.Second):
		t.Fatal("openConnVia did not return after context cancellation")
	}
}
