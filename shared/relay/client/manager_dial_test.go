package client

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// TestManager_InProgressDialIsSafeForReadersAndCleanup covers the new state that
// option 1 introduces: openConnVia now publishes a relay track in the map and
// releases the map lock BEFORE dialing, so a track can legitimately exist with
// relayClient == nil and no track lock held while its Connect() is in flight.
//
// The status path (RelayStates) and the cleanup loop both touch every track, so
// both must tolerate that mid-dial state — neither deref the nil relayClient nor
// evict a track whose dial is still running.
func TestManager_InProgressDialIsSafeForReadersAndCleanup(t *testing.T) {
	m := &Manager{
		relayClients: make(map[string]*RelayTrack),
		// 0 so the created-time grace does not mask the mid-dial (nil relayClient)
		// guard in cleanUpUnusedRelays.
		keepUnusedServerTime: 0,
	}

	const addr = "relay.example.com:443"
	rt := NewRelayTrack() // ready open, relayClient nil, unlocked == dial in progress
	m.relayClients[addr] = rt

	// A status call must not block or panic on a relay still being dialed; it has
	// no state to report yet.
	require.Empty(t, m.RelayStates(), "a relay still being dialed has no state to report")

	// Cleanup must not deref the nil relayClient, and must not evict an in-flight dial.
	m.cleanUpUnusedRelays()
	m.relayClientsMutex.RLock()
	_, stillTracked := m.relayClients[addr]
	m.relayClientsMutex.RUnlock()
	require.True(t, stillTracked, "an in-progress dial must not be cleaned up")
}

// TestOpenConnOnTrack_ReleasesOnContextCancelDuringDial verifies the core option-1
// property: a caller that finds a track whose dial is in progress waits on
// rt.ready, not on the track lock, and can be released by its own context. This
// is what keeps a slow relay dial from serializing behind the track lock.
func TestOpenConnOnTrack_ReleasesOnContextCancelDuringDial(t *testing.T) {
	m := &Manager{relayClients: make(map[string]*RelayTrack)}

	rt := NewRelayTrack() // ready deliberately left open == dial in progress

	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() {
		_, err := m.openConnOnTrack(ctx, rt, "peerKey")
		errCh <- err
	}()

	// While waiting for the dial the caller holds no track lock, so a concurrent
	// reader (e.g. RelayStates) can still take it.
	require.True(t, rt.TryRLock(), "waiter must not hold the track lock while the dial is in progress")
	rt.RUnlock()

	// Caller gives up: openConnOnTrack must return via ctx rather than hang on the dial.
	cancel()
	select {
	case err := <-errCh:
		require.ErrorIs(t, err, context.Canceled)
	case <-time.After(2 * time.Second):
		t.Fatal("openConnOnTrack did not return on ctx cancellation while a dial was in progress")
	}
}
