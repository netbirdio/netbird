package client

import (
	"testing"
	"time"
)

// TestRelayStates_DoesNotBlockWhileForeignRelayConnecting is a regression test for
// status calls hanging behind an in-progress relay dial.
//
// openConnVia establishes a new foreign relay like this:
//
//	rt = NewRelayTrack()
//	rt.Lock()                          // track write-lock
//	m.relayClients[serverAddress] = rt
//	m.relayClientsMutex.Unlock()
//	...
//	err := relayClient.Connect(m.ctx)  // network dial, held UNDER rt.Lock()
//	...
//	rt.Unlock()                        // released only after Connect returns/times out
//
// So while a relay is being dialed, its RelayTrack write-lock is held for the whole
// dial (up to serverResponseTimeout per transport attempt, times the transport
// fallback chain, times however many relays are being dialed at once).
//
// RelayStates() — reached from the daemon status path via
// peer.Status.GetFullStatus() -> GetRelayStates() -> Manager.RelayStates() — takes
// rt.RLock() on every tracked relay. A reader lock blocks while a writer holds the
// lock, so a single foreign relay mid-Connect stalls RelayStates(), and therefore
// `netbird status -d`, for the full dial timeout. #6547 moved this off the shared
// map lock but the per-track RLock still blocks the status path.
//
// This test recreates the exact in-progress-dial state (track present in the map
// with its write-lock held) and asserts RelayStates() does not wait on it.
func TestRelayStates_DoesNotBlockWhileForeignRelayConnecting(t *testing.T) {
	m := &Manager{
		relayClients: make(map[string]*RelayTrack),
	}

	// Mirror openConnVia's state during a live dial: a track in the map whose
	// write-lock is held for the duration of relayClient.Connect().
	rt := NewRelayTrack()
	rt.Lock()
	m.relayClients["relay.example.com:443"] = rt
	// Release at the end so a (buggy) blocked RelayStates goroutine can unwind
	// instead of leaking past the test.
	t.Cleanup(rt.Unlock)

	done := make(chan []RelayConnState, 1)
	go func() {
		done <- m.RelayStates()
	}()

	select {
	case <-done:
		// RelayStates returned without waiting for the in-progress dial. Good.
	case <-time.After(2 * time.Second):
		t.Fatal("RelayStates() blocked on a relay track whose Connect() is in progress " +
			"(rt.Lock held across the dial in openConnVia); `netbird status -d` hangs for " +
			"the relay dial timeout")
	}
}
