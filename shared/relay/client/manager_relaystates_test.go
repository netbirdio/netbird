package client

import (
	"testing"
	"time"
)

// TestRelayStates_DoesNotBlockWhileForeignRelayConnecting is a regression test for
// status calls hanging behind an in-progress relay dial.
//
// While a relay is being dialed, its RelayTrack write-lock is held for the whole
// dial (up to serverResponseTimeout per transport attempt, times the transport
// fallback chain, times however many relays are being dialed at once) in openConnVia.
//
// RelayStates() is reached from the daemon status path via
// peer.Status.GetFullStatus() -> GetRelayStates() -> Manager.RelayStates().
// It takes rt.RLock() on every tracked relay. A reader lock blocks while a
// writer holds the  lock, so a single foreign relay mid-Connect in openConnVia
// stalls RelayStates(), and therefore `netbird status -d` hangs for the full dial timeout.
func TestRelayStates_DoesNotBlockWhileForeignRelayConnecting(t *testing.T) {
	m := &Manager{
		relayClients: make(map[string]*RelayTrack),
	}

	// Mirror openConnVia's state during a live dial: a track in the map whose
	// write-lock is held for the duration of relayClient.Connect().
	rt := NewRelayTrack()
	rt.Lock()
	m.relayClients["relay.example.com:443"] = rt
	t.Cleanup(rt.Unlock)

	done := make(chan []RelayConnState, 1)
	go func() {
		done <- m.RelayStates()
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("RelayStates() blocked on a relay track whose Connect() is in progress")
	}
}
