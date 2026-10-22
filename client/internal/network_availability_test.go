package internal

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/netbirdio/netbird/client/internal/peer"
	"github.com/netbirdio/netbird/client/netevents"
)

// On desktop the engine is the only source of the network state: offline
// must reach the manager, and it must come back online whenever the network
// returns or the monitor stops, or the daemon-wide manager would keep every
// later connection attempt waiting for a network that never gets reported.
func TestNetworkAvailability(t *testing.T) {
	mgr := netevents.NewManager(peer.NewRecorder(""))
	a := networkAvailability{mgr: mgr}

	a.set(false)
	assert.False(t, mgr.IsOnline(), "offline reaches the manager")

	a.set(true)
	assert.True(t, mgr.IsOnline(), "the network coming back reaches the manager")

	a.set(false)
	a.set(true) // what the monitor loop does on its way out
	assert.True(t, mgr.IsOnline(), "the manager is left online when the monitor stops")
}

func TestNetworkAvailabilityWithoutManager(t *testing.T) {
	a := networkAvailability{}
	assert.NotPanics(t, func() {
		a.set(false)
		a.set(true)
	}, "no manager: nothing to report")
}
