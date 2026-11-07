package internal

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/netbirdio/netbird/client/internal/peer"
	"github.com/netbirdio/netbird/client/netevents"
)

// On desktop the engine is the only source of the network state: offline
// must reach the manager, and the network coming back must too. The monitor
// stopping while offline is covered by the loop tests.
func TestNetworkAvailability(t *testing.T) {
	mgr := netevents.NewManager(peer.NewRecorder(""))
	a := networkAvailability{mgr: mgr}

	a.set(false)
	assert.False(t, mgr.IsOnline(), "offline reaches the manager")

	a.set(true)
	assert.True(t, mgr.IsOnline(), "the network coming back reaches the manager")
}

func TestNetworkAvailabilityWithoutManager(t *testing.T) {
	a := networkAvailability{}
	assert.NotPanics(t, func() {
		a.set(false)
		a.set(true)
	}, "no manager: nothing to report")
}
