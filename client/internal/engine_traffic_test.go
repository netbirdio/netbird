package internal

import (
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/netbirdio/netbird/client/iface/configurer"
	"github.com/netbirdio/netbird/monotime"
)

// The retry gate reads real traffic from the activity recorder. Byte counters
// move on every keepalive and handshake, so they must not be read at all.
func TestTunnelActivity(t *testing.T) {
	now := monotime.Now()
	old := now - monotime.Time(10*time.Minute)
	activities := map[string]monotime.Time{"a": old, "b": now - monotime.Time(3*time.Second)}
	iface := &MockWGIface{
		LastActivitiesFunc: func() map[string]monotime.Time { return activities },
		GetStatsFunc: func() (map[string]configurer.WGStats, error) {
			t.Fatal("byte counters count keepalives and must not be read")
			return nil, errors.New("byte counters must not be read")
		},
	}
	probe := tunnelActivity(iface)

	stamp, ok := probe()
	assert.True(t, ok)
	assert.Equal(t, int64(activities["b"]), stamp, "newest real packet of any peer")

	// A keepalive only minute: byte counters would move, the stamp does not.
	activities = map[string]monotime.Time{"a": old, "b": monotime.Time(stamp)}
	again, ok := probe()
	assert.True(t, ok)
	assert.Equal(t, stamp, again, "keepalives leave the stamp where it was")

	activities = nil
	_, ok = probe()
	assert.False(t, ok, "no peers: traffic unknown")
}
