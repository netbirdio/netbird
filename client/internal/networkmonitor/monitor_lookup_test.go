//go:build !ios && !android

package networkmonitor

import (
	"errors"
	"net"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/netbirdio/netbird/client/internal/routemanager/systemops"
	"github.com/netbirdio/netbird/client/internal/routemanager/vars"
)

// Offline must mean that no default exists. A lookup that fails, such as a
// netlink error, says nothing about the network: reporting it as offline
// parks the client until the next route event.
func TestNewChangeTellsOfflineFromLookupErrors(t *testing.T) {
	home := NextHops{V4: systemops.Nexthop{IP: netip.MustParseAddr("192.168.1.1"), Intf: &net.Interface{Index: 2, Name: "eth0"}}}
	t.Cleanup(func() { readSnapshotFn = readSnapshot })

	readSnapshotFn = func() (NextHops, error) { return NextHops{}, vars.ErrRouteNotFound }
	assert.Equal(t, ChangeOffline, newChange(home).Kind, "no default at all is offline")

	readSnapshotFn = func() (NextHops, error) { return NextHops{}, errors.New("netlink: interrupted") }
	change := newChange(home)
	assert.Equal(t, ChangeNone, change.Kind, "a failed lookup is not offline")
	assert.Equal(t, home, change.After, "a failed lookup keeps the baseline")
}

// A family whose lookup fails is unknown, not without a default: dropping it
// from the snapshot would read as the default moving and trigger a redial.
func TestReadNextHopsFailsOnOneFamilyLookupError(t *testing.T) {
	v4 := systemops.Nexthop{IP: netip.MustParseAddr("192.168.1.1"), Intf: &net.Interface{Index: 2, Name: "eth0"}}
	t.Cleanup(func() { underlayNextHopFn = underlayNextHop })

	underlayNextHopFn = func(family netip.Addr) (systemops.Nexthop, error) {
		if family.Is4() {
			return v4, nil
		}
		return systemops.Nexthop{}, vars.ErrRouteNotFound
	}
	_, _, err := readNextHops()
	assert.NoError(t, err, "a family without a default is a normal snapshot")

	underlayNextHopFn = func(family netip.Addr) (systemops.Nexthop, error) {
		if family.Is4() {
			return v4, nil
		}
		return systemops.Nexthop{}, errors.New("netlink: interrupted")
	}
	_, _, err = readNextHops()
	assert.Error(t, err, "a failed lookup on one family fails the snapshot")
	assert.NotErrorIs(t, err, vars.ErrRouteNotFound, "and is not mistaken for a missing default")
}
