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
