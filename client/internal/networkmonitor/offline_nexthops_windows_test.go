package networkmonitor

import (
	"net"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/netbirdio/netbird/client/internal/routemanager/systemops"
)

// A DHCP lease that lapses and comes back from the same router re-adds the
// same default. Online that is noise and is ignored; offline it is the
// network coming back and must be reported.
func TestOfflineChecksReportThePreLossDefault(t *testing.T) {
	home := systemops.Nexthop{IP: netip.MustParseAddr("192.168.1.1"), Intf: &net.Interface{Index: 13, Name: "Ethernet"}}
	added := systemops.RouteUpdate{
		Type:        systemops.RouteAdded,
		Destination: netip.PrefixFrom(netip.IPv4Unspecified(), 0),
		NextHop:     home,
	}

	assert.False(t, routeChanged(added, home, systemops.Nexthop{}), "online: the tracked default re-added is ignored")

	v4, v6 := offlineCheckNextHops(home, systemops.Nexthop{})
	assert.True(t, routeChanged(added, v4, v6), "offline: the pre-loss default coming back is reported")
}
