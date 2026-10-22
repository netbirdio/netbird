//go:build !ios && !android

package networkmonitor

import (
	"net"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/netbirdio/netbird/client/internal/routemanager/systemops"
)

func TestDefaultInterfaceAddrs(t *testing.T) {
	lo, err := net.InterfaceByName("lo")
	if err != nil {
		t.Skip("no loopback interface named lo on this host")
	}
	// Loopback addresses are not underlay addresses and must be dropped.
	assert.Empty(t, defaultInterfaceAddrs(systemops.Nexthop{Intf: lo}), "loopback addresses are skipped")
	assert.Empty(t, defaultInterfaceAddrs(systemops.Nexthop{}), "a family without a default contributes nothing")
}

// The default interface's routable addresses are what the snapshot compares;
// the IPv4 and IPv6 defaults often share one interface, which must count once.
func TestDefaultInterfaceAddrsKeepsRoutableAddresses(t *testing.T) {
	ifaces, err := net.Interfaces()
	if err != nil {
		t.Skipf("list interfaces: %v", err)
	}
	for i := range ifaces {
		iface := &ifaces[i]
		var routable []netip.Addr
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			if p, err := netip.ParsePrefix(a.String()); err == nil && p.Addr().IsGlobalUnicast() || err == nil && p.Addr().IsPrivate() {
				routable = append(routable, p.Addr().Unmap())
			}
		}
		if len(routable) == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}

		got := defaultInterfaceAddrs(systemops.Nexthop{Intf: iface}, systemops.Nexthop{Intf: iface})
		assert.ElementsMatch(t, routable, got, "routable addresses of %s, once each", iface.Name)
		return
	}
	t.Skip("no interface with a routable address on this host")
}
