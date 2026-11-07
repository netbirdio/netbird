//go:build windows

package systemops

import (
	"fmt"
	"net"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// T-COEX-U2: another installation's exit node (0.0.0.0/1 on wt0) never becomes
// the uplink of wt_acme's sockets; the physical adapter does.
func TestPickUplinkSkipsNetBirdAdapters(t *testing.T) {
	ifaces := map[int]*net.Interface{
		1: {Index: 1, Name: "wt0", Flags: net.FlagUp},
		2: {Index: 2, Name: "wt_acme", Flags: net.FlagUp},
		3: {Index: 3, Name: "Ethernet", Flags: net.FlagUp},
	}
	byIndex := func(i int) (*net.Interface, error) {
		if iface, ok := ifaces[i]; ok {
			return iface, nil
		}
		return nil, fmt.Errorf("no interface %d", i)
	}
	candidates := []candidateRoute{
		{interfaceIndex: 1, prefixLength: 1, routeMetric: 1, interfaceMetric: 5},
		{interfaceIndex: 2, prefixLength: 1, routeMetric: 1, interfaceMetric: 1000},
		{interfaceIndex: 3, prefixLength: 0, routeMetric: 25, interfaceMetric: 25, nextHop: netip.MustParseAddr("192.168.1.1")},
	}
	sortRouteCandidates(candidates)

	iface, candidate, err := pickUplink(candidates, netip.MustParseAddr("203.0.113.10"), byIndex)
	require.NoError(t, err)
	assert.Equal(t, "Ethernet", iface.Name, "uplink")
	assert.Equal(t, netip.MustParseAddr("192.168.1.1"), candidate.nextHop, "next hop")

	_, _, err = pickUplink(candidates[:2], netip.MustParseAddr("203.0.113.10"), byIndex)
	assert.Error(t, err, "only NetBird adapters: no uplink")
}
