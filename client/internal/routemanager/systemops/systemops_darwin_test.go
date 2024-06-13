//go:build !ios

package systemops

import (
	"net"
	"net/netip"
	"sync"
	"testing"
)

func init() {
	testCases = append(testCases, []testCase{
		{
			name:              "To more specific route without custom dialer via vpn",
			destination:       "10.10.0.2:53",
			expectedInterface: expectedVPNint,
			dialer:            &net.Dialer{},
			expectedPacket:    createPacketExpectation("100.64.0.1", 12345, "10.10.0.2", 53),
		},
	}...)
}

func TestConcurrentRoutes(t *testing.T) {
	baseIP := netip.MustParseAddr("192.0.2.0")
	intf := &net.Interface{Name: "lo0"}

	r := NewSysOps(nil)

	var wg sync.WaitGroup
	for i := 0; i < 1024; i++ {
		wg.Add(1)
		go func(ip netip.Addr) {
			defer wg.Done()
			prefix := netip.PrefixFrom(ip, 32)
			if err := r.addToRouteTable(prefix, Nexthop{netip.Addr{}, intf}); err != nil {
				t.Errorf("Failed to add route for %s: %v", prefix, err)
			}
		}(baseIP)
		baseIP = baseIP.Next()
	}

	wg.Wait()

	baseIP = netip.MustParseAddr("192.0.2.0")

	for i := 0; i < 1024; i++ {
		wg.Add(1)
		go func(ip netip.Addr) {
			defer wg.Done()
			prefix := netip.PrefixFrom(ip, 32)
			if err := r.removeFromRouteTable(prefix, Nexthop{netip.Addr{}, intf}); err != nil {
				t.Errorf("Failed to remove route for %s: %v", prefix, err)
			}
		}(baseIP)
		baseIP = baseIP.Next()
	}

	wg.Wait()
}
