//go:build !linux || android

package systemops

import (
	"fmt"
	"net/netip"
)

func getNextHopViaNetlink(ip netip.Addr) (Nexthop, error) {
	return Nexthop{}, fmt.Errorf("netlink route fallback not available on this platform")
}
