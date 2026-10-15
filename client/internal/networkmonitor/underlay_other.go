//go:build !linux && !ios && !android

package networkmonitor

import (
	"net/netip"

	"github.com/netbirdio/netbird/client/internal/routemanager/systemops"
)

// underlayNextHop falls back to the plain route lookup. With an exit node
// installed as 0/1 and 128/1, it may resolve to the NetBird interface instead
// of the physical default; these platforms still restart on every change, so
// the comparison does not decide anything there yet.
func underlayNextHop(family netip.Addr) (systemops.Nexthop, error) {
	return systemops.GetNextHop(family)
}
