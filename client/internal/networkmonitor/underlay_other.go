//go:build !linux && !windows && !darwin && !ios && !android

package networkmonitor

import (
	"net/netip"

	"github.com/netbirdio/netbird/client/internal/routemanager/systemops"
)

// underlayNextHop falls back to the plain route lookup on the BSDs, which run
// legacy routing and restart on every change, so the comparison does not
// decide anything there.
func underlayNextHop(family netip.Addr) (systemops.Nexthop, error) {
	return systemops.GetNextHop(family)
}
