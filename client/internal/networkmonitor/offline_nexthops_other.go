//go:build !windows && !ios && !android

package networkmonitor

import "github.com/netbirdio/netbird/client/internal/routemanager/systemops"

// offlineCheckNextHops returns the next hops the checker filters on while no
// default exists. These checkers report every added default whatever its next
// hop, and some need a tracked interface to start, so they keep the pre-loss
// ones.
func offlineCheckNextHops(v4, v6 systemops.Nexthop) (systemops.Nexthop, systemops.Nexthop) {
	return v4, v6
}
