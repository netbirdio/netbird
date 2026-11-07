package networkmonitor

import "github.com/netbirdio/netbird/client/internal/routemanager/systemops"

// offlineCheckNextHops returns the next hops the checker filters on while no
// default exists. The Windows checker ignores an added default with the
// tracked next hop, so a network coming back through the same router would
// never be reported: offline it tracks none.
func offlineCheckNextHops(_, _ systemops.Nexthop) (systemops.Nexthop, systemops.Nexthop) {
	return systemops.Nexthop{}, systemops.Nexthop{}
}
