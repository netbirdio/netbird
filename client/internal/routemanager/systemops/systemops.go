package systemops

import (
	"net"
	"net/netip"

	"github.com/netbirdio/netbird/client/internal/routemanager/refcounter"
	"github.com/netbirdio/netbird/iface"
)

type Nexthop struct {
	IP   netip.Addr
	Intf *net.Interface
}

type ExclusionCounter = refcounter.Counter[any, Nexthop]

type SysOps struct {
	refCounter  *ExclusionCounter
	wgInterface *iface.WGIface
}

func NewSysOps(wgInterface *iface.WGIface) *SysOps {
	return &SysOps{
		wgInterface: wgInterface,
	}
}

// IsAddrRouted checks if the candidate address would route to the vpn, in which case it returns true and the matched prefix.
func IsAddrRouted(addr netip.Addr, vpnRoutes []netip.Prefix) (bool, netip.Prefix) {
	localRoutes, err := hasSeparateRouting()
	if err != nil {
		if !errors.Is(err, ErrRoutingIsSeparate) {
			log.Errorf("Failed to get routes: %v", err)
		}
		return false, netip.Prefix{}
	}

	return isVpnRoute(addr, vpnRoutes, localRoutes)
}

func isVpnRoute(addr netip.Addr, vpnRoutes []netip.Prefix, localRoutes []netip.Prefix) (bool, netip.Prefix) {
	vpnPrefixMap := map[netip.Prefix]struct{}{}
	for _, prefix := range vpnRoutes {
		vpnPrefixMap[prefix] = struct{}{}
	}

	// remove vpnRoute duplicates
	for _, prefix := range localRoutes {
		delete(vpnPrefixMap, prefix)
	}

	var longestPrefix netip.Prefix
	var isVpn bool

	combinedRoutes := make([]netip.Prefix, len(vpnRoutes)+len(localRoutes))
	copy(combinedRoutes, vpnRoutes)
	copy(combinedRoutes[len(vpnRoutes):], localRoutes)

	for _, prefix := range combinedRoutes {
		// Ignore the default route, it has special handling
		if prefix.Bits() == 0 {
			continue
		}

		if prefix.Contains(addr) {
			// Longest prefix match
			if !longestPrefix.IsValid() || prefix.Bits() > longestPrefix.Bits() {
				longestPrefix = prefix
				_, isVpn = vpnPrefixMap[prefix]
			}
		}
	}

	if !longestPrefix.IsValid() {
		// No route matched
		return false, netip.Prefix{}
	}

	// Return true if the longest matching prefix is from vpnRoutes
	return isVpn, longestPrefix
}
