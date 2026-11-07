//go:build !windows && !android && !ios

package systemops

import "net/netip"

// GetUplinkNextHop is GetNextHop: only Windows runs several installations whose
// adapters must be skipped.
func GetUplinkNextHop(dest netip.Addr) (Nexthop, error) {
	return GetNextHop(dest)
}
