package routemanager

import (
	"net/netip"
)

func addToRouteTableIfNoExists(prefix netip.Prefix, addr, intf string) error {
	return nil
}

func removeFromRouteTableIfNonSystem(prefix netip.Prefix, addr, intf string) error {
	return nil
}
