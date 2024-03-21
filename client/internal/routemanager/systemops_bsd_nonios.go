//go:build (darwin || dragonfly || freebsd || netbsd || openbsd) && !ios

package routemanager

import "net/netip"

func addToRouteTableIfNoExists(prefix netip.Prefix, addr string, intf string) error {
	return genericAddToRouteTableIfNoExists(prefix, addr, intf)
}

func removeFromRouteTableIfNonSystem(prefix netip.Prefix, addr string, intf string) error {
	return genericRemoveFromRouteTableIfNonSystem(prefix, addr, intf)
}
