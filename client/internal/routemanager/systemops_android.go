package routemanager

import (
	"net/netip"

	"github.com/netbirdio/netbird/iface"
)

func setupRouting([]net.IP, *iface.WGIface) error {
	return nil
}

func cleanupRouting() error {
	return nil
}

func addToRouteTableIfNoExists(prefix netip.Prefix, addr, intf string) error {
	return nil
}

func removeFromRouteTableIfNonSystem(prefix netip.Prefix, addr, intf string) error {
	return nil
}
