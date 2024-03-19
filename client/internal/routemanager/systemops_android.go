package routemanager

import (
	"net"
	"net/netip"

	"github.com/netbirdio/netbird/client/internal/peer"
	"github.com/netbirdio/netbird/iface"
)

func setupRouting([]net.IP, *iface.WGIface) (peer.BeforeAddPeerHookFunc, peer.AfterRemovePeerHookFunc, error) {
	return nil, nil, nil
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
