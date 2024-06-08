package routemanager

import (
	"net"
	"net/netip"
	"runtime"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/internal/peer"
	"github.com/netbirdio/netbird/iface"
)

func setupRouting([]net.IP, *iface.WGIface) (peer.BeforeAddPeerHookFunc, peer.AfterRemovePeerHookFunc, error) {
	return nil, nil, nil
}

func cleanupRouting() error {
	return nil
}

func enableIPForwarding(includeV6 bool) error {
	log.Infof("Enable IP forwarding is not implemented on %s", runtime.GOOS)
	return nil
}

func addVPNRoute(netip.Prefix, *net.Interface) error {
	return nil
}

func removeVPNRoute(netip.Prefix, *net.Interface) error {
	return nil
}
