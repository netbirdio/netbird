package systemops

import (
	"net"
	"net/netip"
	"runtime"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/internal/peer"
	"github.com/netbirdio/netbird/iface"
)

func SetupRouting([]net.IP, *iface.WGIface) (peer.BeforeAddPeerHookFunc, peer.AfterRemovePeerHookFunc, error) {
	return nil, nil, nil
}

func CleanupRouting() error {
	return nil
}

func EnableIPForwarding() error {
	log.Infof("Enable IP forwarding is not implemented on %s", runtime.GOOS)
	return nil
}

func AddVPNRoute(netip.Prefix, *net.Interface) error {
	return nil
}

func RemoveVPNRoute(netip.Prefix, *net.Interface) error {
	return nil
}
