//go:build ios || android

package systemops

import (
	"net"
	"net/netip"
	"runtime"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/internal/peer"
)

func (r *SysOps) SetupRouting([]net.IP) (peer.BeforeAddPeerHookFunc, peer.AfterRemovePeerHookFunc, error) {
	return nil, nil, nil
}

func (r *SysOps) CleanupRouting() error {
	return nil
}

func (r *SysOps) AddVPNRoute(netip.Prefix, *net.Interface) error {
	return nil
}

func (r *SysOps) RemoveVPNRoute(netip.Prefix, *net.Interface) error {
	return nil
}

func EnableIPForwarding() error {
	log.Infof("Enable IP forwarding is not implemented on %s", runtime.GOOS)
	return nil
}
