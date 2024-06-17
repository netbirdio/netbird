//go:build ios || android

package systemops

import (
	"net"
	"net/netip"
	"runtime"

	log "github.com/sirupsen/logrus"

	nbnet "github.com/netbirdio/netbird/util/net"
)

func (r *SysOps) SetupRouting([]net.IP) (nbnet.AddHookFunc, nbnet.RemoveHookFunc, error) {
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

func IsAddrRouted(netip.Addr, []netip.Prefix) (bool, netip.Prefix) {
	return false, netip.Prefix{}
}
