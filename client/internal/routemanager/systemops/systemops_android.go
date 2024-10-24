//go:build android

package systemops

import (
	"net"
	"net/netip"
	"runtime"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/internal/statemanager"
	nbnet "github.com/netbirdio/netbird/util/net"
)

func (r *SysOps) SetupRouting([]net.IP, *statemanager.Manager) (nbnet.AddHookFunc, nbnet.RemoveHookFunc, error) {
	return nil, nil, nil
}

func (r *SysOps) CleanupRouting(*statemanager.Manager) error {
	return nil
}

func (r *SysOps) AddVPNRoute(netip.Prefix, *net.Interface) error {
	return nil
}

func (r *SysOps) RemoveVPNRoute(netip.Prefix, *net.Interface) error {
	return nil
}

func (r *SysOps) removeFromRouteTable(netip.Prefix, Nexthop) error {
	return nil
}

func EnableIPForwarding() error {
	log.Infof("Enable IP forwarding is not implemented on %s", runtime.GOOS)
	return nil
}

func IsAddrRouted(netip.Addr, []netip.Prefix) (bool, netip.Prefix) {
	return false, netip.Prefix{}
}
