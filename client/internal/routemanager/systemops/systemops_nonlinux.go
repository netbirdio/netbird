//go:build !linux && !ios

package systemops

import (
	"net"
	"net/netip"
	"runtime"

	log "github.com/sirupsen/logrus"
)

func (r *SysOps) AddVPNRoute(prefix netip.Prefix, intf *net.Interface) error {
	return r.genericAddVPNRoute(prefix, intf)
}

func (r *SysOps) RemoveVPNRoute(prefix netip.Prefix, intf *net.Interface) error {
	return r.genericRemoveVPNRoute(prefix, intf)
}

func EnableIPForwarding() error {
	log.Infof("Enable IP forwarding is not implemented on %s", runtime.GOOS)
	return nil
}

func AddVPNRoute(prefix netip.Prefix, intf *net.Interface) error {
	return genericAddVPNRoute(prefix, intf)
}

func RemoveVPNRoute(prefix netip.Prefix, intf *net.Interface) error {
	return genericRemoveVPNRoute(prefix, intf)
}

func hasSeparateRouting() ([]netip.Prefix, error) {
	return getRoutesFromTable()
}
