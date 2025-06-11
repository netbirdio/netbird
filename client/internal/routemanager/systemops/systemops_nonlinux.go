//go:build !linux && !ios

package systemops

import (
	"net"
	"net/netip"
	"runtime"

	log "github.com/sirupsen/logrus"
)

func (r *SysOps) AddVPNRoute(prefix netip.Prefix, intf *net.Interface) error {
	if err := r.validateRoute(prefix); err != nil {
		return err
	}
	return r.genericAddVPNRoute(prefix, intf)
}

func (r *SysOps) RemoveVPNRoute(prefix netip.Prefix, intf *net.Interface) error {
	if err := r.validateRoute(prefix); err != nil {
		return err
	}
	return r.genericRemoveVPNRoute(prefix, intf)
}

func EnableIPForwarding() error {
	log.Infof("Enable IP forwarding is not implemented on %s", runtime.GOOS)
	return nil
}

func hasSeparateRouting() ([]netip.Prefix, error) {
	return GetRoutesFromTable()
}
