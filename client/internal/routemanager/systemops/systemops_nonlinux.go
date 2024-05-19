//go:build !linux && !ios

package systemops

import (
	"net"
	"net/netip"
	"runtime"

	log "github.com/sirupsen/logrus"
)

func (r *RoutingManager) AddVPNRoute(prefix netip.Prefix, intf *net.Interface) error {
	return r.genericAddVPNRoute(prefix, intf)
}

func (r *RoutingManager) RemoveVPNRoute(prefix netip.Prefix, intf *net.Interface) error {
	return r.genericRemoveVPNRoute(prefix, intf)
}

func EnableIPForwarding() error {
	log.Infof("Enable IP forwarding is not implemented on %s", runtime.GOOS)
	return nil
}
