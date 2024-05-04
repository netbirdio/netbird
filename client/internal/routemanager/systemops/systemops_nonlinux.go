//go:build !linux && !ios

package systemops

import (
	"net"
	"net/netip"
	"runtime"

	log "github.com/sirupsen/logrus"
)

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
