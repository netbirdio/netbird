//go:build !linux && !ios

package routemanager

import (
	"net"
	"net/netip"
	"runtime"

	log "github.com/sirupsen/logrus"
)

func enableIPForwarding(includeV6 bool) error {
	log.Infof("Enable IP forwarding is not implemented on %s", runtime.GOOS)
	return nil
}

func addVPNRoute(prefix netip.Prefix, intf *net.Interface) error {
	return genericAddVPNRoute(prefix, intf)
}

func removeVPNRoute(prefix netip.Prefix, intf *net.Interface) error {
	return genericRemoveVPNRoute(prefix, intf)
}
