//go:build !linux && !ios

package routemanager

import (
	"net/netip"
	"runtime"

	log "github.com/sirupsen/logrus"
)

func enableIPForwarding() error {
	log.Infof("Enable IP forwarding is not implemented on %s", runtime.GOOS)
	return nil
}

func addVPNRoute(prefix netip.Prefix, intf string) error {
	return genericAddVPNRoute(prefix, intf)
}

func removeVPNRoute(prefix netip.Prefix, intf string) error {
	return genericRemoveVPNRoute(prefix, intf)
}
