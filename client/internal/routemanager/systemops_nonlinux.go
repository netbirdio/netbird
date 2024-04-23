//go:build !linux && !ios

package routemanager

import (
	"fmt"
	"net"
	"net/netip"
	"runtime"
	"strconv"

	log "github.com/sirupsen/logrus"
)

func enableIPForwarding() error {
	log.Infof("Enable IP forwarding is not implemented on %s", runtime.GOOS)
	return nil
}

func addVPNRoute(prefix netip.Prefix, intf string) error {
	if runtime.GOOS == "windows" {
		i, err := net.InterfaceByName(intf)
		if err != nil {
			return fmt.Errorf("get interface: %w", err)
		}
		intf = strconv.Itoa(i.Index)
	}
	return genericAddVPNRoute(prefix, intf)
}

func removeVPNRoute(prefix netip.Prefix, intf string) error {
	return genericRemoveVPNRoute(prefix, intf)
}
