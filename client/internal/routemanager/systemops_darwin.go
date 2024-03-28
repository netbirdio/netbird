//go:build darwin && !ios

package routemanager

import (
	"fmt"
	"net"
	"net/netip"
	"os/exec"
	"strings"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/internal/peer"
	"github.com/netbirdio/netbird/iface"
)

var routeManager *RouteManager

func setupRouting(initAddresses []net.IP, wgIface *iface.WGIface) (peer.BeforeAddPeerHookFunc, peer.AfterRemovePeerHookFunc, error) {
	return setupRoutingWithRouteManager(&routeManager, initAddresses, wgIface)
}

func cleanupRouting() error {
	return cleanupRoutingWithRouteManager(routeManager)
}

func addToRouteTable(prefix netip.Prefix, nexthop netip.Addr, intf string) error {
	return routeCmd("add", prefix, nexthop, intf)
}

func removeFromRouteTable(prefix netip.Prefix, nexthop netip.Addr, intf string) error {
	return routeCmd("delete", prefix, nexthop, intf)
}

func routeCmd(action string, prefix netip.Prefix, nexthop netip.Addr, intf string) error {
	inet := "-inet"
	if prefix.Addr().Is6() {
		inet = "-inet6"
		// Special case for IPv6 split default route, pointing to the wg interface fails
		// TODO: Remove once we have IPv6 support on the interface
		if prefix.Bits() == 1 {
			intf = "lo0"
		}
	}

	args := []string{"-n", action, inet, prefix.String()}
	if nexthop.IsValid() {
		args = append(args, nexthop.Unmap().String())
	} else if intf != "" {
		args = append(args, "-interface", intf)
	}

	out, err := exec.Command("route", args...).CombinedOutput()
	log.Tracef("route %s: %s", strings.Join(args, " "), out)

	if err != nil {
		return fmt.Errorf("failed to %s route for %s: %w", action, prefix, err)
	}
	return nil
}
