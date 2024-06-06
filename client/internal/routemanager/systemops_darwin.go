//go:build darwin && !ios

package routemanager

import (
	"fmt"
	"net"
	"net/netip"
	"os/exec"
	"strings"
	"time"

	"github.com/cenkalti/backoff/v4"
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

func addToRouteTable(prefix netip.Prefix, nexthop netip.Addr, intf *net.Interface) error {
	return routeCmd("add", prefix, nexthop, intf)
}

func removeFromRouteTable(prefix netip.Prefix, nexthop netip.Addr, intf *net.Interface) error {
	return routeCmd("delete", prefix, nexthop, intf)
}

func routeCmd(action string, prefix netip.Prefix, nexthop netip.Addr, intf *net.Interface) error {
	inet := "-inet"
	network := prefix.String()
	if prefix.IsSingleIP() {
		network = prefix.Addr().String()
	}
	if prefix.Addr().Is6() {
		inet = "-inet6"
	}

	args := []string{"-n", action, inet, network}
	if nexthop.IsValid() {
		args = append(args, nexthop.Unmap().String())
	} else if intf != nil {
		args = append(args, "-interface", intf.Name)
	}

	if err := retryRouteCmd(args); err != nil {
		return fmt.Errorf("failed to %s route for %s: %w", action, prefix, err)
	}
	return nil
}

func retryRouteCmd(args []string) error {
	operation := func() error {
		out, err := exec.Command("route", args...).CombinedOutput()
		log.Tracef("route %s: %s", strings.Join(args, " "), out)
		// https://github.com/golang/go/issues/45736
		if err != nil && strings.Contains(string(out), "sysctl: cannot allocate memory") {
			return err
		} else if err != nil {
			return backoff.Permanent(err)
		}
		return nil
	}

	expBackOff := backoff.NewExponentialBackOff()
	expBackOff.InitialInterval = 50 * time.Millisecond
	expBackOff.MaxInterval = 500 * time.Millisecond
	expBackOff.MaxElapsedTime = 1 * time.Second

	err := backoff.Retry(operation, expBackOff)
	if err != nil {
		return fmt.Errorf("route cmd retry failed: %w", err)
	}
	return nil
}
