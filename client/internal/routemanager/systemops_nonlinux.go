//go:build !linux
// +build !linux

package routemanager

import (
	"fmt"
	"net/netip"
	"os/exec"
	"runtime"

	log "github.com/sirupsen/logrus"
)

func setupRouting() error {
	return nil
}

func cleanupRouting() error {
	return nil
}

func addToRouteTable(prefix netip.Prefix, addr, _ string) error {
	cmd := exec.Command("route", "add", prefix.String(), addr)
	out, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("add route: %w", err)
	}
	log.Debugf(string(out))
	return nil
}

func removeFromRouteTable(prefix netip.Prefix, addr, _ string) error {
	args := []string{"delete", prefix.String()}
	if runtime.GOOS == "darwin" {
		args = append(args, addr)
	}
	cmd := exec.Command("route", args...)
	out, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("remove route: %w", err)
	}
	log.Debugf(string(out))
	return nil
}

func enableIPForwarding() error {
	log.Infof("Enable IP forwarding is not implemented on %s", runtime.GOOS)
	return nil
}

func addRouteForCurrentDefaultGateway(prefix netip.Prefix) error {
	defaultGateway, err := getExistingRIBRouteGateway(defaultv4)
	if err != nil && !errors.Is(err, errRouteNotFound) {
		return fmt.Errorf("get existing route gateway: %s", err)
	}

	addr := netip.MustParseAddr(defaultGateway.String())

	if !prefix.Contains(addr) {
		log.Debugf("Skipping adding a new route for gateway %s because it is not in the network %s", addr, prefix)
		return nil
	}

	gatewayPrefix := netip.PrefixFrom(addr, 32)

	ok, err := existsInRouteTable(gatewayPrefix)
	if err != nil {
		return fmt.Errorf("unable to check if there is an existing route for gateway %s. error: %s", gatewayPrefix, err)
	}

	if ok {
		log.Debugf("Skipping adding a new route for gateway %s because it already exists", gatewayPrefix)
		return nil
	}

	gatewayHop, err := getExistingRIBRouteGateway(gatewayPrefix)
	if err != nil && !errors.Is(err, errRouteNotFound) {
		return fmt.Errorf("unable to get the next hop for the default gateway address. error: %s", err)
	}
	log.Debugf("Adding a new route for gateway %s with next hop %s", gatewayPrefix, gatewayHop)
	return addToRouteTable(gatewayPrefix, gatewayHop.String(), "")
}

func addToRouteTableIfNoExists(prefix netip.Prefix, addr string, intf string) error {
	ok, err := existsInRouteTable(prefix)
	if err != nil {
		return fmt.Errorf("exists in route table: %w", err)
	}
	if ok {
		log.Warnf("Skipping adding a new route for network %s because it already exists", prefix)
		return nil
	}

	ok, err = isSubRange(prefix)
	if err != nil {
		return fmt.Errorf("sub range: %w", err)
	}

	if ok {
		err := addRouteForCurrentDefaultGateway(prefix)
		if err != nil {
			log.Warnf("Unable to add route for current default gateway route. Will proceed without it. error: %s", err)
		}
	}

	return addToRouteTable(prefix, addr, intf)
}

func removeFromRouteTableIfNonSystem(prefix netip.Prefix, addr string, intf string) error {
	return removeFromRouteTable(prefix, addr, intf)
}
