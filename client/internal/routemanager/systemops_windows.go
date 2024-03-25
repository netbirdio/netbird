//go:build windows

package routemanager

import (
	"fmt"
	"net"
	"net/netip"
	"os/exec"
	"strings"

	log "github.com/sirupsen/logrus"
	"github.com/yusufpapurcu/wmi"

	"github.com/netbirdio/netbird/client/internal/peer"
	"github.com/netbirdio/netbird/iface"
)

type Win32_IP4RouteTable struct {
	Destination string
	Mask        string
}

var routeManager *RouteManager

func setupRouting(initAddresses []net.IP, wgIface *iface.WGIface) (peer.BeforeAddPeerHookFunc, peer.AfterRemovePeerHookFunc, error) {
	return setupRoutingWithRouteManager(&routeManager, initAddresses, wgIface)
}

func cleanupRouting() error {
	return cleanupRoutingWithRouteManager(routeManager)
}

func getRoutesFromTable() ([]netip.Prefix, error) {
	var routes []Win32_IP4RouteTable
	query := "SELECT Destination, Mask FROM Win32_IP4RouteTable"

	err := wmi.Query(query, &routes)
	if err != nil {
		return nil, fmt.Errorf("get routes: %w", err)
	}

	var prefixList []netip.Prefix
	for _, route := range routes {
		addr, err := netip.ParseAddr(route.Destination)
		if err != nil {
			log.Warnf("Unable to parse route destination %s: %v", route.Destination, err)
			continue
		}
		maskSlice := net.ParseIP(route.Mask).To4()
		if maskSlice == nil {
			log.Warnf("Unable to parse route mask %s", route.Mask)
			continue
		}
		mask := net.IPv4Mask(maskSlice[0], maskSlice[1], maskSlice[2], maskSlice[3])
		cidr, _ := mask.Size()

		routePrefix := netip.PrefixFrom(addr, cidr)
		if routePrefix.IsValid() && routePrefix.Addr().Is4() {
			prefixList = append(prefixList, routePrefix)
		}
	}
	return prefixList, nil
}

func addRoutePowershell(prefix netip.Prefix, nexthop netip.Addr, intf string) error {
	destinationPrefix := prefix.String()
	psCmd := "New-NetRoute"

	addressFamily := "IPv4"
	if prefix.Addr().Is6() {
		addressFamily = "IPv6"
	}

	script := fmt.Sprintf(
		`%s -AddressFamily "%s" -DestinationPrefix "%s" -InterfaceAlias "%s" -Confirm:$False -ErrorAction Stop`,
		psCmd, addressFamily, destinationPrefix, intf,
	)

	if nexthop.IsValid() {
		script = fmt.Sprintf(
			`%s -NextHop "%s"`, script, nexthop,
		)
	}

	out, err := exec.Command("powershell", "-Command", script).CombinedOutput()
	log.Tracef("PowerShell add route: %s", string(out))

	if err != nil {
		return fmt.Errorf("PowerShell add route: %w", err)
	}

	return nil
}

func addRouteCmd(prefix netip.Prefix, nexthop netip.Addr, _ string) error {
	args := []string{"add", prefix.String(), nexthop.Unmap().String()}

	out, err := exec.Command("route", args...).CombinedOutput()

	log.Tracef("route %s output: %s", strings.Join(args, " "), out)
	if err != nil {
		return fmt.Errorf("route add: %w", err)
	}

	return nil
}

func addToRouteTable(prefix netip.Prefix, nexthop netip.Addr, intf string) error {
	// Powershell doesn't support adding routes without an interface but allows to add interface by name
	if intf != "" {
		return addRoutePowershell(prefix, nexthop, intf)
	}
	return addRouteCmd(prefix, nexthop, intf)
}

func removeFromRouteTable(prefix netip.Prefix, nexthop netip.Addr, _ string) error {
	args := []string{"delete", prefix.String()}
	if nexthop.IsValid() {
		args = append(args, nexthop.Unmap().String())
	}

	out, err := exec.Command("route", args...).CombinedOutput()
	log.Tracef("route %s output: %s", strings.Join(args, " "), out)

	if err != nil {
		return fmt.Errorf("remove route: %w", err)
	}
	return nil
}
