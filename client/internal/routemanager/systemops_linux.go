package routemanager

import (
	"github.com/vishvananda/netlink"
	"io/ioutil"
	"net"
	"net/netip"
)

const ipv4ForwardingPath = "/proc/sys/net/ipv4/ip_forward"

func addToRouteTable(prefix netip.Prefix, addr string) error {
	_, ipNet, err := net.ParseCIDR(prefix.String())
	if err != nil {
		return err
	}

	addrMask := "/32"
	if prefix.Addr().Unmap().Is6() {
		addrMask = "/128"
	}

	ip, _, err := net.ParseCIDR(addr + addrMask)
	if err != nil {
		return err
	}

	route := &netlink.Route{
		Scope: netlink.SCOPE_UNIVERSE,
		Dst:   ipNet,
		Gw:    ip,
	}

	err = netlink.RouteAdd(route)
	if err != nil {
		return err
	}

	return nil
}

func removeFromRouteTable(prefix netip.Prefix) error {
	_, ipNet, err := net.ParseCIDR(prefix.String())
	if err != nil {
		return err
	}

	route := &netlink.Route{
		Scope: netlink.SCOPE_UNIVERSE,
		Dst:   ipNet,
	}

	err = netlink.RouteDel(route)
	if err != nil {
		return err
	}

	return nil
}

func enableIPForwarding() error {
	err := ioutil.WriteFile(ipv4ForwardingPath, []byte("1"), 0644)
	return err
}

func isNetForwardHistoryEnabled() bool {
	out, err := ioutil.ReadFile(ipv4ForwardingPath)
	if err != nil {
		// todo
		panic(err)
	}
	return string(out) == "1"
}
