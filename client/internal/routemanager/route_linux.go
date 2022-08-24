package routemanager

import (
	"github.com/vishvananda/netlink"
	"io/ioutil"
	"net"
	"net/netip"
)

const IPv4ForwardingPath = "/proc/sys/net/ipv4/ip_forward"

func addToRouteTable(prefix netip.Prefix, addr string) error {
	_, ipNet, err := net.ParseCIDR(prefix.String())
	if err != nil {
		return err
	}

	ip, _, err := net.ParseCIDR(addr + "/32")
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
	err := ioutil.WriteFile(IPv4ForwardingPath, []byte("1"), 0644)
	return err
}

func isNetForwardHistoryEnabled() bool {
	out, err := ioutil.ReadFile(IPv4ForwardingPath)
	if err != nil {
		// todo
		panic(err)
	}
	return string(out) == "1"
}
