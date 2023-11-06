//go:build !android

package routemanager

import (
	"net"
	"net/netip"
	"os"
	"syscall"
	"unsafe"

	"github.com/vishvananda/netlink"
)

// Pulled from http://man7.org/linux/man-pages/man7/rtnetlink.7.html
// See the section on RTM_NEWROUTE, specifically 'struct rtmsg'.
type routeInfoInMemory struct {
	Family byte
	DstLen byte
	SrcLen byte
	TOS    byte

	Table    byte
	Protocol byte
	Scope    byte
	Type     byte

	Flags uint32
}

const ipv4ForwardingPath = "/proc/sys/net/ipv4/ip_forward"
const ipv6ForwardingPath = "/proc/sys/net/ipv6/conf/all/forwarding"

func addToRouteTable(prefix netip.Prefix, addr string, devName string) error {
	_, ipNet, err := net.ParseCIDR(prefix.String())
	if err != nil {
		return err
	}

	addrMask := "/32"
	if prefix.Addr().Unmap().Is6() {
		addrMask = "/128"
	}

	var ip net.IP = nil
	if addr != "" {
		parsedIp, _, err := net.ParseCIDR(addr + addrMask)
		if err != nil {
			return err
		}
		// for IPv6, setting the local IP as the gateway address results in an "invalid argument" error.
		// Therefore, we cannot use it to obtain the interface for the route (that would only be possible in IPv4).
		if parsedIp.To4() != nil {
			ip = parsedIp
		}
	}

	// We obtain the route interface using the device name.
	linkAlias, err := netlink.LinkByName(devName)
	if err != nil {
		return err
	}

	route := &netlink.Route{
		Scope:     netlink.SCOPE_UNIVERSE,
		Dst:       ipNet,
		Gw:        ip,
		LinkIndex: linkAlias.Attrs().Index,
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

func existsInRouteTable(prefix netip.Prefix) (bool, error) {
	tab, err := syscall.NetlinkRIB(syscall.RTM_GETROUTE, syscall.AF_UNSPEC)
	if err != nil {
		return true, err
	}
	msgs, err := syscall.ParseNetlinkMessage(tab)
	if err != nil {
		return true, err
	}
loop:
	for _, m := range msgs {
		switch m.Header.Type {
		case syscall.NLMSG_DONE:
			break loop
		case syscall.RTM_NEWROUTE:
			rt := (*routeInfoInMemory)(unsafe.Pointer(&m.Data[0]))
			attrs, err := syscall.ParseNetlinkRouteAttr(&m)
			if err != nil {
				return true, err
			}
			if rt.Family != syscall.AF_INET {
				continue loop
			}

			for _, attr := range attrs {
				if attr.Attr.Type == syscall.RTA_DST {
					ip := net.IP(attr.Value)
					mask := net.CIDRMask(int(rt.DstLen), len(attr.Value)*8)
					cidr, _ := mask.Size()
					if ip.String() == prefix.Addr().String() && cidr == prefix.Bits() {
						return true, nil
					}
				}
			}
		}
	}
	return false, nil
}

func enableIPForwarding() error {
	bytes, err := os.ReadFile(ipv4ForwardingPath)
	if err != nil {
		return err
	}

	// check if it is already enabled
	// see more: https://github.com/netbirdio/netbird/issues/872
	if len(bytes) == 0 || bytes[0] != 49 {
		err = os.WriteFile(ipv4ForwardingPath, []byte("1"), 0644)
		if err != nil {
			return err
		}
	}

	// Do the same for IPv6
	bytes, err = os.ReadFile(ipv6ForwardingPath)
	if len(bytes) > 0 && bytes[0] == 49 {
		return nil
	}
	return os.WriteFile(ipv6ForwardingPath, []byte("1"), 0644)

}
