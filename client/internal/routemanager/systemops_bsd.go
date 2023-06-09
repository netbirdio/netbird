//go:build darwin || dragonfly || freebsd || netbsd || openbsd
// +build darwin dragonfly freebsd netbsd openbsd

package routemanager

import (
	"fmt"
	"net"
	"net/netip"
	"syscall"

	"golang.org/x/net/route"
)

// selected BSD Route flags.
const (
	RTF_UP        = 0x1
	RTF_GATEWAY   = 0x2
	RTF_HOST      = 0x4
	RTF_REJECT    = 0x8
	RTF_DYNAMIC   = 0x10
	RTF_MODIFIED  = 0x20
	RTF_STATIC    = 0x800
	RTF_BLACKHOLE = 0x1000
	RTF_LOCAL     = 0x200000
	RTF_BROADCAST = 0x400000
	RTF_MULTICAST = 0x800000
)

func existsInRouteTable(prefix netip.Prefix) (bool, error) {
	tab, err := route.FetchRIB(syscall.AF_UNSPEC, route.RIBTypeRoute, 0)
	if err != nil {
		return false, err
	}
	msgs, err := route.ParseRIB(route.RIBTypeRoute, tab)
	if err != nil {
		return false, err
	}

	for _, msg := range msgs {
		m := msg.(*route.RouteMessage)

		if m.Version < 3 || m.Version > 5 {
			return false, fmt.Errorf("unexpected RIB message version: %d", m.Version)
		}
		if m.Type != 4 /* RTM_GET */ {
			return true, fmt.Errorf("unexpected RIB message type: %d", m.Type)
		}

		if m.Flags&RTF_UP == 0 ||
			m.Flags&(RTF_REJECT|RTF_BLACKHOLE) != 0 {
			continue
		}

		dst, err := toIPAddr(m.Addrs[0])
		if err != nil {
			return true, fmt.Errorf("unexpected RIB destination: %v", err)
		}

		mask, _ := toIPAddr(m.Addrs[2])
		cidr, _ := net.IPMask(mask.To4()).Size()
		if dst.String() == prefix.Addr().String() && cidr == prefix.Bits() {
			return true, nil
		}
	}

	return false, nil
}

func toIPAddr(a route.Addr) (net.IP, error) {
	switch t := a.(type) {
	case *route.Inet4Addr:
		ip := net.IPv4(t.IP[0], t.IP[1], t.IP[2], t.IP[3])
		return ip, nil
	case *route.Inet6Addr:
		ip := make(net.IP, net.IPv6len)
		copy(ip, t.IP[:])
		return ip, nil
	default:
		return net.IP{}, fmt.Errorf("unknown family: %v", t)
	}
}
