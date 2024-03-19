//go:build darwin || dragonfly || freebsd || netbsd || openbsd

package routemanager

import (
	"fmt"
	"net"
	"net/netip"
	"syscall"

	"golang.org/x/net/route"

	"github.com/netbirdio/netbird/client/internal/peer"
	"github.com/netbirdio/netbird/iface"
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

func setupRouting([]net.IP, *iface.WGIface) (peer.BeforeAddPeerHookFunc, peer.AfterRemovePeerHookFunc, error) {
	return nil, nil, nil
}

func cleanupRouting() error {
	return nil
}

func getRoutesFromTable() ([]netip.Prefix, error) {
	tab, err := route.FetchRIB(syscall.AF_UNSPEC, route.RIBTypeRoute, 0)
	if err != nil {
		return nil, err
	}
	msgs, err := route.ParseRIB(route.RIBTypeRoute, tab)
	if err != nil {
		return nil, err
	}
	var prefixList []netip.Prefix
	for _, msg := range msgs {
		m := msg.(*route.RouteMessage)

		if m.Version < 3 || m.Version > 5 {
			return nil, fmt.Errorf("unexpected RIB message version: %d", m.Version)
		}
		if m.Type != 4 /* RTM_GET */ {
			return nil, fmt.Errorf("unexpected RIB message type: %d", m.Type)
		}

		if m.Flags&RTF_UP == 0 ||
			m.Flags&(RTF_REJECT|RTF_BLACKHOLE) != 0 {
			continue
		}

		addr, ok := toNetIPAddr(m.Addrs[0])
		if !ok {
			continue
		}

		mask, ok := toNetIPMASK(m.Addrs[2])
		if !ok {
			continue
		}
		cidr, _ := mask.Size()

		routePrefix := netip.PrefixFrom(addr, cidr)
		if routePrefix.IsValid() {
			prefixList = append(prefixList, routePrefix)
		}
	}
	return prefixList, nil
}

func toNetIPAddr(a route.Addr) (netip.Addr, bool) {
	switch t := a.(type) {
	case *route.Inet4Addr:
		ip := net.IPv4(t.IP[0], t.IP[1], t.IP[2], t.IP[3])
		addr := netip.MustParseAddr(ip.String())
		return addr, true
	default:
		return netip.Addr{}, false
	}
}

func toNetIPMASK(a route.Addr) (net.IPMask, bool) {
	switch t := a.(type) {
	case *route.Inet4Addr:
		mask := net.IPv4Mask(t.IP[0], t.IP[1], t.IP[2], t.IP[3])
		return mask, true
	default:
		return nil, false
	}
}
