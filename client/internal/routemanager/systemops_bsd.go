//go:build darwin || dragonfly || freebsd || netbsd || openbsd

package routemanager

import (
	"fmt"
	"net"
	"net/netip"
	"syscall"

	log "github.com/sirupsen/logrus"
	"golang.org/x/net/route"
)


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

		if m.Flags&syscall.RTF_UP == 0 ||
			m.Flags&(syscall.RTF_REJECT|syscall.RTF_BLACKHOLE|syscall.RTF_WASCLONED) != 0 {
			continue
		}

		if len(m.Addrs) < 3 {
			log.Warnf("Unexpected RIB message Addrs: %v", m.Addrs)
			continue
		}

		addr, ok := toNetIPAddr(m.Addrs[0])
		if !ok {
			continue
		}

		cidr := 32
		if mask := m.Addrs[2]; mask != nil {
			cidr, ok = toCIDR(mask)
			if !ok {
				log.Debugf("Unexpected RIB message Addrs[2]: %v", mask)
				continue
			}
		}

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
		return netip.AddrFrom4(t.IP), true
	default:
		return netip.Addr{}, false
	}
}

func toCIDR(a route.Addr) (int, bool) {
	switch t := a.(type) {
	case *route.Inet4Addr:
		mask := net.IPv4Mask(t.IP[0], t.IP[1], t.IP[2], t.IP[3])
		cidr, _ := mask.Size()
		return cidr, true
	default:
		return 0, false
	}
}
