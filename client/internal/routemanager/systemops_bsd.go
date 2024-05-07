//go:build darwin || dragonfly || freebsd || netbsd || openbsd

package routemanager

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"syscall"
	"time"

	"github.com/cenkalti/backoff/v4"
	log "github.com/sirupsen/logrus"
	"golang.org/x/net/route"
)

type Route struct {
	Dst       netip.Prefix
	Gw        netip.Addr
	Interface *net.Interface
}

func getRoutesFromTable() ([]netip.Prefix, error) {
	tab, err := retryFetchRIB()
	if err != nil {
		return nil, fmt.Errorf("fetch RIB: %v", err)
	}
	msgs, err := route.ParseRIB(route.RIBTypeRoute, tab)
	if err != nil {
		return nil, fmt.Errorf("parse RIB: %v", err)
	}

	var prefixList []netip.Prefix
	for _, msg := range msgs {
		m := msg.(*route.RouteMessage)

		if m.Version < 3 || m.Version > 5 {
			return nil, fmt.Errorf("unexpected RIB message version: %d", m.Version)
		}
		if m.Type != syscall.RTM_GET {
			return nil, fmt.Errorf("unexpected RIB message type: %d", m.Type)
		}

		if m.Flags&syscall.RTF_UP == 0 ||
			m.Flags&(syscall.RTF_REJECT|syscall.RTF_BLACKHOLE|syscall.RTF_WASCLONED) != 0 {
			continue
		}

		route, err := MsgToRoute(m)
		if err != nil {
			log.Warnf("Failed to parse route message: %v", err)
			continue
		}
		if route.Dst.IsValid() {
			prefixList = append(prefixList, route.Dst)
		}
	}
	return prefixList, nil
}

func retryFetchRIB() ([]byte, error) {
	var out []byte
	operation := func() error {
		var err error
		out, err = route.FetchRIB(syscall.AF_UNSPEC, route.RIBTypeRoute, 0)
		if errors.Is(err, syscall.ENOMEM) {
			log.Debug("~etrying fetchRIB due to 'cannot allocate memory' error")
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
		return nil, fmt.Errorf("failed to fetch routing information: %w", err)
	}
	return out, nil
}

func toNetIP(a route.Addr) netip.Addr {
	switch t := a.(type) {
	case *route.Inet4Addr:
		return netip.AddrFrom4(t.IP)
	case *route.Inet6Addr:
		ip := netip.AddrFrom16(t.IP)
		if t.ZoneID != 0 {
			ip.WithZone(strconv.Itoa(t.ZoneID))
		}
		return ip
	default:
		return netip.Addr{}
	}
}

func ones(a route.Addr) (int, error) {
	switch t := a.(type) {
	case *route.Inet4Addr:
		mask, _ := net.IPMask(t.IP[:]).Size()
		return mask, nil
	case *route.Inet6Addr:
		mask, _ := net.IPMask(t.IP[:]).Size()
		return mask, nil
	default:
		return 0, fmt.Errorf("unexpected address type: %T", a)
	}
}

func MsgToRoute(msg *route.RouteMessage) (*Route, error) {
	dstIP, nexthop, dstMask := msg.Addrs[0], msg.Addrs[1], msg.Addrs[2]

	addr := toNetIP(dstIP)

	var nexthopAddr netip.Addr
	var nexthopIntf *net.Interface

	switch t := nexthop.(type) {
	case *route.Inet4Addr, *route.Inet6Addr:
		nexthopAddr = toNetIP(t)
	case *route.LinkAddr:
		nexthopIntf = &net.Interface{
			Index: t.Index,
			Name:  t.Name,
		}
	default:
		return nil, fmt.Errorf("unexpected next hop type: %T", t)
	}

	var prefix netip.Prefix

	if dstMask == nil {
		if addr.Is4() {
			prefix = netip.PrefixFrom(addr, 32)
		} else {
			prefix = netip.PrefixFrom(addr, 128)
		}
	} else {
		bits, err := ones(dstMask)
		if err != nil {
			return nil, fmt.Errorf("failed to parse mask: %v", dstMask)
		}
		prefix = netip.PrefixFrom(addr, bits)
	}

	return &Route{
		Dst:       prefix,
		Gw:        nexthopAddr,
		Interface: nexthopIntf,
	}, nil

}
