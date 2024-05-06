//go:build darwin || dragonfly || freebsd || netbsd || openbsd

package routemanager

import (
	"fmt"
	"net"
	"net/netip"
	"strings"
	"syscall"
	"time"

	"github.com/cenkalti/backoff/v4"
	log "github.com/sirupsen/logrus"
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

// TODO: fix here with retry and backoff
func getRoutesFromTable() ([]netip.Prefix, error) {
	tab, err := retryFetchRIB()
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

func retryFetchRIB() ([]byte, error) {
	var out []byte
	operation := func() error {
		var err error
		out, err = route.FetchRIB(syscall.AF_UNSPEC, route.RIBTypeRoute, 0)
		if errors.Is(err, syscall.ENOMEM) {
			log.Debug("retrying fetchRIB due to 'cannot allocate memory' error")
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
