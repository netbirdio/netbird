//go:build darwin || dragonfly || freebsd || netbsd || openbsd

package routemanager

import (
	"fmt"
	"net"
	"net/netip"
	"syscall"
	"os/exec"
	"strings"
	"time"

	"github.com/cenkalti/backoff/v4"
	log "github.com/sirupsen/logrus"
	"golang.org/x/net/route"

	"github.com/netbirdio/netbird/client/internal/peer"
	"github.com/netbirdio/netbird/iface"
)


var routeManager *RouteManager


func setupRouting(initAddresses []net.IP, wgIface *iface.WGIface) (peer.BeforeAddPeerHookFunc, peer.AfterRemovePeerHookFunc, error) {
	return setupRoutingWithRouteManager(&routeManager, initAddresses, wgIface)
}

func cleanupRouting() error {
	return cleanupRoutingWithRouteManager(routeManager)
}

func addToRouteTable(prefix netip.Prefix, nexthop netip.Addr, intf string) error {
	return routeCmd("add", prefix, nexthop, intf)
}

func removeFromRouteTable(prefix netip.Prefix, nexthop netip.Addr, intf string) error {
	return routeCmd("delete", prefix, nexthop, intf)
}

func routeCmd(action string, prefix netip.Prefix, nexthop netip.Addr, intf string) error {
	inet := "-inet"
	network := prefix.String()
	if prefix.IsSingleIP() {
		network = prefix.Addr().String()
	}
	if prefix.Addr().Is6() {
		inet = "-inet6"
		// Special case for IPv6 split default route, pointing to the wg interface fails
		// TODO: Remove once we have IPv6 support on the interface
		if prefix.Bits() == 1 {
			intf = "lo0"
		}
	}

	args := []string{"-n", action, inet, network}
	if nexthop.IsValid() {
		args = append(args, nexthop.Unmap().String())
	} else if intf != "" {
		args = append(args, "-interface", intf)
	}

	if err := retryRouteCmd(args); err != nil {
		return fmt.Errorf("failed to %s route for %s: %w", action, prefix, err)
	}
	return nil
}

func retryRouteCmd(args []string) error {
	operation := func() error {
		out, err := exec.Command("route", args...).CombinedOutput()
		log.Tracef("route %s: %s", strings.Join(args, " "), out)
		// https://github.com/golang/go/issues/45736
		if err != nil && strings.Contains(string(out), "sysctl: cannot allocate memory") {
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
		return fmt.Errorf("route cmd retry failed: %w", err)
	}
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
