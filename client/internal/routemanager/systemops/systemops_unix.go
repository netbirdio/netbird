//go:build (darwin && !ios) || dragonfly || freebsd || netbsd || openbsd

package systemops

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"syscall"
	"time"
	"unsafe"

	"github.com/cenkalti/backoff/v4"
	log "github.com/sirupsen/logrus"
	"golang.org/x/net/route"
	"golang.org/x/sys/unix"

	"github.com/netbirdio/netbird/client/internal/statemanager"
)

func (r *SysOps) SetupRouting(initAddresses []net.IP, stateManager *statemanager.Manager, advancedRouting bool) error {
	return r.setupRefCounter(initAddresses, stateManager)
}

func (r *SysOps) CleanupRouting(stateManager *statemanager.Manager, advancedRouting bool) error {
	return r.cleanupRefCounter(stateManager)
}

func (r *SysOps) addToRouteTable(prefix netip.Prefix, nexthop Nexthop) error {
	return r.routeSocket(unix.RTM_ADD, prefix, nexthop)
}

func (r *SysOps) removeFromRouteTable(prefix netip.Prefix, nexthop Nexthop) error {
	return r.routeSocket(unix.RTM_DELETE, prefix, nexthop)
}

func (r *SysOps) routeSocket(action int, prefix netip.Prefix, nexthop Nexthop) error {
	if !prefix.IsValid() {
		return fmt.Errorf("invalid prefix: %s", prefix)
	}

	expBackOff := backoff.NewExponentialBackOff()
	expBackOff.InitialInterval = 50 * time.Millisecond
	expBackOff.MaxInterval = 500 * time.Millisecond
	expBackOff.MaxElapsedTime = 1 * time.Second

	if err := backoff.Retry(r.routeOp(action, prefix, nexthop), expBackOff); err != nil {
		a := "add"
		if action == unix.RTM_DELETE {
			a = "remove"
		}
		return fmt.Errorf("%s route for %s: %w", a, prefix, err)
	}
	return nil
}

func (r *SysOps) routeOp(action int, prefix netip.Prefix, nexthop Nexthop) func() error {
	operation := func() error {
		fd, err := unix.Socket(syscall.AF_ROUTE, syscall.SOCK_RAW, syscall.AF_UNSPEC)
		if err != nil {
			return fmt.Errorf("open routing socket: %w", err)
		}
		defer func() {
			if err := unix.Close(fd); err != nil && !errors.Is(err, unix.EBADF) {
				log.Warnf("failed to close routing socket: %v", err)
			}
		}()

		msg, err := r.buildRouteMessage(action, prefix, nexthop)
		if err != nil {
			return backoff.Permanent(fmt.Errorf("build route message: %w", err))
		}

		msgBytes, err := msg.Marshal()
		if err != nil {
			return backoff.Permanent(fmt.Errorf("marshal route message: %w", err))
		}

		if _, err = unix.Write(fd, msgBytes); err != nil {
			if errors.Is(err, unix.ENOBUFS) || errors.Is(err, unix.EAGAIN) {
				return fmt.Errorf("write: %w", err)
			}
			return backoff.Permanent(fmt.Errorf("write: %w", err))
		}

		respBuf := make([]byte, 2048)
		n, err := unix.Read(fd, respBuf)
		if err != nil {
			return backoff.Permanent(fmt.Errorf("read route response: %w", err))
		}

		if n > 0 {
			if err := r.parseRouteResponse(respBuf[:n]); err != nil {
				return backoff.Permanent(err)
			}
		}

		return nil
	}
	return operation
}

func (r *SysOps) buildRouteMessage(action int, prefix netip.Prefix, nexthop Nexthop) (msg *route.RouteMessage, err error) {
	msg = &route.RouteMessage{
		Type:    action,
		Flags:   unix.RTF_UP,
		Version: unix.RTM_VERSION,
		Seq:     r.getSeq(),
	}

	const numAddrs = unix.RTAX_NETMASK + 1
	addrs := make([]route.Addr, numAddrs)

	addrs[unix.RTAX_DST], err = addrToRouteAddr(prefix.Addr())
	if err != nil {
		return nil, fmt.Errorf("build destination address for %s: %w", prefix.Addr(), err)
	}

	if prefix.IsSingleIP() {
		msg.Flags |= unix.RTF_HOST
	} else {
		addrs[unix.RTAX_NETMASK], err = prefixToRouteNetmask(prefix)
		if err != nil {
			return nil, fmt.Errorf("build netmask for %s: %w", prefix, err)
		}
	}

	if nexthop.IP.IsValid() {
		msg.Flags |= unix.RTF_GATEWAY
		addrs[unix.RTAX_GATEWAY], err = addrToRouteAddr(nexthop.IP.Unmap())
		if err != nil {
			return nil, fmt.Errorf("build gateway IP address for %s: %w", nexthop.IP, err)
		}
	} else if nexthop.Intf != nil {
		msg.Index = nexthop.Intf.Index
		addrs[unix.RTAX_GATEWAY] = &route.LinkAddr{
			Index: nexthop.Intf.Index,
			Name:  nexthop.Intf.Name,
		}
	}

	msg.Addrs = addrs
	return msg, nil
}

func (r *SysOps) parseRouteResponse(buf []byte) error {
	if len(buf) < int(unsafe.Sizeof(unix.RtMsghdr{})) {
		return nil
	}

	rtMsg := (*unix.RtMsghdr)(unsafe.Pointer(&buf[0]))
	if rtMsg.Errno != 0 {
		return fmt.Errorf("parse: %d", rtMsg.Errno)
	}

	return nil
}

// addrToRouteAddr converts a netip.Addr to the appropriate route.Addr (*route.Inet4Addr or *route.Inet6Addr).
func addrToRouteAddr(addr netip.Addr) (route.Addr, error) {
	if addr.Is4() {
		return &route.Inet4Addr{IP: addr.As4()}, nil
	}

	if addr.Zone() == "" {
		return &route.Inet6Addr{IP: addr.As16()}, nil
	}

	var zone int
	// zone can be either a numeric zone ID or an interface name.
	if z, err := strconv.Atoi(addr.Zone()); err == nil {
		zone = z
	} else {
		iface, err := net.InterfaceByName(addr.Zone())
		if err != nil {
			return nil, fmt.Errorf("resolve zone '%s': %w", addr.Zone(), err)
		}
		zone = iface.Index
	}
	return &route.Inet6Addr{IP: addr.As16(), ZoneID: zone}, nil
}

func prefixToRouteNetmask(prefix netip.Prefix) (route.Addr, error) {
	bits := prefix.Bits()
	if prefix.Addr().Is4() {
		m := net.CIDRMask(bits, 32)
		var maskBytes [4]byte
		copy(maskBytes[:], m)
		return &route.Inet4Addr{IP: maskBytes}, nil
	}

	if prefix.Addr().Is6() {
		m := net.CIDRMask(bits, 128)
		var maskBytes [16]byte
		copy(maskBytes[:], m)
		return &route.Inet6Addr{IP: maskBytes}, nil
	}

	return nil, fmt.Errorf("unknown IP version in prefix: %s", prefix.Addr().String())
}
