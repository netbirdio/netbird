//go:build (darwin && !ios) || dragonfly || freebsd || netbsd || openbsd

package systemops

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strconv"
	"syscall"
	"time"
	"unsafe"

	"github.com/cenkalti/backoff/v4"
	"github.com/hashicorp/go-multierror"
	log "github.com/sirupsen/logrus"
	"golang.org/x/net/route"
	"golang.org/x/sys/unix"

	nberrors "github.com/netbirdio/netbird/client/errors"
	"github.com/netbirdio/netbird/client/internal/statemanager"
)

const (
	envRouteProtoFlag = "NB_ROUTE_PROTO_FLAG"

	// routeBudget bounds retries for per-prefix exclusion route programming.
	routeBudget = 1 * time.Second
)

var routeProtoFlag int

func init() {
	switch os.Getenv(envRouteProtoFlag) {
	case "2":
		routeProtoFlag = unix.RTF_PROTO2
	case "3":
		routeProtoFlag = unix.RTF_PROTO3
	default:
		routeProtoFlag = unix.RTF_PROTO1
	}
}

func (r *SysOps) SetupRouting(initAddresses []net.IP, stateManager *statemanager.Manager, advancedRouting bool) error {
	if advancedRouting {
		return r.setupAdvancedRouting()
	}

	log.Infof("Using legacy routing setup with ref counters")
	return r.setupRefCounter(initAddresses, stateManager)
}

func (r *SysOps) CleanupRouting(stateManager *statemanager.Manager, advancedRouting bool) error {
	if advancedRouting {
		return r.cleanupAdvancedRouting()
	}

	return r.cleanupRefCounter(stateManager)
}

// FlushMarkedRoutes removes single IP exclusion routes marked with the configured RTF_PROTO flag.
// On darwin it also flushes residual RTF_IFSCOPE scoped default routes so a
// crashed prior session can't leave crud in the table.
func (r *SysOps) FlushMarkedRoutes() error {
	var merr *multierror.Error

	if err := r.flushPlatformExtras(); err != nil {
		merr = multierror.Append(merr, fmt.Errorf("flush platform extras: %w", err))
	}

	rib, err := retryFetchRIB()
	if err != nil {
		return nberrors.FormatErrorOrNil(multierror.Append(merr, fmt.Errorf("fetch routing table: %w", err)))
	}

	msgs, err := route.ParseRIB(route.RIBTypeRoute, rib)
	if err != nil {
		return nberrors.FormatErrorOrNil(multierror.Append(merr, fmt.Errorf("parse routing table: %w", err)))
	}

	flushedCount := 0

	for _, msg := range msgs {
		rtMsg, ok := msg.(*route.RouteMessage)
		if !ok {
			continue
		}

		if rtMsg.Flags&routeProtoFlag == 0 {
			continue
		}

		routeInfo, err := MsgToRoute(rtMsg)
		if err != nil {
			log.Debugf("Skipping route flush: %v", err)
			continue
		}

		if !routeInfo.Dst.IsValid() || !routeInfo.Dst.IsSingleIP() {
			continue
		}

		nexthop := Nexthop{
			IP:   routeInfo.Gw,
			Intf: routeInfo.Interface,
		}

		if err := r.removeFromRouteTable(routeInfo.Dst, nexthop); err != nil {
			merr = multierror.Append(merr, fmt.Errorf("remove route %s: %w", routeInfo.Dst, err))
			continue
		}

		flushedCount++
		log.Debugf("Flushed marked route: %s", routeInfo.Dst)
	}

	if flushedCount > 0 {
		log.Infof("Flushed %d residual NetBird routes from previous session", flushedCount)
	}

	return nberrors.FormatErrorOrNil(merr)
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

	msg, err := r.buildRouteMessage(action, prefix, nexthop)
	if err != nil {
		return fmt.Errorf("build route message: %w", err)
	}

	if err := r.writeRouteMessage(msg, routeBudget); err != nil {
		a := "add"
		if action == unix.RTM_DELETE {
			a = "remove"
		}
		return fmt.Errorf("%s route for %s: %w", a, prefix, err)
	}
	return nil
}

// writeRouteMessage sends a route message over AF_ROUTE and waits for the
// kernel's matching reply, retrying transient failures until budget elapses.
// Callers do not need to manage sockets or seq numbers themselves.
func (r *SysOps) writeRouteMessage(msg *route.RouteMessage, budget time.Duration) error {
	expBackOff := backoff.NewExponentialBackOff()
	expBackOff.InitialInterval = 50 * time.Millisecond
	expBackOff.MaxInterval = 500 * time.Millisecond
	expBackOff.MaxElapsedTime = budget

	return backoff.Retry(func() error { return routeMessageRoundtrip(msg) }, expBackOff)
}

func routeMessageRoundtrip(msg *route.RouteMessage) error {
	fd, err := unix.Socket(syscall.AF_ROUTE, syscall.SOCK_RAW, syscall.AF_UNSPEC)
	if err != nil {
		return fmt.Errorf("open routing socket: %w", err)
	}
	defer func() {
		if err := unix.Close(fd); err != nil && !errors.Is(err, unix.EBADF) {
			log.Warnf("close routing socket: %v", err)
		}
	}()

	tv := unix.Timeval{Sec: 1}
	if err := unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv); err != nil {
		return backoff.Permanent(fmt.Errorf("set recv timeout: %w", err))
	}

	// AF_ROUTE is a broadcast channel: every route socket on the host sees
	// every RTM_* event. With concurrent route programming the default
	// per-socket queue overflows and our own reply gets dropped.
	if err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUF, 1<<20); err != nil {
		log.Debugf("set SO_RCVBUF on route socket: %v", err)
	}

	bytes, err := msg.Marshal()
	if err != nil {
		return backoff.Permanent(fmt.Errorf("marshal: %w", err))
	}

	if _, err = unix.Write(fd, bytes); err != nil {
		if errors.Is(err, unix.ENOBUFS) || errors.Is(err, unix.EAGAIN) {
			return fmt.Errorf("write: %w", err)
		}
		return backoff.Permanent(fmt.Errorf("write: %w", err))
	}
	return readRouteResponse(fd, msg.Type, msg.Seq)
}

// readRouteResponse reads from the AF_ROUTE socket until it sees a reply
// matching our write (same type, seq, and pid). AF_ROUTE SOCK_RAW is a
// broadcast channel: interface up/down, third-party route changes and neighbor
// discovery events can all land between our write and read, so we must filter.
func readRouteResponse(fd, wantType, wantSeq int) error {
	pid := int32(os.Getpid())
	resp := make([]byte, 2048)
	deadline := time.Now().Add(time.Second)
	for {
		if time.Now().After(deadline) {
			// Transient: under concurrent pressure the kernel can drop our reply
			// from the socket buffer. Let backoff.Retry re-send with a fresh seq.
			return fmt.Errorf("read: timeout waiting for route reply type=%d seq=%d", wantType, wantSeq)
		}
		n, err := unix.Read(fd, resp)
		if err != nil {
			if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EWOULDBLOCK) {
				// SO_RCVTIMEO fired while waiting; loop to re-check the absolute deadline.
				continue
			}
			return backoff.Permanent(fmt.Errorf("read: %w", err))
		}
		if n < int(unsafe.Sizeof(unix.RtMsghdr{})) {
			continue
		}
		hdr := (*unix.RtMsghdr)(unsafe.Pointer(&resp[0]))
		// Darwin reflects the sender's pid on replies; matching (Type, Seq, Pid)
		// uniquely identifies our own reply among broadcast traffic.
		if int(hdr.Type) != wantType || int(hdr.Seq) != wantSeq || hdr.Pid != pid {
			continue
		}
		if hdr.Errno != 0 {
			return backoff.Permanent(fmt.Errorf("kernel: %w", syscall.Errno(hdr.Errno)))
		}
		return nil
	}
}

func (r *SysOps) buildRouteMessage(action int, prefix netip.Prefix, nexthop Nexthop) (msg *route.RouteMessage, err error) {
	msg = &route.RouteMessage{
		Type:    action,
		Flags:   unix.RTF_UP | routeProtoFlag,
		Version: unix.RTM_VERSION,
		ID:      uintptr(os.Getpid()),
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
