package net

import (
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"syscall"

	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
)

// On darwin IPV6_BOUND_IF also scopes v4-mapped egress from dual-stack
// (IPV6_V6ONLY=0) AF_INET6 sockets, so a single setsockopt on "udp6"/"tcp6"
// covers both families. Setting IP_BOUND_IF on an AF_INET6 socket returns
// EINVAL regardless of V6ONLY because the IPPROTO_IP ctloutput path is
// dispatched by socket domain (AF_INET only) not by inp_vflag.

// boundIface holds the physical interface chosen at routing setup time. Sockets
// created via nbnet.NewDialer / nbnet.NewListener bind to it via IP_BOUND_IF
// (IPv4) or IPV6_BOUND_IF (IPv6 / dual-stack) so their scoped route lookup
// hits the RTF_IFSCOPE default installed by the routemanager, rather than
// following the VPN's split default.
var (
	boundIfaceMu sync.RWMutex
	boundIface4  *net.Interface
	boundIface6  *net.Interface
)

// SetBoundInterface records the egress interface for an address family. Called
// by the routemanager after a scoped default route has been installed.
// af must be unix.AF_INET or unix.AF_INET6; other values are ignored.
// nil iface is rejected — use ClearBoundInterfaces to clear all slots.
func SetBoundInterface(af int, iface *net.Interface) {
	if iface == nil {
		log.Warnf("SetBoundInterface: nil iface for AF %d, ignored", af)
		return
	}
	boundIfaceMu.Lock()
	defer boundIfaceMu.Unlock()
	switch af {
	case unix.AF_INET:
		boundIface4 = iface
	case unix.AF_INET6:
		boundIface6 = iface
	default:
		log.Warnf("SetBoundInterface: unsupported address family %d", af)
	}
}

// ClearBoundInterfaces resets the cached egress interfaces. Called by the
// routemanager during cleanup.
func ClearBoundInterfaces() {
	boundIfaceMu.Lock()
	defer boundIfaceMu.Unlock()
	boundIface4 = nil
	boundIface6 = nil
}

// boundInterfaceFor returns the cached egress interface for a socket's address
// family, falling back to the other family if the preferred slot is empty.
// The kernel stores both IP_BOUND_IF and IPV6_BOUND_IF in inp_boundifp, so
// either setsockopt scopes the socket; preferring same-family still matters
// when v4 and v6 defaults egress different NICs.
func boundInterfaceFor(network, address string) *net.Interface {
	if iface := zoneInterface(address); iface != nil {
		return iface
	}

	boundIfaceMu.RLock()
	defer boundIfaceMu.RUnlock()

	primary, secondary := boundIface4, boundIface6
	if isV6Network(network) {
		primary, secondary = boundIface6, boundIface4
	}
	if primary != nil {
		return primary
	}
	return secondary
}

func isV6Network(network string) bool {
	return strings.HasSuffix(network, "6")
}

// zoneInterface extracts an explicit interface from an IPv6 link-local zone (e.g. fe80::1%en0).
func zoneInterface(address string) *net.Interface {
	if address == "" {
		return nil
	}
	addr, err := netip.ParseAddrPort(address)
	if err != nil {
		a, err := netip.ParseAddr(address)
		if err != nil {
			return nil
		}
		addr = netip.AddrPortFrom(a, 0)
	}
	zone := addr.Addr().Zone()
	if zone == "" {
		return nil
	}
	if iface, err := net.InterfaceByName(zone); err == nil {
		return iface
	}
	if idx, err := strconv.Atoi(zone); err == nil {
		if iface, err := net.InterfaceByIndex(idx); err == nil {
			return iface
		}
	}
	return nil
}

func setIPv4BoundIf(fd uintptr, iface *net.Interface) error {
	if err := unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_BOUND_IF, iface.Index); err != nil {
		return fmt.Errorf("set IP_BOUND_IF: %w (interface: %s, index: %d)", err, iface.Name, iface.Index)
	}
	return nil
}

func setIPv6BoundIf(fd uintptr, iface *net.Interface) error {
	if err := unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_BOUND_IF, iface.Index); err != nil {
		return fmt.Errorf("set IPV6_BOUND_IF: %w (interface: %s, index: %d)", err, iface.Name, iface.Index)
	}
	return nil
}

// applyBoundIfToSocket binds the socket to the cached physical egress interface
// so scoped route lookup avoids the VPN utun and egresses the underlay directly.
func applyBoundIfToSocket(network, address string, c syscall.RawConn) error {
	if !AdvancedRouting() {
		return nil
	}

	iface := boundInterfaceFor(network, address)
	if iface == nil {
		log.Debugf("no bound iface cached for %s to %s, skipping BOUND_IF", network, address)
		return nil
	}

	isV6 := isV6Network(network)
	var controlErr error
	if err := c.Control(func(fd uintptr) {
		if isV6 {
			controlErr = setIPv6BoundIf(fd, iface)
		} else {
			controlErr = setIPv4BoundIf(fd, iface)
		}
		if controlErr == nil {
			log.Debugf("set BOUND_IF=%d on %s for %s to %s", iface.Index, iface.Name, network, address)
		}
	}); err != nil {
		return fmt.Errorf("control: %w", err)
	}
	return controlErr
}
