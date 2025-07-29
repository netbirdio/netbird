package net

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"

	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/windows"

	"github.com/netbirdio/netbird/client/internal/routemanager/systemops"
)

const (
	// https://learn.microsoft.com/en-us/windows/win32/winsock/ipproto-ip-socket-options
	IpUnicastIf   = 31
	Ipv6UnicastIf = 31

	// https://learn.microsoft.com/en-us/windows/win32/winsock/ipproto-ipv6-socket-options
	IPV6_V6ONLY = 27
)

// nativeToBigEndian converts a uint32 from native byte order to big-endian
func nativeToBigEndian(v uint32) uint32 {
	return (v&0xff)<<24 | (v&0xff00)<<8 | (v&0xff0000)>>8 | (v&0xff000000)>>24
}

// parseDestinationAddress parses the destination address from various formats
func parseDestinationAddress(network, address string) (netip.Addr, error) {
	if address == "" {
		if strings.HasSuffix(network, "6") {
			return netip.IPv6Unspecified(), nil
		}
		return netip.IPv4Unspecified(), nil
	}

	if addrPort, err := netip.ParseAddrPort(address); err == nil {
		return addrPort.Addr(), nil
	}

	if dest, err := netip.ParseAddr(address); err == nil {
		return dest, nil
	}

	host, _, err := net.SplitHostPort(address)
	if err != nil {
		// No port, treat whole string as host
		host = address
	}

	if host == "" {
		if strings.HasSuffix(network, "6") {
			return netip.IPv6Unspecified(), nil
		}
		return netip.IPv4Unspecified(), nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil || len(ips) == 0 {
		return netip.Addr{}, fmt.Errorf("resolve destination %s: %w", host, err)
	}

	dest, ok := netip.AddrFromSlice(ips[0].IP)
	if !ok {
		return netip.Addr{}, fmt.Errorf("convert IP %v to netip.Addr", ips[0].IP)
	}

	if ips[0].Zone != "" {
		dest = dest.WithZone(ips[0].Zone)
	}

	return dest, nil
}

func getInterfaceFromZone(zone string) *net.Interface {
	if zone == "" {
		return nil
	}

	idx, err := strconv.Atoi(zone)
	if err != nil {
		log.Debugf("invalid zone format for Windows (expected numeric): %s", zone)
		return nil
	}

	iface, err := net.InterfaceByIndex(idx)
	if err != nil {
		log.Debugf("failed to get interface by index %d from zone: %v", idx, err)
		return nil
	}

	return iface
}

type interfaceSelection struct {
	iface4 *net.Interface
	iface6 *net.Interface
}

func selectInterfaceForZone(dest netip.Addr, zone string) *interfaceSelection {
	iface := getInterfaceFromZone(zone)
	if iface == nil {
		return nil
	}

	if dest.Is6() {
		return &interfaceSelection{iface6: iface}
	}
	return &interfaceSelection{iface4: iface}
}

func selectInterfaceForUnspecified() (*interfaceSelection, error) {
	var result interfaceSelection
	vpnIfaceName := GetVPNInterfaceName()

	if iface4, err := systemops.GetBestInterface(netip.IPv4Unspecified(), vpnIfaceName); err == nil {
		result.iface4 = iface4
	} else {
		log.Debugf("No IPv4 default route found: %v", err)
	}

	if iface6, err := systemops.GetBestInterface(netip.IPv6Unspecified(), vpnIfaceName); err == nil {
		result.iface6 = iface6
	} else {
		log.Debugf("No IPv6 default route found: %v", err)
	}

	if result.iface4 == nil && result.iface6 == nil {
		return nil, errors.New("no default routes found")
	}

	return &result, nil
}

func selectInterface(dest netip.Addr) (*interfaceSelection, error) {
	if zone := dest.Zone(); zone != "" {
		if selection := selectInterfaceForZone(dest, zone); selection != nil {
			return selection, nil
		}
	}

	if dest.IsUnspecified() {
		return selectInterfaceForUnspecified()
	}

	iface, err := systemops.GetBestInterface(dest, GetVPNInterfaceName())
	if err != nil {
		return nil, fmt.Errorf("find route for %s: %w", dest, err)
	}

	if dest.Is6() {
		return &interfaceSelection{iface6: iface}, nil
	}
	return &interfaceSelection{iface4: iface}, nil
}

func setIPv4UnicastIF(fd uintptr, iface *net.Interface) error {
	ifaceIndexBE := nativeToBigEndian(uint32(iface.Index))
	if err := windows.SetsockoptInt(windows.Handle(fd), windows.IPPROTO_IP, IpUnicastIf, int(ifaceIndexBE)); err != nil {
		return fmt.Errorf("set IP_UNICAST_IF: %w (interface: %s, index: %d)", err, iface.Name, iface.Index)
	}
	return nil
}

func setIPv6UnicastIF(fd uintptr, iface *net.Interface) error {
	if err := windows.SetsockoptInt(windows.Handle(fd), windows.IPPROTO_IPV6, Ipv6UnicastIf, iface.Index); err != nil {
		return fmt.Errorf("set IPV6_UNICAST_IF: %w (interface: %s, index: %d)", err, iface.Name, iface.Index)
	}
	return nil
}

func setUnicastIf(fd uintptr, network string, selection *interfaceSelection, address string) error {
	// The Go runtime always passes specific network types to Control (udp4, udp6, tcp4, tcp6, etc.)
	// Never generic ones (udp, tcp, ip)

	switch {
	case strings.HasSuffix(network, "4"):
		// IPv4-only socket (udp4, tcp4, ip4)
		return setUnicastIfIPv4(fd, network, selection, address)

	case strings.HasSuffix(network, "6"):
		// IPv6 socket (udp6, tcp6, ip6) - could be dual-stack or IPv6-only
		return setUnicastIfIPv6(fd, network, selection, address)
	}

	// Shouldn't reach here based on Go's documented behavior
	return fmt.Errorf("unexpected network type: %s", network)
}

func setUnicastIfIPv4(fd uintptr, network string, selection *interfaceSelection, address string) error {
	if selection.iface4 == nil {
		return nil
	}

	if err := setIPv4UnicastIF(fd, selection.iface4); err != nil {
		return err
	}

	log.Debugf("Set IP_UNICAST_IF=%d on %s for %s to %s", selection.iface4.Index, selection.iface4.Name, network, address)
	return nil
}

func setUnicastIfIPv6(fd uintptr, network string, selection *interfaceSelection, address string) error {
	isDualStack := checkDualStack(fd)

	// For dual-stack sockets, also set the IPv4 option
	if isDualStack && selection.iface4 != nil {
		if err := setIPv4UnicastIF(fd, selection.iface4); err != nil {
			return err
		}
		log.Debugf("Set IP_UNICAST_IF=%d on %s for %s to %s (dual-stack)", selection.iface4.Index, selection.iface4.Name, network, address)
	}

	if selection.iface6 == nil {
		return nil
	}

	if err := setIPv6UnicastIF(fd, selection.iface6); err != nil {
		return err
	}

	log.Debugf("Set IPV6_UNICAST_IF=%d on %s for %s to %s", selection.iface6.Index, selection.iface6.Name, network, address)
	return nil
}

func checkDualStack(fd uintptr) bool {
	var v6Only int
	v6OnlyLen := int32(unsafe.Sizeof(v6Only))
	err := windows.Getsockopt(windows.Handle(fd), windows.IPPROTO_IPV6, IPV6_V6ONLY, (*byte)(unsafe.Pointer(&v6Only)), &v6OnlyLen)
	return err == nil && v6Only == 0
}

// applyUnicastIFToSocket applies IpUnicastIf to a socket based on the destination address
func applyUnicastIFToSocket(network string, address string, c syscall.RawConn) error {
	if !AdvancedRouting() {
		return nil
	}

	dest, err := parseDestinationAddress(network, address)
	if err != nil {
		return err
	}

	dest = dest.Unmap()

	if !dest.IsValid() {
		return fmt.Errorf("invalid destination address for %s", address)
	}

	selection, err := selectInterface(dest)
	if err != nil {
		return err
	}

	var controlErr error
	err = c.Control(func(fd uintptr) {
		controlErr = setUnicastIf(fd, network, selection, address)
	})

	if err != nil {
		return fmt.Errorf("control: %w", err)
	}

	return controlErr
}
