//go:build windows

package systemops

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	log "github.com/sirupsen/logrus"
	"github.com/yusufpapurcu/wmi"
	"golang.org/x/sys/windows"

	"github.com/netbirdio/netbird/client/firewall/uspfilter"
	"github.com/netbirdio/netbird/client/internal/statemanager"
	nbnet "github.com/netbirdio/netbird/util/net"
)

type RouteUpdateType int

// RouteUpdate represents a change in the routing table.
// The interface field contains the index only.
type RouteUpdate struct {
	Type        RouteUpdateType
	Destination netip.Prefix
	NextHop     Nexthop
}

// RouteMonitor provides a way to monitor changes in the routing table.
type RouteMonitor struct {
	updates chan RouteUpdate
	handle  windows.Handle
	done    chan struct{}
}

// Route represents a single routing table entry.
type Route struct {
	Destination netip.Prefix
	Nexthop     netip.Addr
	Interface   *net.Interface
}

type MSFT_NetRoute struct {
	DestinationPrefix string
	NextHop           string
	InterfaceIndex    int32
	InterfaceAlias    string
	AddressFamily     uint16
}

// MIB_IPFORWARD_ROW2 is defined in https://learn.microsoft.com/en-us/windows/win32/api/netioapi/ns-netioapi-mib_ipforward_row2
type MIB_IPFORWARD_ROW2 struct {
	InterfaceLuid        uint64
	InterfaceIndex       uint32
	DestinationPrefix    IP_ADDRESS_PREFIX
	NextHop              SOCKADDR_INET_NEXTHOP
	SitePrefixLength     uint8
	ValidLifetime        uint32
	PreferredLifetime    uint32
	Metric               uint32
	Protocol             uint32
	Loopback             uint8
	AutoconfigureAddress uint8
	Publish              uint8
	Immortal             uint8
	Age                  uint32
	Origin               uint32
}

// IP_ADDRESS_PREFIX is defined in https://learn.microsoft.com/en-us/windows/win32/api/netioapi/ns-netioapi-ip_address_prefix
type IP_ADDRESS_PREFIX struct {
	Prefix       SOCKADDR_INET
	PrefixLength uint8
}

// SOCKADDR_INET is defined in https://learn.microsoft.com/en-us/windows/win32/api/ws2ipdef/ns-ws2ipdef-sockaddr_inet
// It represents the union of IPv4 and IPv6 socket addresses
type SOCKADDR_INET struct {
	sin6_family int16
	// nolint:unused
	sin6_port uint16
	// 4 bytes ipv4 or 4 bytes flowinfo + 16 bytes ipv6 + 4 bytes scope_id
	data [24]byte
}

// SOCKADDR_INET_NEXTHOP is the same as SOCKADDR_INET but offset by 2 bytes
type SOCKADDR_INET_NEXTHOP struct {
	// nolint:unused
	pad         [2]byte
	sin6_family int16
	// nolint:unused
	sin6_port uint16
	// 4 bytes ipv4 or 4 bytes flowinfo + 16 bytes ipv6 + 4 bytes scope_id
	data [24]byte
}

// MIB_NOTIFICATION_TYPE is defined in https://learn.microsoft.com/en-us/windows/win32/api/netioapi/ne-netioapi-mib_notification_type
type MIB_NOTIFICATION_TYPE int32

var (
	modiphlpapi                = windows.NewLazyDLL("iphlpapi.dll")
	procNotifyRouteChange2     = modiphlpapi.NewProc("NotifyRouteChange2")
	procCancelMibChangeNotify2 = modiphlpapi.NewProc("CancelMibChangeNotify2")

	prefixList []netip.Prefix
	lastUpdate time.Time
	mux        sync.Mutex
)

const (
	MibParemeterModification MIB_NOTIFICATION_TYPE = iota
	MibAddInstance
	MibDeleteInstance
	MibInitialNotification
)

const (
	RouteModified RouteUpdateType = iota
	RouteAdded
	RouteDeleted
)

func (r *SysOps) SetupRouting(initAddresses []net.IP, stateManager *statemanager.Manager) (nbnet.AddHookFunc, nbnet.RemoveHookFunc, error) {
	return r.setupRefCounter(initAddresses, stateManager)
}

func (r *SysOps) CleanupRouting(stateManager *statemanager.Manager) error {
	return r.cleanupRefCounter(stateManager)
}

func (r *SysOps) addToRouteTable(prefix netip.Prefix, nexthop Nexthop) error {
	if nexthop.IP.Zone() != "" && nexthop.Intf == nil {
		zone, err := strconv.Atoi(nexthop.IP.Zone())
		if err != nil {
			return fmt.Errorf("invalid zone: %w", err)
		}
		nexthop.Intf = &net.Interface{Index: zone}
	}

	return addRouteCmd(prefix, nexthop)
}

func (r *SysOps) removeFromRouteTable(prefix netip.Prefix, nexthop Nexthop) error {
	args := []string{"delete", prefix.String()}
	if nexthop.IP.IsValid() {
		ip := nexthop.IP.WithZone("")
		args = append(args, ip.Unmap().String())
	}

	routeCmd := uspfilter.GetSystem32Command("route")

	out, err := exec.Command(routeCmd, args...).CombinedOutput()
	log.Tracef("route %s: %s", strings.Join(args, " "), out)

	if err != nil {
		return fmt.Errorf("remove route: %w", err)
	}
	return nil
}

// NewRouteMonitor creates and starts a new RouteMonitor.
// It returns a pointer to the RouteMonitor and an error if the monitor couldn't be started.
func NewRouteMonitor(ctx context.Context) (*RouteMonitor, error) {
	rm := &RouteMonitor{
		updates: make(chan RouteUpdate, 5),
		done:    make(chan struct{}),
	}

	if err := rm.start(ctx); err != nil {
		return nil, err
	}

	return rm, nil
}

func (rm *RouteMonitor) start(ctx context.Context) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}

	callbackPtr := windows.NewCallback(func(callerContext uintptr, row *MIB_IPFORWARD_ROW2, notificationType MIB_NOTIFICATION_TYPE) uintptr {
		if ctx.Err() != nil {
			return 0
		}

		update, err := rm.parseUpdate(row, notificationType)
		if err != nil {
			log.Errorf("Failed to parse route update: %v", err)
			return 0
		}

		select {
		case <-rm.done:
			return 0
		case rm.updates <- update:
		default:
			log.Warn("Route update channel is full, dropping update")
		}
		return 0
	})

	var handle windows.Handle
	if err := notifyRouteChange2(windows.AF_UNSPEC, callbackPtr, 0, false, &handle); err != nil {
		return fmt.Errorf("NotifyRouteChange2 failed: %w", err)
	}

	rm.handle = handle

	return nil
}

func (rm *RouteMonitor) parseUpdate(row *MIB_IPFORWARD_ROW2, notificationType MIB_NOTIFICATION_TYPE) (RouteUpdate, error) {
	// destination prefix, next hop, interface index, interface luid are guaranteed to be there
	// GetIpForwardEntry2 is not needed

	var update RouteUpdate

	idx := int(row.InterfaceIndex)
	if idx != 0 {
		intf, err := net.InterfaceByIndex(idx)
		if err != nil {
			log.Warnf("failed to get interface name for index %d: %v", idx, err)
			update.NextHop.Intf = &net.Interface{
				Index: idx,
			}
		} else {
			update.NextHop.Intf = intf
		}
	}

	log.Tracef("Received route update with destination %v, next hop %v, interface %v", row.DestinationPrefix, row.NextHop, update.NextHop.Intf)
	dest := parseIPPrefix(row.DestinationPrefix, idx)
	if !dest.Addr().IsValid() {
		return RouteUpdate{}, fmt.Errorf("invalid destination: %v", row)
	}

	nexthop := parseIPNexthop(row.NextHop, idx)
	if !nexthop.IsValid() {
		return RouteUpdate{}, fmt.Errorf("invalid next hop %v", row)
	}

	updateType := RouteModified
	switch notificationType {
	case MibParemeterModification:
		updateType = RouteModified
	case MibAddInstance:
		updateType = RouteAdded
	case MibDeleteInstance:
		updateType = RouteDeleted
	}

	update.Type = updateType
	update.Destination = dest
	update.NextHop.IP = nexthop

	return update, nil
}

// Stop stops the RouteMonitor.
func (rm *RouteMonitor) Stop() error {
	if rm.handle != 0 {
		if err := cancelMibChangeNotify2(rm.handle); err != nil {
			return fmt.Errorf("CancelMibChangeNotify2 failed: %w", err)
		}
		rm.handle = 0
	}
	close(rm.done)
	close(rm.updates)
	return nil
}

// RouteUpdates returns a channel that receives RouteUpdate messages.
func (rm *RouteMonitor) RouteUpdates() <-chan RouteUpdate {
	return rm.updates
}

func notifyRouteChange2(family uint32, callback uintptr, callerContext uintptr, initialNotification bool, handle *windows.Handle) error {
	var initNotif uint32
	if initialNotification {
		initNotif = 1
	}

	r1, _, e1 := syscall.SyscallN(
		procNotifyRouteChange2.Addr(),
		uintptr(family),
		callback,
		callerContext,
		uintptr(initNotif),
		uintptr(unsafe.Pointer(handle)),
	)
	if r1 != 0 {
		if e1 != 0 {
			return e1
		}
		return syscall.EINVAL
	}
	return nil
}

func cancelMibChangeNotify2(handle windows.Handle) error {
	r1, _, e1 := syscall.SyscallN(procCancelMibChangeNotify2.Addr(), uintptr(handle))
	if r1 != 0 {
		if e1 != 0 {
			return e1
		}
		return syscall.EINVAL
	}
	return nil
}

// GetRoutesFromTable returns the current routing table from with prefixes only.
// It ccaches the result for 2 seconds to avoid blocking the caller.
func GetRoutesFromTable() ([]netip.Prefix, error) {
	mux.Lock()
	defer mux.Unlock()

	// If many routes are added at the same time this might block for a long time (seconds to minutes), so we cache the result
	if !isCacheDisabled() && time.Since(lastUpdate) < 2*time.Second {
		return prefixList, nil
	}

	routes, err := GetRoutes()
	if err != nil {
		return nil, fmt.Errorf("get routes: %w", err)
	}

	prefixList = nil
	for _, route := range routes {
		prefixList = append(prefixList, route.Destination)
	}

	lastUpdate = time.Now()
	return prefixList, nil
}

// GetRoutes retrieves the current routing table using WMI.
func GetRoutes() ([]Route, error) {
	var entries []MSFT_NetRoute

	query := `SELECT DestinationPrefix, Nexthop, InterfaceIndex, InterfaceAlias, AddressFamily FROM MSFT_NetRoute`
	if err := wmi.QueryNamespace(query, &entries, `ROOT\StandardCimv2`); err != nil {
		return nil, fmt.Errorf("get routes: %w", err)
	}

	var routes []Route
	for _, entry := range entries {
		dest, err := netip.ParsePrefix(entry.DestinationPrefix)
		if err != nil {
			log.Warnf("Unable to parse route destination %s: %v", entry.DestinationPrefix, err)
			continue
		}

		nexthop, err := netip.ParseAddr(entry.NextHop)
		if err != nil {
			log.Warnf("Unable to parse route next hop %s: %v", entry.NextHop, err)
			continue
		}

		var intf *net.Interface
		if entry.InterfaceIndex != 0 {
			intf = &net.Interface{
				Index: int(entry.InterfaceIndex),
				Name:  entry.InterfaceAlias,
			}

			if nexthop.Is6() {
				nexthop = addZone(nexthop, int(entry.InterfaceIndex))
			}
		}

		routes = append(routes, Route{
			Destination: dest,
			Nexthop:     nexthop,
			Interface:   intf,
		})
	}

	return routes, nil
}

func addRouteCmd(prefix netip.Prefix, nexthop Nexthop) error {
	args := []string{"add", prefix.String()}

	if nexthop.IP.IsValid() {
		ip := nexthop.IP.WithZone("")
		args = append(args, ip.Unmap().String())
	} else {
		addr := "0.0.0.0"
		if prefix.Addr().Is6() {
			addr = "::"
		}
		args = append(args, addr)
	}

	if nexthop.Intf != nil {
		args = append(args, "if", strconv.Itoa(nexthop.Intf.Index))
	}

	routeCmd := uspfilter.GetSystem32Command("route")

	out, err := exec.Command(routeCmd, args...).CombinedOutput()
	log.Tracef("route %s: %s", strings.Join(args, " "), out)
	if err != nil {
		return fmt.Errorf("route add: %w", err)
	}

	return nil
}

func isCacheDisabled() bool {
	return os.Getenv("NB_DISABLE_ROUTE_CACHE") == "true"
}

func parseIPPrefix(prefix IP_ADDRESS_PREFIX, idx int) netip.Prefix {
	ip := parseIP(prefix.Prefix, idx)
	return netip.PrefixFrom(ip, int(prefix.PrefixLength))
}

func parseIP(addr SOCKADDR_INET, idx int) netip.Addr {
	return parseIPGeneric(addr.sin6_family, addr.data, idx)
}

func parseIPNexthop(addr SOCKADDR_INET_NEXTHOP, idx int) netip.Addr {
	return parseIPGeneric(addr.sin6_family, addr.data, idx)
}

func parseIPGeneric(family int16, data [24]byte, interfaceIndex int) netip.Addr {
	switch family {
	case windows.AF_INET:
		ipv4 := binary.BigEndian.Uint32(data[:4])
		return netip.AddrFrom4([4]byte{
			byte(ipv4 >> 24),
			byte(ipv4 >> 16),
			byte(ipv4 >> 8),
			byte(ipv4),
		})

	case windows.AF_INET6:
		// The IPv6 address is stored after the 4-byte flowinfo field
		var ipv6 [16]byte
		copy(ipv6[:], data[4:20])
		ip := netip.AddrFrom16(ipv6)

		// Check if there's a non-zero scope_id
		scopeID := binary.BigEndian.Uint32(data[20:24])
		if scopeID != 0 {
			ip = ip.WithZone(strconv.FormatUint(uint64(scopeID), 10))
		} else if interfaceIndex != 0 {
			ip = addZone(ip, interfaceIndex)
		}

		return ip
	}

	return netip.IPv4Unspecified()
}

func addZone(ip netip.Addr, interfaceIndex int) netip.Addr {
	if ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		ip = ip.WithZone(strconv.Itoa(interfaceIndex))
	}
	return ip
}
