package systemops

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"os"
	"runtime/debug"
	"strconv"
	"sync"
	"syscall"
	"time"
	"unsafe"

	log "github.com/sirupsen/logrus"
	"github.com/yusufpapurcu/wmi"
	"golang.org/x/sys/windows"

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

// luid represents a locally unique identifier for network interfaces
type luid uint64

// MIB_IPFORWARD_ROW2 represents a route entry in the routing table.
// It is defined in https://learn.microsoft.com/en-us/windows/win32/api/netioapi/ns-netioapi-mib_ipforward_row2
type MIB_IPFORWARD_ROW2 struct {
	InterfaceLuid        luid
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
	modiphlpapi                     = windows.NewLazyDLL("iphlpapi.dll")
	procNotifyRouteChange2          = modiphlpapi.NewProc("NotifyRouteChange2")
	procCancelMibChangeNotify2      = modiphlpapi.NewProc("CancelMibChangeNotify2")
	procCreateIpForwardEntry2       = modiphlpapi.NewProc("CreateIpForwardEntry2")
	procDeleteIpForwardEntry2       = modiphlpapi.NewProc("DeleteIpForwardEntry2")
	procGetIpForwardEntry2          = modiphlpapi.NewProc("GetIpForwardEntry2")
	procInitializeIpForwardEntry    = modiphlpapi.NewProc("InitializeIpForwardEntry")
	procConvertInterfaceIndexToLuid = modiphlpapi.NewProc("ConvertInterfaceIndexToLuid")

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
	// if we don't have an interface but a zone, extract the interface index from the zone
	if nexthop.IP.Zone() != "" && nexthop.Intf == nil {
		zone, err := strconv.Atoi(nexthop.IP.Zone())
		if err != nil {
			return fmt.Errorf("invalid zone: %w", err)
		}
		nexthop.Intf = &net.Interface{Index: zone}
	}

	return addRoute(prefix, nexthop)
}

func (r *SysOps) removeFromRouteTable(prefix netip.Prefix, nexthop Nexthop) error {
	return deleteRoute(prefix, nexthop)
}

// setupRouteEntry prepares a route entry with common configuration
func setupRouteEntry(prefix netip.Prefix, nexthop Nexthop) (*MIB_IPFORWARD_ROW2, error) {
	route := &MIB_IPFORWARD_ROW2{}

	initializeIPForwardEntry(route)

	// Convert interface index to luid if interface is specified
	if nexthop.Intf != nil {
		var luid luid
		if err := convertInterfaceIndexToLUID(uint32(nexthop.Intf.Index), &luid); err != nil {
			return nil, fmt.Errorf("convert interface index to luid: %w", err)
		}
		route.InterfaceLuid = luid
		route.InterfaceIndex = uint32(nexthop.Intf.Index)
	}

	if err := setDestinationPrefix(&route.DestinationPrefix, prefix); err != nil {
		return nil, fmt.Errorf("set destination prefix: %w", err)
	}

	if nexthop.IP.IsValid() {
		if err := setNextHop(&route.NextHop, nexthop.IP); err != nil {
			return nil, fmt.Errorf("set next hop: %w", err)
		}
	}

	return route, nil
}

// addRoute adds a route using Windows iphelper APIs
func addRoute(prefix netip.Prefix, nexthop Nexthop) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("panic in addRoute: %v, stack trace: %s", r, debug.Stack())
		}
	}()

	route, setupErr := setupRouteEntry(prefix, nexthop)
	if setupErr != nil {
		return fmt.Errorf("setup route entry: %w", setupErr)
	}

	route.Metric = 1
	route.ValidLifetime = 0xffffffff
	route.PreferredLifetime = 0xffffffff

	return createIPForwardEntry2(route)
}

// deleteRoute deletes a route using Windows iphelper APIs
func deleteRoute(prefix netip.Prefix, nexthop Nexthop) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("panic in deleteRoute: %v, stack trace: %s", r, debug.Stack())
		}
	}()

	route, setupErr := setupRouteEntry(prefix, nexthop)
	if setupErr != nil {
		return fmt.Errorf("setup route entry: %w", setupErr)
	}

	if err := getIPForwardEntry2(route); err != nil {
		return fmt.Errorf("get route entry: %w", err)
	}

	return deleteIPForwardEntry2(route)
}

// setDestinationPrefix sets the destination prefix in the route structure
func setDestinationPrefix(prefix *IP_ADDRESS_PREFIX, dest netip.Prefix) error {
	addr := dest.Addr()
	prefix.PrefixLength = uint8(dest.Bits())

	if addr.Is4() {
		prefix.Prefix.sin6_family = windows.AF_INET
		ip4 := addr.As4()
		binary.BigEndian.PutUint32(prefix.Prefix.data[:4],
			uint32(ip4[0])<<24|uint32(ip4[1])<<16|uint32(ip4[2])<<8|uint32(ip4[3]))
		return nil
	}

	if addr.Is6() {
		prefix.Prefix.sin6_family = windows.AF_INET6
		ip6 := addr.As16()
		copy(prefix.Prefix.data[4:20], ip6[:])

		if zone := addr.Zone(); zone != "" {
			if scopeID, err := strconv.ParseUint(zone, 10, 32); err == nil {
				binary.BigEndian.PutUint32(prefix.Prefix.data[20:24], uint32(scopeID))
			}
		}
		return nil
	}

	return fmt.Errorf("invalid address family")
}

// setNextHop sets the next hop address in the route structure
func setNextHop(nextHop *SOCKADDR_INET_NEXTHOP, addr netip.Addr) error {
	if addr.Is4() {
		nextHop.sin6_family = windows.AF_INET
		ip4 := addr.As4()
		binary.BigEndian.PutUint32(nextHop.data[:4],
			uint32(ip4[0])<<24|uint32(ip4[1])<<16|uint32(ip4[2])<<8|uint32(ip4[3]))
		return nil
	}

	if addr.Is6() {
		nextHop.sin6_family = windows.AF_INET6
		ip6 := addr.As16()
		copy(nextHop.data[4:20], ip6[:])

		// Handle zone if present
		if zone := addr.Zone(); zone != "" {
			if scopeID, err := strconv.ParseUint(zone, 10, 32); err == nil {
				binary.BigEndian.PutUint32(nextHop.data[20:24], uint32(scopeID))
			}
		}
		return nil
	}

	return fmt.Errorf("invalid address family")
}

// Windows API wrappers
func createIPForwardEntry2(route *MIB_IPFORWARD_ROW2) error {
	r1, _, e1 := syscall.SyscallN(procCreateIpForwardEntry2.Addr(), uintptr(unsafe.Pointer(route)))
	if r1 != 0 {
		if e1 != 0 {
			return fmt.Errorf("CreateIpForwardEntry2: %w", e1)
		}
		return fmt.Errorf("CreateIpForwardEntry2: code %d", r1)
	}
	return nil
}

func deleteIPForwardEntry2(route *MIB_IPFORWARD_ROW2) error {
	r1, _, e1 := syscall.SyscallN(procDeleteIpForwardEntry2.Addr(), uintptr(unsafe.Pointer(route)))
	if r1 != 0 {
		if e1 != 0 {
			return fmt.Errorf("DeleteIpForwardEntry2: %w", e1)
		}
		return fmt.Errorf("DeleteIpForwardEntry2: code %d", r1)
	}
	return nil
}

func getIPForwardEntry2(route *MIB_IPFORWARD_ROW2) error {
	r1, _, e1 := syscall.SyscallN(procGetIpForwardEntry2.Addr(), uintptr(unsafe.Pointer(route)))
	if r1 != 0 {
		if e1 != 0 {
			return fmt.Errorf("GetIpForwardEntry2: %w", e1)
		}
		return fmt.Errorf("GetIpForwardEntry2: code %d", r1)
	}
	return nil
}

// https://learn.microsoft.com/en-us/windows/win32/api/netioapi/nf-netioapi-initializeipforwardentry
func initializeIPForwardEntry(route *MIB_IPFORWARD_ROW2) {
	// Does not return anything. Trying to handle the error might return an uninitialized value.
	_, _, _ = syscall.SyscallN(procInitializeIpForwardEntry.Addr(), uintptr(unsafe.Pointer(route)))
}

func convertInterfaceIndexToLUID(interfaceIndex uint32, interfaceLUID *luid) error {
	r1, _, e1 := syscall.SyscallN(procConvertInterfaceIndexToLuid.Addr(),
		uintptr(interfaceIndex), uintptr(unsafe.Pointer(interfaceLUID)))
	if r1 != 0 {
		if e1 != 0 {
			return fmt.Errorf("ConvertInterfaceIndexToLuid: %w", e1)
		}
		return fmt.Errorf("ConvertInterfaceIndexToLuid: code %d", r1)
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
