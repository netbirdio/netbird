//go:build !android

package systemops

import (
	"bufio"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"syscall"

	"github.com/hashicorp/go-multierror"
	log "github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	nberrors "github.com/netbirdio/netbird/client/errors"
	"github.com/netbirdio/netbird/client/internal/routemanager/sysctl"
	"github.com/netbirdio/netbird/client/internal/routemanager/vars"
	"github.com/netbirdio/netbird/client/internal/statemanager"
	nbnet "github.com/netbirdio/netbird/client/net"
)

// IPRule contains IP rule information for debugging
type IPRule struct {
	Priority     int
	From         netip.Prefix
	To           netip.Prefix
	IIF          string
	OIF          string
	Table        string
	Action       string
	Mark         uint32
	Mask         uint32
	TunID        uint32
	Goto         uint32
	Flow         uint32
	SuppressPlen int
	SuppressIFL  int
	Invert       bool
}

const (
	// NetbirdVPNTableID is the ID of the custom routing table used by Netbird.
	NetbirdVPNTableID = 0x1BD0
	// NetbirdVPNTableName is the name of the custom routing table used by Netbird.
	NetbirdVPNTableName = "netbird"

	// rtTablesPath is the path to the file containing the routing table names.
	rtTablesPath = "/etc/iproute2/rt_tables"

	// ipv4ForwardingPath is the path to the file containing the IP forwarding setting.
	ipv4ForwardingPath = "net.ipv4.ip_forward"
)

var ErrTableIDExists = errors.New("ID exists with different name")

const errParsePrefixMsg = "failed to parse prefix %s: %w"

// originalSysctl stores the original sysctl values before they are modified
var originalSysctl map[string]int

// sysctlFailed is used as an indicator to emit a warning when default routes are configured
var sysctlFailed bool

type ruleParams struct {
	priority       int
	fwmark         uint32
	tableID        int
	family         int
	invert         bool
	suppressPrefix int
	description    string
}

func getSetupRules() []ruleParams {
	return []ruleParams{
		{105, 0, syscall.RT_TABLE_MAIN, netlink.FAMILY_V4, false, 0, "rule with suppress prefixlen v4"},
		{105, 0, syscall.RT_TABLE_MAIN, netlink.FAMILY_V6, false, 0, "rule with suppress prefixlen v6"},
		{110, nbnet.ControlPlaneMark, NetbirdVPNTableID, netlink.FAMILY_V4, true, -1, "rule v4 netbird"},
		{110, nbnet.ControlPlaneMark, NetbirdVPNTableID, netlink.FAMILY_V6, true, -1, "rule v6 netbird"},
	}
}

// SetupRouting establishes the routing configuration for the VPN, including essential rules
// to ensure proper traffic flow for management, locally configured routes, and VPN traffic.
//
// Rule 1 (Main Route Precedence): Safeguards locally installed routes by giving them precedence over
// potential routes received and configured for the VPN.  This rule is skipped for the default route and routes
// that are not in the main table.
//
// Rule 2 (VPN Traffic Routing): Directs all remaining traffic to the 'NetbirdVPNTableID' custom routing table.
// This table is where a default route or other specific routes received from the management server are configured,
// enabling VPN connectivity.
func (r *SysOps) SetupRouting(initAddresses []net.IP, stateManager *statemanager.Manager, advancedRouting bool) (err error) {
	if !advancedRouting {
		log.Infof("Using legacy routing setup")
		return r.setupRefCounter(initAddresses, stateManager)
	}

	defer func() {
		if err != nil {
			if cleanErr := r.CleanupRouting(stateManager, advancedRouting); cleanErr != nil {
				log.Errorf("Error cleaning up routing: %v", cleanErr)
			}
		}
	}()

	rules := getSetupRules()
	for _, rule := range rules {
		if err := addRule(rule); err != nil {
			return fmt.Errorf("%s: %w", rule.description, err)
		}
	}

	if err = addRoutingTableName(); err != nil {
		log.Errorf("Error adding routing table name: %v", err)
	}

	originalValues, err := sysctl.Setup(r.wgInterface)
	if err != nil {
		log.Errorf("Error setting up sysctl: %v", err)
		sysctlFailed = true
	}
	originalSysctl = originalValues

	return nil
}

// CleanupRouting performs a thorough cleanup of the routing configuration established by 'setupRouting'.
// It systematically removes the three rules and any associated routing table entries to ensure a clean state.
// The function uses error aggregation to report any errors encountered during the cleanup process.
func (r *SysOps) CleanupRouting(stateManager *statemanager.Manager, advancedRouting bool) error {
	if !advancedRouting {
		return r.cleanupRefCounter(stateManager)
	}

	var result *multierror.Error

	if err := flushRoutes(NetbirdVPNTableID, netlink.FAMILY_V4); err != nil {
		result = multierror.Append(result, fmt.Errorf("flush routes v4: %w", err))
	}
	if err := flushRoutes(NetbirdVPNTableID, netlink.FAMILY_V6); err != nil {
		result = multierror.Append(result, fmt.Errorf("flush routes v6: %w", err))
	}

	rules := getSetupRules()
	for _, rule := range rules {
		if err := removeRule(rule); err != nil {
			result = multierror.Append(result, fmt.Errorf("%s: %w", rule.description, err))
		}
	}

	if err := sysctl.Cleanup(originalSysctl); err != nil {
		result = multierror.Append(result, fmt.Errorf("cleanup sysctl: %w", err))
	}
	originalSysctl = nil
	sysctlFailed = false

	return nberrors.FormatErrorOrNil(result)
}

func (r *SysOps) addToRouteTable(prefix netip.Prefix, nexthop Nexthop) error {
	return addRoute(prefix, nexthop, syscall.RT_TABLE_MAIN)
}

func (r *SysOps) removeFromRouteTable(prefix netip.Prefix, nexthop Nexthop) error {
	return removeRoute(prefix, nexthop, syscall.RT_TABLE_MAIN)
}

func (r *SysOps) AddVPNRoute(prefix netip.Prefix, intf *net.Interface) error {
	if err := r.validateRoute(prefix); err != nil {
		return err
	}

	if !nbnet.AdvancedRouting() {
		return r.genericAddVPNRoute(prefix, intf)
	}

	if sysctlFailed && (prefix == vars.Defaultv4 || prefix == vars.Defaultv6) {
		log.Warnf("Default route is configured but sysctl operations failed, VPN traffic may not be routed correctly, consider using NB_USE_LEGACY_ROUTING=true or setting net.ipv4.conf.*.rp_filter to 2 (loose) or 0 (off)")
	}

	// No need to check if routes exist as main table takes precedence over the VPN table via Rule 1

	// TODO remove this once we have ipv6 support
	if prefix == vars.Defaultv4 {
		if err := addUnreachableRoute(vars.Defaultv6, NetbirdVPNTableID); err != nil {
			return fmt.Errorf("add blackhole: %w", err)
		}
	}
	if err := addRoute(prefix, Nexthop{netip.Addr{}, intf}, NetbirdVPNTableID); err != nil {
		return fmt.Errorf("add route: %w", err)
	}
	return nil
}

func (r *SysOps) RemoveVPNRoute(prefix netip.Prefix, intf *net.Interface) error {
	if err := r.validateRoute(prefix); err != nil {
		return err
	}

	if !nbnet.AdvancedRouting() {
		return r.genericRemoveVPNRoute(prefix, intf)
	}

	// TODO remove this once we have ipv6 support
	if prefix == vars.Defaultv4 {
		if err := removeUnreachableRoute(vars.Defaultv6, NetbirdVPNTableID); err != nil {
			return fmt.Errorf("remove unreachable route: %w", err)
		}
	}
	if err := removeRoute(prefix, Nexthop{netip.Addr{}, intf}, NetbirdVPNTableID); err != nil {
		return fmt.Errorf("remove route: %w", err)
	}
	return nil
}

func GetRoutesFromTable() ([]netip.Prefix, error) {
	v4Routes, err := getRoutes(syscall.RT_TABLE_MAIN, netlink.FAMILY_V4)
	if err != nil {
		return nil, fmt.Errorf("get v4 routes: %w", err)
	}
	v6Routes, err := getRoutes(syscall.RT_TABLE_MAIN, netlink.FAMILY_V6)
	if err != nil {
		return nil, fmt.Errorf("get v6 routes: %w", err)

	}
	return append(v4Routes, v6Routes...), nil
}

// GetDetailedRoutesFromTable returns detailed route information from all routing tables
func GetDetailedRoutesFromTable() ([]DetailedRoute, error) {
	tables := discoverRoutingTables()
	return collectRoutesFromTables(tables), nil
}

func discoverRoutingTables() []int {
	tables, err := getAllRoutingTables()
	if err != nil {
		log.Warnf("Failed to get all routing tables, using fallback list: %v", err)
		return []int{
			syscall.RT_TABLE_MAIN,
			syscall.RT_TABLE_LOCAL,
			NetbirdVPNTableID,
		}
	}
	return tables
}

func collectRoutesFromTables(tables []int) []DetailedRoute {
	var allRoutes []DetailedRoute

	for _, tableID := range tables {
		routes := collectRoutesFromTable(tableID)
		allRoutes = append(allRoutes, routes...)
	}

	return allRoutes
}

func collectRoutesFromTable(tableID int) []DetailedRoute {
	var routes []DetailedRoute

	if v4Routes := getRoutesForFamily(tableID, netlink.FAMILY_V4); len(v4Routes) > 0 {
		routes = append(routes, v4Routes...)
	}

	if v6Routes := getRoutesForFamily(tableID, netlink.FAMILY_V6); len(v6Routes) > 0 {
		routes = append(routes, v6Routes...)
	}

	return routes
}

func getRoutesForFamily(tableID, family int) []DetailedRoute {
	routes, err := getDetailedRoutes(tableID, family)
	if err != nil {
		log.Debugf("Failed to get routes from table %d family %d: %v", tableID, family, err)
		return nil
	}
	return routes
}

func getAllRoutingTables() ([]int, error) {
	tablesMap := make(map[int]bool)
	families := []int{netlink.FAMILY_V4, netlink.FAMILY_V6}

	// Use table 0 (RT_TABLE_UNSPEC) to discover all tables
	for _, family := range families {
		routes, err := netlink.RouteListFiltered(family, &netlink.Route{Table: 0}, netlink.RT_FILTER_TABLE)
		if err != nil {
			log.Debugf("Failed to list routes from table 0 for family %d: %v", family, err)
			continue
		}

		// Extract unique table IDs from all routes
		for _, route := range routes {
			if route.Table > 0 {
				tablesMap[route.Table] = true
			}
		}
	}

	var tables []int
	for tableID := range tablesMap {
		tables = append(tables, tableID)
	}

	standardTables := []int{syscall.RT_TABLE_MAIN, syscall.RT_TABLE_LOCAL, NetbirdVPNTableID}
	for _, table := range standardTables {
		if !tablesMap[table] {
			tables = append(tables, table)
		}
	}

	return tables, nil
}

// getDetailedRoutes fetches detailed routes from a specific routing table
func getDetailedRoutes(tableID, family int) ([]DetailedRoute, error) {
	var detailedRoutes []DetailedRoute

	routes, err := netlink.RouteListFiltered(family, &netlink.Route{Table: tableID}, netlink.RT_FILTER_TABLE)
	if err != nil {
		return nil, fmt.Errorf("list routes from table %d: %v", tableID, err)
	}

	for _, route := range routes {
		detailed := buildDetailedRoute(route, tableID, family)
		if detailed != nil {
			detailedRoutes = append(detailedRoutes, *detailed)
		}
	}

	return detailedRoutes, nil
}

func buildDetailedRoute(route netlink.Route, tableID, family int) *DetailedRoute {
	detailed := DetailedRoute{
		Route:           Route{},
		Metric:          route.Priority,
		InterfaceMetric: -1, // Interface metrics not typically used on Linux
		InterfaceIndex:  route.LinkIndex,
		Protocol:        routeProtocolToString(int(route.Protocol)),
		Scope:           routeScopeToString(route.Scope),
		Type:            routeTypeToString(route.Type),
		Table:           routeTableToString(tableID),
		Flags:           "-",
	}

	if !processRouteDestination(&detailed, route, family) {
		return nil
	}

	processRouteGateway(&detailed, route)

	processRouteInterface(&detailed, route)

	return &detailed
}

func processRouteDestination(detailed *DetailedRoute, route netlink.Route, family int) bool {
	if route.Dst != nil {
		addr, ok := netip.AddrFromSlice(route.Dst.IP)
		if !ok {
			return false
		}
		ones, _ := route.Dst.Mask.Size()
		prefix := netip.PrefixFrom(addr.Unmap(), ones)
		if prefix.IsValid() {
			detailed.Route.Dst = prefix
		} else {
			return false
		}
	} else {
		if family == netlink.FAMILY_V4 {
			detailed.Route.Dst = netip.MustParsePrefix("0.0.0.0/0")
		} else {
			detailed.Route.Dst = netip.MustParsePrefix("::/0")
		}
	}
	return true
}

func processRouteGateway(detailed *DetailedRoute, route netlink.Route) {
	if route.Gw != nil {
		if gateway, ok := netip.AddrFromSlice(route.Gw); ok {
			detailed.Route.Gw = gateway.Unmap()
		}
	}
}

func processRouteInterface(detailed *DetailedRoute, route netlink.Route) {
	if route.LinkIndex > 0 {
		if link, err := netlink.LinkByIndex(route.LinkIndex); err == nil {
			detailed.Route.Interface = &net.Interface{
				Index: link.Attrs().Index,
				Name:  link.Attrs().Name,
			}
		} else {
			detailed.Route.Interface = &net.Interface{
				Index: route.LinkIndex,
				Name:  fmt.Sprintf("index-%d", route.LinkIndex),
			}
		}
	}
}

// Helper functions to convert netlink constants to strings
func routeProtocolToString(protocol int) string {
	switch protocol {
	case syscall.RTPROT_UNSPEC:
		return "unspec"
	case syscall.RTPROT_REDIRECT:
		return "redirect"
	case syscall.RTPROT_KERNEL:
		return "kernel"
	case syscall.RTPROT_BOOT:
		return "boot"
	case syscall.RTPROT_STATIC:
		return "static"
	case syscall.RTPROT_DHCP:
		return "dhcp"
	case unix.RTPROT_RA:
		return "ra"
	case unix.RTPROT_ZEBRA:
		return "zebra"
	case unix.RTPROT_BIRD:
		return "bird"
	case unix.RTPROT_DNROUTED:
		return "dnrouted"
	case unix.RTPROT_XORP:
		return "xorp"
	case unix.RTPROT_NTK:
		return "ntk"
	default:
		return fmt.Sprintf("%d", protocol)
	}
}

func routeScopeToString(scope netlink.Scope) string {
	switch scope {
	case netlink.SCOPE_UNIVERSE:
		return "global"
	case netlink.SCOPE_SITE:
		return "site"
	case netlink.SCOPE_LINK:
		return "link"
	case netlink.SCOPE_HOST:
		return "host"
	case netlink.SCOPE_NOWHERE:
		return "nowhere"
	default:
		return fmt.Sprintf("%d", scope)
	}
}

func routeTypeToString(routeType int) string {
	switch routeType {
	case syscall.RTN_UNSPEC:
		return "unspec"
	case syscall.RTN_UNICAST:
		return "unicast"
	case syscall.RTN_LOCAL:
		return "local"
	case syscall.RTN_BROADCAST:
		return "broadcast"
	case syscall.RTN_ANYCAST:
		return "anycast"
	case syscall.RTN_MULTICAST:
		return "multicast"
	case syscall.RTN_BLACKHOLE:
		return "blackhole"
	case syscall.RTN_UNREACHABLE:
		return "unreachable"
	case syscall.RTN_PROHIBIT:
		return "prohibit"
	case syscall.RTN_THROW:
		return "throw"
	case syscall.RTN_NAT:
		return "nat"
	case syscall.RTN_XRESOLVE:
		return "xresolve"
	default:
		return fmt.Sprintf("%d", routeType)
	}
}

func routeTableToString(tableID int) string {
	switch tableID {
	case syscall.RT_TABLE_MAIN:
		return "main"
	case syscall.RT_TABLE_LOCAL:
		return "local"
	case NetbirdVPNTableID:
		return "netbird"
	default:
		return fmt.Sprintf("%d", tableID)
	}
}

// getRoutes fetches routes from a specific routing table identified by tableID.
func getRoutes(tableID, family int) ([]netip.Prefix, error) {
	var prefixList []netip.Prefix

	routes, err := netlink.RouteListFiltered(family, &netlink.Route{Table: tableID}, netlink.RT_FILTER_TABLE)
	if err != nil {
		return nil, fmt.Errorf("list routes from table %d: %v", tableID, err)
	}

	for _, route := range routes {
		if route.Dst != nil {
			addr, ok := netip.AddrFromSlice(route.Dst.IP)
			if !ok {
				return nil, fmt.Errorf("parse route destination IP: %v", route.Dst.IP)
			}

			ones, _ := route.Dst.Mask.Size()

			prefix := netip.PrefixFrom(addr.Unmap(), ones)
			if prefix.IsValid() {
				prefixList = append(prefixList, prefix)
			}
		}
	}

	return prefixList, nil
}

// GetIPRules returns IP rules for debugging
func GetIPRules() ([]IPRule, error) {
	v4Rules, err := getIPRules(netlink.FAMILY_V4)
	if err != nil {
		return nil, fmt.Errorf("get v4 rules: %w", err)
	}
	v6Rules, err := getIPRules(netlink.FAMILY_V6)
	if err != nil {
		return nil, fmt.Errorf("get v6 rules: %w", err)
	}
	return append(v4Rules, v6Rules...), nil
}

// getIPRules fetches IP rules for the specified address family
func getIPRules(family int) ([]IPRule, error) {
	rules, err := netlink.RuleList(family)
	if err != nil {
		return nil, fmt.Errorf("list rules for family %d: %w", family, err)
	}

	var ipRules []IPRule
	for _, rule := range rules {
		ipRule := buildIPRule(rule)
		ipRules = append(ipRules, ipRule)
	}

	return ipRules, nil
}

func buildIPRule(rule netlink.Rule) IPRule {
	var mask uint32
	if rule.Mask != nil {
		mask = *rule.Mask
	}

	ipRule := IPRule{
		Priority:     rule.Priority,
		IIF:          rule.IifName,
		OIF:          rule.OifName,
		Table:        ruleTableToString(rule.Table),
		Action:       ruleActionToString(int(rule.Type)),
		Mark:         rule.Mark,
		Mask:         mask,
		TunID:        uint32(rule.TunID),
		Goto:         uint32(rule.Goto),
		Flow:         uint32(rule.Flow),
		SuppressPlen: rule.SuppressPrefixlen,
		SuppressIFL:  rule.SuppressIfgroup,
		Invert:       rule.Invert,
	}

	if rule.Src != nil {
		ipRule.From = parseRulePrefix(rule.Src)
	}

	if rule.Dst != nil {
		ipRule.To = parseRulePrefix(rule.Dst)
	}

	return ipRule
}

func parseRulePrefix(ipNet *net.IPNet) netip.Prefix {
	if addr, ok := netip.AddrFromSlice(ipNet.IP); ok {
		ones, _ := ipNet.Mask.Size()
		prefix := netip.PrefixFrom(addr.Unmap(), ones)
		if prefix.IsValid() {
			return prefix
		}
	}
	return netip.Prefix{}
}

func ruleTableToString(table int) string {
	switch table {
	case syscall.RT_TABLE_MAIN:
		return "main"
	case syscall.RT_TABLE_LOCAL:
		return "local"
	case syscall.RT_TABLE_DEFAULT:
		return "default"
	case NetbirdVPNTableID:
		return "netbird"
	default:
		return fmt.Sprintf("%d", table)
	}
}

func ruleActionToString(action int) string {
	switch action {
	case unix.FR_ACT_UNSPEC:
		return "unspec"
	case unix.FR_ACT_TO_TBL:
		return "lookup"
	case unix.FR_ACT_GOTO:
		return "goto"
	case unix.FR_ACT_NOP:
		return "nop"
	case unix.FR_ACT_BLACKHOLE:
		return "blackhole"
	case unix.FR_ACT_UNREACHABLE:
		return "unreachable"
	case unix.FR_ACT_PROHIBIT:
		return "prohibit"
	default:
		return fmt.Sprintf("%d", action)
	}
}

// addRoute adds a route to a specific routing table identified by tableID.
func addRoute(prefix netip.Prefix, nexthop Nexthop, tableID int) error {
	route := &netlink.Route{
		Scope:  netlink.SCOPE_UNIVERSE,
		Table:  tableID,
		Family: getAddressFamily(prefix),
	}

	_, ipNet, err := net.ParseCIDR(prefix.String())
	if err != nil {
		return fmt.Errorf(errParsePrefixMsg, prefix, err)
	}
	route.Dst = ipNet

	if err := addNextHop(nexthop, route); err != nil {
		return fmt.Errorf("add gateway and device: %w", err)
	}

	if err := netlink.RouteAdd(route); err != nil && !isOpErr(err) {
		return fmt.Errorf("netlink add route: %w", err)
	}

	return nil
}

// addUnreachableRoute adds an unreachable route for the specified IP family and routing table.
// ipFamily should be netlink.FAMILY_V4 for IPv4 or netlink.FAMILY_V6 for IPv6.
// tableID specifies the routing table to which the unreachable route will be added.
func addUnreachableRoute(prefix netip.Prefix, tableID int) error {
	_, ipNet, err := net.ParseCIDR(prefix.String())
	if err != nil {
		return fmt.Errorf(errParsePrefixMsg, prefix, err)
	}

	route := &netlink.Route{
		Type:   syscall.RTN_UNREACHABLE,
		Table:  tableID,
		Family: getAddressFamily(prefix),
		Dst:    ipNet,
	}

	if err := netlink.RouteAdd(route); err != nil && !isOpErr(err) {
		return fmt.Errorf("netlink add unreachable route: %w", err)
	}

	return nil
}

func removeUnreachableRoute(prefix netip.Prefix, tableID int) error {
	_, ipNet, err := net.ParseCIDR(prefix.String())
	if err != nil {
		return fmt.Errorf(errParsePrefixMsg, prefix, err)
	}

	route := &netlink.Route{
		Type:   syscall.RTN_UNREACHABLE,
		Table:  tableID,
		Family: getAddressFamily(prefix),
		Dst:    ipNet,
	}

	if err := netlink.RouteDel(route); err != nil &&
		!errors.Is(err, syscall.ESRCH) &&
		!errors.Is(err, syscall.ENOENT) &&
		!isOpErr(err) {
		return fmt.Errorf("netlink remove unreachable route: %w", err)
	}

	return nil

}

// removeRoute removes a route from a specific routing table identified by tableID.
func removeRoute(prefix netip.Prefix, nexthop Nexthop, tableID int) error {
	_, ipNet, err := net.ParseCIDR(prefix.String())
	if err != nil {
		return fmt.Errorf(errParsePrefixMsg, prefix, err)
	}

	route := &netlink.Route{
		Scope:  netlink.SCOPE_UNIVERSE,
		Table:  tableID,
		Family: getAddressFamily(prefix),
		Dst:    ipNet,
	}

	if err := addNextHop(nexthop, route); err != nil {
		return fmt.Errorf("add gateway and device: %w", err)
	}

	if err := netlink.RouteDel(route); err != nil && !errors.Is(err, syscall.ESRCH) && !isOpErr(err) {
		return fmt.Errorf("netlink remove route: %w", err)
	}

	return nil
}

func flushRoutes(tableID, family int) error {
	routes, err := netlink.RouteListFiltered(family, &netlink.Route{Table: tableID}, netlink.RT_FILTER_TABLE)
	if err != nil {
		return fmt.Errorf("list routes from table %d: %w", tableID, err)
	}

	var result *multierror.Error
	for i := range routes {
		route := routes[i]
		// unreachable default routes don't come back with Dst set
		if route.Gw == nil && route.Src == nil && route.Dst == nil {
			if family == netlink.FAMILY_V4 {
				routes[i].Dst = &net.IPNet{IP: net.IPv4zero, Mask: net.CIDRMask(0, 32)}
			} else {
				routes[i].Dst = &net.IPNet{IP: net.IPv6zero, Mask: net.CIDRMask(0, 128)}
			}
		}
		if err := netlink.RouteDel(&routes[i]); err != nil && !isOpErr(err) {
			result = multierror.Append(result, fmt.Errorf("failed to delete route %v from table %d: %w", routes[i], tableID, err))
		}
	}

	return nberrors.FormatErrorOrNil(result)
}

func EnableIPForwarding() error {
	_, err := sysctl.Set(ipv4ForwardingPath, 1, false)
	return err
}

// entryExists checks if the specified ID or name already exists in the rt_tables file
// and verifies if existing names start with "netbird_".
func entryExists(file *os.File, id int) (bool, error) {
	if _, err := file.Seek(0, 0); err != nil {
		return false, fmt.Errorf("seek rt_tables: %w", err)
	}
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		var existingID int
		var existingName string
		if _, err := fmt.Sscanf(line, "%d %s\n", &existingID, &existingName); err == nil {
			if existingID == id {
				if existingName != NetbirdVPNTableName {
					return true, ErrTableIDExists
				}
				return true, nil
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return false, fmt.Errorf("scan rt_tables: %w", err)
	}
	return false, nil
}

// addRoutingTableName adds human-readable names for custom routing tables.
func addRoutingTableName() error {
	file, err := os.Open(rtTablesPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("open rt_tables: %w", err)
	}
	defer func() {
		if err := file.Close(); err != nil {
			log.Errorf("Error closing rt_tables: %v", err)
		}
	}()

	exists, err := entryExists(file, NetbirdVPNTableID)
	if err != nil {
		return fmt.Errorf("verify entry %d, %s: %w", NetbirdVPNTableID, NetbirdVPNTableName, err)
	}
	if exists {
		return nil
	}

	// Reopen the file in append mode to add new entries
	if err := file.Close(); err != nil {
		log.Errorf("Error closing rt_tables before appending: %v", err)
	}
	file, err = os.OpenFile(rtTablesPath, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0644)
	if err != nil {
		return fmt.Errorf("open rt_tables for appending: %w", err)
	}

	if _, err := file.WriteString(fmt.Sprintf("\n%d\t%s\n", NetbirdVPNTableID, NetbirdVPNTableName)); err != nil {
		return fmt.Errorf("append entry to rt_tables: %w", err)
	}

	return nil
}

// addRule adds a routing rule to a specific routing table identified by tableID.
func addRule(params ruleParams) error {
	rule := netlink.NewRule()
	rule.Table = params.tableID
	rule.Mark = params.fwmark
	rule.Family = params.family
	rule.Priority = params.priority
	rule.Invert = params.invert
	rule.SuppressPrefixlen = params.suppressPrefix

	if err := netlink.RuleAdd(rule); err != nil && !errors.Is(err, syscall.EEXIST) && !isOpErr(err) {
		return fmt.Errorf("add routing rule: %w", err)
	}

	return nil
}

// removeRule removes a routing rule from a specific routing table identified by tableID.
func removeRule(params ruleParams) error {
	rule := netlink.NewRule()
	rule.Table = params.tableID
	rule.Mark = params.fwmark
	rule.Family = params.family
	rule.Invert = params.invert
	rule.Priority = params.priority
	rule.SuppressPrefixlen = params.suppressPrefix

	if err := netlink.RuleDel(rule); err != nil && !errors.Is(err, syscall.ENOENT) && !isOpErr(err) {
		return fmt.Errorf("remove routing rule: %w", err)
	}

	return nil
}

// addNextHop adds the gateway and device to the route.
func addNextHop(nexthop Nexthop, route *netlink.Route) error {
	if nexthop.Intf != nil {
		route.LinkIndex = nexthop.Intf.Index
	}

	if nexthop.IP.IsValid() {
		route.Gw = nexthop.IP.AsSlice()

		// if zone is set, it means the gateway is a link-local address, so we set the link index
		if nexthop.IP.Zone() != "" && nexthop.Intf == nil {
			link, err := netlink.LinkByName(nexthop.IP.Zone())
			if err != nil {
				return fmt.Errorf("get link by name for zone %s: %w", nexthop.IP.Zone(), err)
			}
			route.LinkIndex = link.Attrs().Index
		}
	}

	return nil
}

func getAddressFamily(prefix netip.Prefix) int {
	if prefix.Addr().Is4() {
		return netlink.FAMILY_V4
	}
	return netlink.FAMILY_V6
}

func hasSeparateRouting() ([]netip.Prefix, error) {
	if !nbnet.AdvancedRouting() {
		return GetRoutesFromTable()
	}
	return nil, ErrRoutingIsSeparate
}

func isOpErr(err error) bool {
	// EAFTNOSUPPORT when ipv6 is disabled via sysctl, EOPNOTSUPP when disabled in boot options or otherwise not supported
	if errors.Is(err, syscall.EAFNOSUPPORT) || errors.Is(err, syscall.EOPNOTSUPP) {
		log.Debugf("route operation not supported: %v", err)
		return true
	}

	return false
}
