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

	nberrors "github.com/netbirdio/netbird/client/errors"
	"github.com/netbirdio/netbird/client/internal/routemanager/sysctl"
	"github.com/netbirdio/netbird/client/internal/routemanager/vars"
	"github.com/netbirdio/netbird/client/internal/statemanager"
	nbnet "github.com/netbirdio/netbird/util/net"
)

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

// originalSysctl stores the original sysctl values before they are modified
var originalSysctl map[string]int

// sysctlFailed is used as an indicator to emit a warning when default routes are configured
var sysctlFailed bool

type ruleParams struct {
	priority       int
	fwmark         int
	tableID        int
	family         int
	invert         bool
	suppressPrefix int
	description    string
}

// isLegacy determines whether to use the legacy routing setup
func isLegacy() bool {
	return os.Getenv("NB_USE_LEGACY_ROUTING") == "true" || nbnet.CustomRoutingDisabled() || nbnet.SkipSocketMark()
}

// setIsLegacy sets the legacy routing setup
func setIsLegacy(b bool) {
	if b {
		os.Setenv("NB_USE_LEGACY_ROUTING", "true")
	} else {
		os.Unsetenv("NB_USE_LEGACY_ROUTING")
	}
}

func getSetupRules() []ruleParams {
	return []ruleParams{
		{100, -1, syscall.RT_TABLE_MAIN, netlink.FAMILY_V4, false, 0, "rule with suppress prefixlen v4"},
		{100, -1, syscall.RT_TABLE_MAIN, netlink.FAMILY_V6, false, 0, "rule with suppress prefixlen v6"},
		{110, nbnet.NetbirdFwmark, NetbirdVPNTableID, netlink.FAMILY_V4, true, -1, "rule v4 netbird"},
		{110, nbnet.NetbirdFwmark, NetbirdVPNTableID, netlink.FAMILY_V6, true, -1, "rule v6 netbird"},
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
func (r *SysOps) SetupRouting(initAddresses []net.IP, stateManager *statemanager.Manager) (_ nbnet.AddHookFunc, _ nbnet.RemoveHookFunc, err error) {
	if isLegacy() {
		log.Infof("Using legacy routing setup")
		return r.setupRefCounter(initAddresses, stateManager)
	}

	defer func() {
		if err != nil {
			if cleanErr := r.CleanupRouting(stateManager); cleanErr != nil {
				log.Errorf("Error cleaning up routing: %v", cleanErr)
			}
		}
	}()

	rules := getSetupRules()
	for _, rule := range rules {
		if err := addRule(rule); err != nil {
			if errors.Is(err, syscall.EOPNOTSUPP) {
				log.Warnf("Rule operations are not supported, falling back to the legacy routing setup")
				setIsLegacy(true)
				return r.setupRefCounter(initAddresses, stateManager)
			}
			return nil, nil, fmt.Errorf("%s: %w", rule.description, err)
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

	return nil, nil, nil
}

// CleanupRouting performs a thorough cleanup of the routing configuration established by 'setupRouting'.
// It systematically removes the three rules and any associated routing table entries to ensure a clean state.
// The function uses error aggregation to report any errors encountered during the cleanup process.
func (r *SysOps) CleanupRouting(stateManager *statemanager.Manager) error {
	if isLegacy() {
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
	if isLegacy() {
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
	if isLegacy() {
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

			prefix := netip.PrefixFrom(addr, ones)
			if prefix.IsValid() {
				prefixList = append(prefixList, prefix)
			}
		}
	}

	return prefixList, nil
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
		return fmt.Errorf("parse prefix %s: %w", prefix, err)
	}
	route.Dst = ipNet

	if err := addNextHop(nexthop, route); err != nil {
		return fmt.Errorf("add gateway and device: %w", err)
	}

	if err := netlink.RouteAdd(route); err != nil && !errors.Is(err, syscall.EEXIST) && !errors.Is(err, syscall.EAFNOSUPPORT) {
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
		return fmt.Errorf("parse prefix %s: %w", prefix, err)
	}

	route := &netlink.Route{
		Type:   syscall.RTN_UNREACHABLE,
		Table:  tableID,
		Family: getAddressFamily(prefix),
		Dst:    ipNet,
	}

	if err := netlink.RouteAdd(route); err != nil && !errors.Is(err, syscall.EEXIST) && !errors.Is(err, syscall.EAFNOSUPPORT) {
		return fmt.Errorf("netlink add unreachable route: %w", err)
	}

	return nil
}

func removeUnreachableRoute(prefix netip.Prefix, tableID int) error {
	_, ipNet, err := net.ParseCIDR(prefix.String())
	if err != nil {
		return fmt.Errorf("parse prefix %s: %w", prefix, err)
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
		!errors.Is(err, syscall.EAFNOSUPPORT) {
		return fmt.Errorf("netlink remove unreachable route: %w", err)
	}

	return nil

}

// removeRoute removes a route from a specific routing table identified by tableID.
func removeRoute(prefix netip.Prefix, nexthop Nexthop, tableID int) error {
	_, ipNet, err := net.ParseCIDR(prefix.String())
	if err != nil {
		return fmt.Errorf("parse prefix %s: %w", prefix, err)
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

	if err := netlink.RouteDel(route); err != nil && !errors.Is(err, syscall.ESRCH) && !errors.Is(err, syscall.EAFNOSUPPORT) {
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
		if err := netlink.RouteDel(&routes[i]); err != nil && !errors.Is(err, syscall.EAFNOSUPPORT) {
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

	if err := netlink.RuleAdd(rule); err != nil && !errors.Is(err, syscall.EEXIST) {
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

	if err := netlink.RuleDel(rule); err != nil && !errors.Is(err, syscall.ENOENT) {
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
	if isLegacy() {
		return GetRoutesFromTable()
	}
	return nil, ErrRoutingIsSeparate
}
