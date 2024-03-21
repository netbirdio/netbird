//go:build !android

package routemanager

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

	"github.com/netbirdio/netbird/client/internal/peer"
	"github.com/netbirdio/netbird/iface"
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
	ipv4ForwardingPath = "/proc/sys/net/ipv4/ip_forward"
)

var ErrTableIDExists = errors.New("ID exists with different name")

type ruleParams struct {
	fwmark         int
	tableID        int
	family         int
	priority       int
	invert         bool
	suppressPrefix int
	description    string
}

func getSetupRules() []ruleParams {
	return []ruleParams{
		{nbnet.NetbirdFwmark, NetbirdVPNTableID, netlink.FAMILY_V4, -1, true, -1, "add rule v4 netbird"},
		{nbnet.NetbirdFwmark, NetbirdVPNTableID, netlink.FAMILY_V6, -1, true, -1, "add rule v6 netbird"},
		{-1, syscall.RT_TABLE_MAIN, netlink.FAMILY_V4, -1, false, 0, "add rule with suppress prefixlen v4"},
		{-1, syscall.RT_TABLE_MAIN, netlink.FAMILY_V6, -1, false, 0, "add rule with suppress prefixlen v6"},
	}
}

// setupRouting establishes the routing configuration for the VPN, including essential rules
// to ensure proper traffic flow for management, locally configured routes, and VPN traffic.
//
// Rule 1 (Main Route Precedence): Safeguards locally installed routes by giving them precedence over
// potential routes received and configured for the VPN.  This rule is skipped for the default route and routes
// that are not in the main table.
//
// Rule 2 (VPN Traffic Routing): Directs all remaining traffic to the 'NetbirdVPNTableID' custom routing table.
// This table is where a default route or other specific routes received from the management server are configured,
// enabling VPN connectivity.
//
// The rules are inserted in reverse order, as rules are added from the bottom up in the rule list.
func setupRouting([]net.IP, *iface.WGIface) (_ peer.BeforeAddPeerHookFunc, _ peer.AfterRemovePeerHookFunc, err error) {
	if err = addRoutingTableName(); err != nil {
		log.Errorf("Error adding routing table name: %v", err)
	}

	defer func() {
		if err != nil {
			if cleanErr := cleanupRouting(); cleanErr != nil {
				log.Errorf("Error cleaning up routing: %v", cleanErr)
			}
		}
	}()

	rules := getSetupRules()
	for _, rule := range rules {
		if err := addRule(rule); err != nil {
			return nil, nil, fmt.Errorf("%s: %w", rule.description, err)
		}
	}

	return nil, nil, nil
}

// cleanupRouting performs a thorough cleanup of the routing configuration established by 'setupRouting'.
// It systematically removes the three rules and any associated routing table entries to ensure a clean state.
// The function uses error aggregation to report any errors encountered during the cleanup process.
func cleanupRouting() error {
	var result *multierror.Error

	if err := flushRoutes(NetbirdVPNTableID, netlink.FAMILY_V4); err != nil {
		result = multierror.Append(result, fmt.Errorf("flush routes v4: %w", err))
	}
	if err := flushRoutes(NetbirdVPNTableID, netlink.FAMILY_V6); err != nil {
		result = multierror.Append(result, fmt.Errorf("flush routes v6: %w", err))
	}

	rules := getSetupRules()
	for _, rule := range rules {
		if err := removeAllRules(rule); err != nil {
			result = multierror.Append(result, fmt.Errorf("%s: %w", rule.description, err))
		}
	}

	return result.ErrorOrNil()
}

func addToRouteTableIfNoExists(prefix netip.Prefix, _ string, intf string) error {
	// No need to check if routes exist as main table takes precedence over the VPN table via Rule 2

	// TODO remove this once we have ipv6 support
	if prefix == defaultv4 {
		if err := addUnreachableRoute(&defaultv6, NetbirdVPNTableID, netlink.FAMILY_V6); err != nil {
			return fmt.Errorf("add blackhole: %w", err)
		}
	}
	if err := addRoute(&prefix, nil, &intf, NetbirdVPNTableID, netlink.FAMILY_V4); err != nil {
		return fmt.Errorf("add route: %w", err)
	}
	return nil
}

func removeFromRouteTableIfNonSystem(prefix netip.Prefix, _ string, intf string) error {
	// TODO remove this once we have ipv6 support
	if prefix == defaultv4 {
		if err := removeUnreachableRoute(&defaultv6, NetbirdVPNTableID, netlink.FAMILY_V6); err != nil {
			return fmt.Errorf("remove unreachable route: %w", err)
		}
	}
	if err := removeRoute(&prefix, nil, &intf, NetbirdVPNTableID, netlink.FAMILY_V4); err != nil {
		return fmt.Errorf("remove route: %w", err)
	}
	return nil
}

func getRoutesFromTable() ([]netip.Prefix, error) {
	return getRoutes(NetbirdVPNTableID, netlink.FAMILY_V4)
}

// addRoute adds a route to a specific routing table identified by tableID.
func addRoute(prefix *netip.Prefix, addr, intf *string, tableID, family int) error {
	route := &netlink.Route{
		Scope:  netlink.SCOPE_UNIVERSE,
		Table:  tableID,
		Family: family,
	}

	if prefix != nil {
		_, ipNet, err := net.ParseCIDR(prefix.String())
		if err != nil {
			return fmt.Errorf("parse prefix %s: %w", prefix, err)
		}
		route.Dst = ipNet
	}

	if err := addNextHop(addr, intf, route); err != nil {
		return fmt.Errorf("add gateway and device: %w", err)
	}

	if err := netlink.RouteAdd(route); err != nil && !errors.Is(err, syscall.EEXIST) {
		return fmt.Errorf("netlink add route: %w", err)
	}

	return nil
}

// addUnreachableRoute adds an unreachable route for the specified IP family and routing table.
// ipFamily should be netlink.FAMILY_V4 for IPv4 or netlink.FAMILY_V6 for IPv6.
// tableID specifies the routing table to which the unreachable route will be added.
func addUnreachableRoute(prefix *netip.Prefix, tableID, ipFamily int) error {
	_, ipNet, err := net.ParseCIDR(prefix.String())
	if err != nil {
		return fmt.Errorf("parse prefix %s: %w", prefix, err)
	}

	route := &netlink.Route{
		Type:   syscall.RTN_UNREACHABLE,
		Table:  tableID,
		Family: ipFamily,
		Dst:    ipNet,
	}

	if err := netlink.RouteAdd(route); err != nil && !errors.Is(err, syscall.EEXIST) {
		return fmt.Errorf("netlink add unreachable route: %w", err)
	}

	return nil
}

func removeUnreachableRoute(prefix *netip.Prefix, tableID, ipFamily int) error {
	_, ipNet, err := net.ParseCIDR(prefix.String())
	if err != nil {
		return fmt.Errorf("parse prefix %s: %w", prefix, err)
	}

	route := &netlink.Route{
		Type:   syscall.RTN_UNREACHABLE,
		Table:  tableID,
		Family: ipFamily,
		Dst:    ipNet,
	}

	if err := netlink.RouteDel(route); err != nil && !errors.Is(err, syscall.ESRCH) {
		return fmt.Errorf("netlink remove unreachable route: %w", err)
	}

	return nil

}

// removeRoute removes a route from a specific routing table identified by tableID.
func removeRoute(prefix *netip.Prefix, addr, intf *string, tableID, family int) error {
	_, ipNet, err := net.ParseCIDR(prefix.String())
	if err != nil {
		return fmt.Errorf("parse prefix %s: %w", prefix, err)
	}

	route := &netlink.Route{
		Scope:  netlink.SCOPE_UNIVERSE,
		Table:  tableID,
		Family: family,
		Dst:    ipNet,
	}

	if err := addNextHop(addr, intf, route); err != nil {
		return fmt.Errorf("add gateway and device: %w", err)
	}

	if err := netlink.RouteDel(route); err != nil && !errors.Is(err, syscall.ESRCH) {
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
		if err := netlink.RouteDel(&routes[i]); err != nil {
			result = multierror.Append(result, fmt.Errorf("failed to delete route %v from table %d: %w", routes[i], tableID, err))
		}
	}

	return result.ErrorOrNil()
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

func enableIPForwarding() error {
	bytes, err := os.ReadFile(ipv4ForwardingPath)
	if err != nil {
		return fmt.Errorf("read file %s: %w", ipv4ForwardingPath, err)
	}

	// check if it is already enabled
	// see more: https://github.com/netbirdio/netbird/issues/872
	if len(bytes) > 0 && bytes[0] == 49 {
		return nil
	}

	//nolint:gosec
	if err := os.WriteFile(ipv4ForwardingPath, []byte("1"), 0644); err != nil {
		return fmt.Errorf("write file %s: %w", ipv4ForwardingPath, err)
	}
	return nil
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

	if err := netlink.RuleAdd(rule); err != nil {
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

	if err := netlink.RuleDel(rule); err != nil {
		return fmt.Errorf("remove routing rule: %w", err)
	}

	return nil
}

func removeAllRules(params ruleParams) error {
	for {
		if err := removeRule(params); err != nil {
			if errors.Is(err, syscall.ENOENT) {
				break
			}
			return err
		}
	}
	return nil
}

// addNextHop adds the gateway and device to the route.
func addNextHop(addr *string, intf *string, route *netlink.Route) error {
	if addr != nil {
		ip := net.ParseIP(*addr)
		if ip == nil {
			return fmt.Errorf("parsing address %s failed", *addr)
		}

		route.Gw = ip
	}

	if intf != nil {
		link, err := netlink.LinkByName(*intf)
		if err != nil {
			return fmt.Errorf("set interface %s: %w", *intf, err)
		}
		route.LinkIndex = link.Attrs().Index
	}

	return nil
}
