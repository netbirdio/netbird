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

	log "github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"

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

var defaultv4 = netip.PrefixFrom(netip.IPv4Unspecified(), 0)
var defaultv6 = netip.PrefixFrom(netip.IPv6Unspecified(), 0)

// setupDefaultRouting sets up the default routing for the VPN.
func setupDefaultRouting(intf string) (err error) {
	defer func() {
		if err != nil {
			if cleanErr := cleanupDefaultRouting(intf); cleanErr != nil {
				log.Errorf("Error cleaning up default routing: %v", cleanErr)
			}
		}
	}()

	if err = addRoutingTableName(); err != nil {
		log.Errorf("Error adding routing table name: %v", err)
	}

	if err = addRoute(&defaultv4, nil, &intf, NetbirdVPNTableID, netlink.FAMILY_V4); err != nil {
		return fmt.Errorf("add route v4: %w", err)
	}

	// TODO: Change this to a normal route once we have ipv6 support
	if err = addBlackholeRoute(&defaultv6, NetbirdVPNTableID, netlink.FAMILY_V6); err != nil {
		return fmt.Errorf("add blackhole route v6: %w", err)
	}

	if err = addRule(nbnet.NetbirdFwmark, NetbirdVPNTableID, netlink.FAMILY_V4, -1, true); err != nil {
		return fmt.Errorf("add rule v4: %w", err)
	}
	if err = addRule(nbnet.NetbirdFwmark, NetbirdVPNTableID, netlink.FAMILY_V6, -1, true); err != nil {
		return fmt.Errorf("add rule v6: %w", err)
	}

	if err = addRuleWithSuppressPrefixlen(syscall.RT_TABLE_MAIN, netlink.FAMILY_V4, 0); err != nil {
		return fmt.Errorf("add rule with suppress prefixlen v4: %w", err)
	}

	if err = addRuleWithSuppressPrefixlen(syscall.RT_TABLE_MAIN, netlink.FAMILY_V6, 0); err != nil {
		return fmt.Errorf("add rule with suppress prefixlen v6: %w", err)
	}

	log.Infof("Default routing setup complete")

	return nil
}

func cleanupDefaultRouting(intf string) error {
	var errs []error

	if err := removeRoute(&defaultv4, nil, &intf, NetbirdVPNTableID, netlink.FAMILY_V4); err != nil {
		errs = append(errs, fmt.Errorf("remove route v4: %w", err))
	}

	if err := removeBlackholeRoute(&defaultv6, NetbirdVPNTableID, netlink.FAMILY_V6); err != nil {
		errs = append(errs, fmt.Errorf("remove blackhole route v6: %w", err))
	}

	if err := removeRule(nbnet.NetbirdFwmark, NetbirdVPNTableID, netlink.FAMILY_V4, -1, true); err != nil {
		errs = append(errs, fmt.Errorf("remove rule v4: %w", err))
	}

	if err := removeRule(nbnet.NetbirdFwmark, NetbirdVPNTableID, netlink.FAMILY_V6, -1, true); err != nil {
		errs = append(errs, fmt.Errorf("remove rule v6: %w", err))
	}

	if err := removeSuppressedPrefixRule(syscall.RT_TABLE_MAIN, netlink.FAMILY_V4, 0); err != nil {
		errs = append(errs, fmt.Errorf("remove rule with suppress prefixlen v4: %w", err))
	}

	if err := removeSuppressedPrefixRule(syscall.RT_TABLE_MAIN, netlink.FAMILY_V6, 0); err != nil {
		errs = append(errs, fmt.Errorf("remove rule with suppress prefixlen v6: %w", err))
	}

	if len(errs) > 0 {
		var combinedErr error
		for _, err := range errs {
			if combinedErr == nil {
				combinedErr = err
			} else {
				combinedErr = fmt.Errorf("%v; %w", combinedErr, err)
			}
		}
		return combinedErr
	}

	log.Infof("Default routing cleanup complete")

	return nil
}

func addToRouteTable(prefix netip.Prefix, addr string) error {
	return addRoute(&prefix, &addr, nil, syscall.RT_TABLE_MAIN, netlink.FAMILY_V4)
}

func removeFromRouteTable(prefix netip.Prefix, addr string) error {
	return removeRoute(&prefix, &addr, nil, syscall.RT_TABLE_MAIN, netlink.FAMILY_V4)
}

func getRoutesFromTable() ([]netip.Prefix, error) {
	return getRoutes(syscall.RT_TABLE_MAIN, netlink.FAMILY_V4)
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

	if err := netlink.RouteAdd(route); err != nil {
		return fmt.Errorf("netlink add route: %w", err)
	}

	return nil
}

// addBlackholeRoute adds a blackhole route for the specified IP family and routing table.
// ipFamily should be netlink.FAMILY_V4 for IPv4 or netlink.FAMILY_V6 for IPv6.
// tableID specifies the routing table to which the blackhole route will be added.
func addBlackholeRoute(prefix *netip.Prefix, tableID, ipFamily int) error {
	route := &netlink.Route{
		Type:   syscall.RTN_BLACKHOLE,
		Table:  tableID,
		Family: ipFamily,
	}

	if prefix != nil {
		_, ipNet, err := net.ParseCIDR(prefix.String())
		if err != nil {
			return fmt.Errorf("parse prefix %s: %w", prefix, err)
		}
		route.Dst = ipNet
	}

	if err := netlink.RouteAdd(route); err != nil {
		return fmt.Errorf("netlink add blackhole route: %w", err)
	}

	return nil
}

func removeBlackholeRoute(prefix *netip.Prefix, tableID, ipFamily int) error {
	route := &netlink.Route{
		Type:   syscall.RTN_BLACKHOLE,
		Table:  tableID,
		Family: ipFamily,
	}

	if prefix != nil {
		_, ipNet, err := net.ParseCIDR(prefix.String())
		if err != nil {
			return fmt.Errorf("parse prefix %s: %w", prefix, err)
		}
		route.Dst = ipNet
	}

	if err := netlink.RouteDel(route); err != nil {
		return fmt.Errorf("netlink remove blackhole route: %w", err)
	}

	return nil

}

// removeRoute removes a route from a specific routing table identified by tableID.
func removeRoute(prefix *netip.Prefix, addr, intf *string, tableID, family int) error {
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

	if err := netlink.RouteDel(route); err != nil {
		return fmt.Errorf("netlink remove route: %w", err)
	}

	return nil
}

func flushRoutes(tableID, family int) error {
	routes, err := netlink.RouteListFiltered(family, &netlink.Route{Table: tableID}, netlink.RT_FILTER_TABLE)
	if err != nil {
		return fmt.Errorf("failed to list routes from table %d: %w", tableID, err)
	}

	for _, route := range routes {
		if err := netlink.RouteDel(&route); err != nil {
			return fmt.Errorf("failed to delete route %v from table %d: %w", route, tableID, err)
		}
	}
	return nil
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
func addRule(fwmark, tableID, family, priority int, invert bool) error {
	rule := netlink.NewRule()
	rule.Table = tableID
	rule.Mark = fwmark
	rule.Family = family
	rule.Priority = priority
	rule.Invert = invert

	if err := netlink.RuleAdd(rule); err != nil {
		return fmt.Errorf("add routing rule: %w", err)
	}

	return nil
}

// removeRule removes a routing rule from a specific routing table identified by tableID.
func removeRule(fwmark, tableID, family, priority int, invert bool) error {
	rule := netlink.NewRule()
	rule.Table = tableID
	rule.Mark = fwmark
	rule.Family = family
	rule.Invert = invert
	rule.Priority = priority

	if err := netlink.RuleDel(rule); err != nil {
		return fmt.Errorf("remove routing rule: %w", err)
	}

	return nil
}

func addRuleWithSuppressPrefixlen(tableID, family, prefixLength int) error {
	rule := netlink.NewRule()
	rule.Table = tableID
	rule.Family = family
	rule.SuppressPrefixlen = prefixLength

	if err := netlink.RuleAdd(rule); err != nil {
		return fmt.Errorf("add routing rule with suppressed prefix: %w", err)
	}

	return nil
}

func removeSuppressedPrefixRule(tableID, family, prefixLength int) error {
	rule := netlink.NewRule()
	rule.Table = tableID
	rule.Family = family
	rule.SuppressPrefixlen = prefixLength

	if err := netlink.RuleDel(rule); err != nil {
		return fmt.Errorf("remove routing rule: %w", err)
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
