//go:build !android && !ios

package systemops

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"runtime"
	"strconv"
	"time"

	"github.com/hashicorp/go-multierror"
	"github.com/libp2p/go-netroute"
	log "github.com/sirupsen/logrus"

	nberrors "github.com/netbirdio/netbird/client/errors"
	"github.com/netbirdio/netbird/client/iface/netstack"
	"github.com/netbirdio/netbird/client/internal/routemanager/refcounter"
	"github.com/netbirdio/netbird/client/internal/routemanager/util"
	"github.com/netbirdio/netbird/client/internal/routemanager/vars"
	"github.com/netbirdio/netbird/client/internal/statemanager"
	"github.com/netbirdio/netbird/client/net/hooks"
)

const localSubnetsCacheTTL = 15 * time.Minute

var splitDefaultv4_1 = netip.PrefixFrom(netip.IPv4Unspecified(), 1)
var splitDefaultv4_2 = netip.PrefixFrom(netip.AddrFrom4([4]byte{128}), 1)
var splitDefaultv6_1 = netip.PrefixFrom(netip.IPv6Unspecified(), 1)
var splitDefaultv6_2 = netip.PrefixFrom(netip.AddrFrom16([16]byte{0x80}), 1)

var ErrRoutingIsSeparate = errors.New("routing is separate")

func (r *SysOps) setupRefCounter(initAddresses []net.IP, stateManager *statemanager.Manager) error {
	stateManager.RegisterState(&ShutdownState{})

	initialNextHopV4, err := GetNextHop(netip.IPv4Unspecified())
	if err != nil && !errors.Is(err, vars.ErrRouteNotFound) {
		log.Errorf("Unable to get initial v4 default next hop: %v", err)
	}
	initialNextHopV6, err := GetNextHop(netip.IPv6Unspecified())
	if err != nil && !errors.Is(err, vars.ErrRouteNotFound) {
		log.Errorf("Unable to get initial v6 default next hop: %v", err)
	}

	refCounter := refcounter.New(
		func(prefix netip.Prefix, _ struct{}) (Nexthop, error) {
			initialNexthop := initialNextHopV4
			if prefix.Addr().Is6() {
				initialNexthop = initialNextHopV6
			}

			nexthop, err := r.addRouteToNonVPNIntf(prefix, r.wgInterface, initialNexthop)
			if errors.Is(err, vars.ErrRouteNotAllowed) || errors.Is(err, vars.ErrRouteNotFound) {
				log.Tracef("Adding for prefix %s: %v", prefix, err)
				// These errors are not critical, but also we should not track and try to remove the routes either.
				return nexthop, refcounter.ErrIgnore
			}

			return nexthop, err
		},
		r.removeFromRouteTable,
	)

	if netstack.IsEnabled() {
		refCounter = refcounter.New(
			func(netip.Prefix, struct{}) (Nexthop, error) {
				return Nexthop{}, refcounter.ErrIgnore
			},
			func(netip.Prefix, Nexthop) error {
				return nil
			},
		)
	}

	r.refCounter = refCounter

	if err := r.setupHooks(initAddresses, stateManager); err != nil {
		return fmt.Errorf("setup hooks: %w", err)
	}
	return nil
}

// updateState updates state on every change so it will be persisted regularly
func (r *SysOps) updateState(stateManager *statemanager.Manager) {
	if err := stateManager.UpdateState((*ShutdownState)(r.refCounter)); err != nil {
		log.Errorf("failed to update state: %v", err)
	}
}

func (r *SysOps) cleanupRefCounter(stateManager *statemanager.Manager) error {
	if r.refCounter == nil {
		return nil
	}

	hooks.RemoveWriteHooks()
	hooks.RemoveCloseHooks()
	hooks.RemoveAddressRemoveHooks()

	if err := r.refCounter.Flush(); err != nil {
		return fmt.Errorf("flush route manager: %w", err)
	}

	if err := stateManager.DeleteState(&ShutdownState{}); err != nil {
		return fmt.Errorf("delete state: %w", err)
	}

	return nil
}

// addRouteToNonVPNIntf adds a new route to the routing table for the given prefix and returns the next hop and interface.
// If the next hop or interface is pointing to the VPN interface, it will return the initial values.
func (r *SysOps) addRouteToNonVPNIntf(prefix netip.Prefix, vpnIntf wgIface, initialNextHop Nexthop) (Nexthop, error) {
	if err := r.validateRoute(prefix); err != nil {
		return Nexthop{}, err
	}

	addr := prefix.Addr()
	if addr.IsUnspecified() {
		return Nexthop{}, vars.ErrRouteNotAllowed
	}

	// Check if the prefix is part of any local subnets
	if isLocal, subnet := r.isPrefixInLocalSubnets(prefix); isLocal {
		return Nexthop{}, fmt.Errorf("prefix %s is part of local subnet %s: %w", prefix, subnet, vars.ErrRouteNotAllowed)
	}

	// Determine the exit interface and next hop for the prefix, so we can add a specific route
	nexthop, err := GetNextHop(addr)
	if err != nil {
		return Nexthop{}, fmt.Errorf("get next hop: %w", err)
	}

	log.Debugf("Found next hop %s for prefix %s with interface %v", nexthop.IP, prefix, nexthop.Intf)
	exitNextHop := nexthop

	vpnAddr := vpnIntf.Address().IP

	// if next hop is the VPN address or the interface is the VPN interface, we should use the initial values
	if exitNextHop.IP == vpnAddr || exitNextHop.Intf != nil && exitNextHop.Intf.Name == vpnIntf.Name() {
		log.Debugf("Route for prefix %s is pointing to the VPN interface, using initial next hop %v", prefix, initialNextHop)
		exitNextHop = initialNextHop
	}

	log.Debugf("Adding a new route for prefix %s with next hop %s", prefix, exitNextHop.IP)
	if err := r.addToRouteTable(prefix, exitNextHop); err != nil {
		return Nexthop{}, fmt.Errorf("add route to table: %w", err)
	}

	return exitNextHop, nil
}

func (r *SysOps) isPrefixInLocalSubnets(prefix netip.Prefix) (bool, *net.IPNet) {
	r.localSubnetsCacheMu.RLock()
	cacheAge := time.Since(r.localSubnetsCacheTime)
	subnets := r.localSubnetsCache
	r.localSubnetsCacheMu.RUnlock()

	if cacheAge > localSubnetsCacheTTL || subnets == nil {
		r.localSubnetsCacheMu.Lock()
		if time.Since(r.localSubnetsCacheTime) > localSubnetsCacheTTL || r.localSubnetsCache == nil {
			r.refreshLocalSubnetsCache()
		}
		subnets = r.localSubnetsCache
		r.localSubnetsCacheMu.Unlock()
	}

	for _, subnet := range subnets {
		if subnet.Contains(prefix.Addr().AsSlice()) {
			return true, subnet
		}
	}

	return false, nil
}

func (r *SysOps) refreshLocalSubnetsCache() {
	localInterfaces, err := net.Interfaces()
	if err != nil {
		log.Errorf("Failed to get local interfaces: %v", err)
		return
	}

	var newSubnets []*net.IPNet
	for _, intf := range localInterfaces {
		addrs, err := intf.Addrs()
		if err != nil {
			log.Errorf("Failed to get addresses for interface %s: %v", intf.Name, err)
			continue
		}

		for _, addr := range addrs {
			ipnet, ok := addr.(*net.IPNet)
			if !ok {
				log.Errorf("Failed to convert address to IPNet: %v", addr)
				continue
			}
			newSubnets = append(newSubnets, ipnet)
		}
	}

	r.localSubnetsCache = newSubnets
	r.localSubnetsCacheTime = time.Now()
}

// genericAddVPNRoute adds a new route to the vpn interface, it splits the default prefix
// in two /1 prefixes to avoid replacing the existing default route
func (r *SysOps) genericAddVPNRoute(prefix netip.Prefix, intf *net.Interface) error {
	nextHop := Nexthop{netip.Addr{}, intf}

	switch prefix {
	case vars.Defaultv4:
		if err := r.addToRouteTable(splitDefaultv4_1, nextHop); err != nil {
			return err
		}
		if err := r.addToRouteTable(splitDefaultv4_2, nextHop); err != nil {
			if err2 := r.removeFromRouteTable(splitDefaultv4_1, nextHop); err2 != nil {
				log.Warnf("Failed to rollback route addition: %s", err2)
			}
			return err
		}

		// TODO: remove once IPv6 is supported on the interface
		if err := r.addToRouteTable(splitDefaultv6_1, nextHop); err != nil {
			return fmt.Errorf("add unreachable route split 1: %w", err)
		}
		if err := r.addToRouteTable(splitDefaultv6_2, nextHop); err != nil {
			if err2 := r.removeFromRouteTable(splitDefaultv6_1, nextHop); err2 != nil {
				log.Warnf("Failed to rollback route addition: %s", err2)
			}
			return fmt.Errorf("add unreachable route split 2: %w", err)
		}

		return nil
	case vars.Defaultv6:
		if err := r.addToRouteTable(splitDefaultv6_1, nextHop); err != nil {
			return fmt.Errorf("add unreachable route split 1: %w", err)
		}
		if err := r.addToRouteTable(splitDefaultv6_2, nextHop); err != nil {
			if err2 := r.removeFromRouteTable(splitDefaultv6_1, nextHop); err2 != nil {
				log.Warnf("Failed to rollback route addition: %s", err2)
			}
			return fmt.Errorf("add unreachable route split 2: %w", err)
		}

		return nil
	}

	return r.addToRouteTable(prefix, nextHop)
}

// genericRemoveVPNRoute removes the route from the vpn interface. If a default prefix is given,
// it will remove the split /1 prefixes
func (r *SysOps) genericRemoveVPNRoute(prefix netip.Prefix, intf *net.Interface) error {
	nextHop := Nexthop{netip.Addr{}, intf}

	switch prefix {
	case vars.Defaultv4:
		var result *multierror.Error
		if err := r.removeFromRouteTable(splitDefaultv4_1, nextHop); err != nil {
			result = multierror.Append(result, err)
		}
		if err := r.removeFromRouteTable(splitDefaultv4_2, nextHop); err != nil {
			result = multierror.Append(result, err)
		}

		// TODO: remove once IPv6 is supported on the interface
		if err := r.removeFromRouteTable(splitDefaultv6_1, nextHop); err != nil {
			result = multierror.Append(result, err)
		}
		if err := r.removeFromRouteTable(splitDefaultv6_2, nextHop); err != nil {
			result = multierror.Append(result, err)
		}

		return nberrors.FormatErrorOrNil(result)
	case vars.Defaultv6:
		var result *multierror.Error
		if err := r.removeFromRouteTable(splitDefaultv6_1, nextHop); err != nil {
			result = multierror.Append(result, err)
		}
		if err := r.removeFromRouteTable(splitDefaultv6_2, nextHop); err != nil {
			result = multierror.Append(result, err)
		}

		return nberrors.FormatErrorOrNil(result)
	default:
		return r.removeFromRouteTable(prefix, nextHop)
	}
}

func (r *SysOps) setupHooks(initAddresses []net.IP, stateManager *statemanager.Manager) error {
	beforeHook := func(connID hooks.ConnectionID, prefix netip.Prefix) error {
		if _, err := r.refCounter.IncrementWithID(string(connID), prefix, struct{}{}); err != nil {
			return fmt.Errorf("adding route reference: %v", err)
		}

		r.updateState(stateManager)

		return nil
	}
	afterHook := func(connID hooks.ConnectionID) error {
		if err := r.refCounter.DecrementWithID(string(connID)); err != nil {
			return fmt.Errorf("remove route reference: %w", err)
		}

		r.updateState(stateManager)

		return nil
	}

	var merr *multierror.Error

	for _, ip := range initAddresses {
		prefix, err := util.GetPrefixFromIP(ip)
		if err != nil {
			merr = multierror.Append(merr, fmt.Errorf("invalid IP address %s: %w", ip, err))
			continue
		}
		if err := beforeHook("init", prefix); err != nil {
			merr = multierror.Append(merr, fmt.Errorf("add initial route for %s: %w", prefix, err))
		}
	}

	hooks.AddWriteHook(beforeHook)
	hooks.AddCloseHook(afterHook)

	hooks.AddAddressRemoveHook(func(connID hooks.ConnectionID, prefix netip.Prefix) error {
		if _, err := r.refCounter.Decrement(prefix); err != nil {
			return fmt.Errorf("remove route reference: %w", err)
		}

		r.updateState(stateManager)
		return nil
	})

	return nberrors.FormatErrorOrNil(merr)
}

func GetNextHop(ip netip.Addr) (Nexthop, error) {
	r, err := netroute.New()
	if err != nil {
		return Nexthop{}, fmt.Errorf("new netroute: %w", err)
	}
	intf, gateway, preferredSrc, err := r.Route(ip.AsSlice())
	if err != nil {
		log.Debugf("Failed to get route for %s: %v", ip, err)
		return Nexthop{}, vars.ErrRouteNotFound
	}

	log.Debugf("Route for %s: interface %v nexthop %v, preferred source %v", ip, intf, gateway, preferredSrc)
	if gateway == nil {
		if preferredSrc == nil {
			return Nexthop{Intf: intf}, nil
		}
		log.Debugf("No next hop found for IP %s, using preferred source %s", ip, preferredSrc)

		addr, err := ipToAddr(preferredSrc, intf)
		if err != nil {
			return Nexthop{}, fmt.Errorf("convert preferred source to address: %w", err)
		}
		return Nexthop{
			IP:   addr,
			Intf: intf,
		}, nil
	}

	addr, err := ipToAddr(gateway, intf)
	if err != nil {
		return Nexthop{}, fmt.Errorf("convert gateway to address: %w", err)
	}

	return Nexthop{
		IP:   addr,
		Intf: intf,
	}, nil
}

// converts a net.IP to a netip.Addr including the zone based on the passed interface
func ipToAddr(ip net.IP, intf *net.Interface) (netip.Addr, error) {
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return netip.Addr{}, fmt.Errorf("failed to convert IP address to netip.Addr: %s", ip)
	}

	if intf != nil && (addr.IsLinkLocalMulticast() || addr.IsLinkLocalUnicast()) {
		zone := intf.Name
		if runtime.GOOS == "windows" {
			zone = strconv.Itoa(intf.Index)
		}
		log.Tracef("Adding zone %s to address %s", zone, addr)
		addr = addr.WithZone(zone)
	}

	return addr.Unmap(), nil
}

// IsAddrRouted checks if the candidate address would route to the vpn, in which case it returns true and the matched prefix.
func IsAddrRouted(addr netip.Addr, vpnRoutes []netip.Prefix) (bool, netip.Prefix) {
	localRoutes, err := hasSeparateRouting()
	if err != nil {
		if !errors.Is(err, ErrRoutingIsSeparate) {
			log.Errorf("Failed to get routes: %v", err)
		}
		return false, netip.Prefix{}
	}

	return isVpnRoute(addr, vpnRoutes, localRoutes)
}

func isVpnRoute(addr netip.Addr, vpnRoutes []netip.Prefix, localRoutes []netip.Prefix) (bool, netip.Prefix) {
	vpnPrefixMap := map[netip.Prefix]struct{}{}
	for _, prefix := range vpnRoutes {
		vpnPrefixMap[prefix] = struct{}{}
	}

	// remove vpnRoute duplicates
	for _, prefix := range localRoutes {
		delete(vpnPrefixMap, prefix)
	}

	var longestPrefix netip.Prefix
	var isVpn bool

	combinedRoutes := make([]netip.Prefix, len(vpnRoutes)+len(localRoutes))
	copy(combinedRoutes, vpnRoutes)
	copy(combinedRoutes[len(vpnRoutes):], localRoutes)

	for _, prefix := range combinedRoutes {
		// Ignore the default route, it has special handling
		if prefix.Bits() == 0 {
			continue
		}

		if prefix.Contains(addr) {
			// Longest prefix match
			if !longestPrefix.IsValid() || prefix.Bits() > longestPrefix.Bits() {
				longestPrefix = prefix
				_, isVpn = vpnPrefixMap[prefix]
			}
		}
	}

	if !longestPrefix.IsValid() {
		// No route matched
		return false, netip.Prefix{}
	}

	// Return true if the longest matching prefix is from vpnRoutes
	return isVpn, longestPrefix
}
