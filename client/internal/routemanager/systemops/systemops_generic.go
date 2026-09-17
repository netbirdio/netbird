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
	nbnet "github.com/netbirdio/netbird/client/net"
	"github.com/netbirdio/netbird/client/net/hooks"
)

const (
	// localSubnetsCacheTTL bounds the exclusion-route lookup, which runs per connection.
	localSubnetsCacheTTL = 15 * time.Minute

	// localSubnetsGuardTTL bounds the VPN-route guard. Route installs come in bursts on a
	// network map update, so this collapses a whole burst into one refresh while still
	// re-reading the host's subnets between bursts, where a LAN change would show up.
	localSubnetsGuardTTL = 5 * time.Second
)

var splitDefaultv4_1 = netip.PrefixFrom(netip.IPv4Unspecified(), 1)
var splitDefaultv4_2 = netip.PrefixFrom(netip.AddrFrom4([4]byte{128}), 1)
var splitDefaultv6_1 = netip.PrefixFrom(netip.IPv6Unspecified(), 1)
var splitDefaultv6_2 = netip.PrefixFrom(netip.AddrFrom16([16]byte{0x80}), 1)

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

	// BSDs blackhole a /32 added inside a directly-connected subnet; Linux/Windows need it to beat the wt0 route.
	switch runtime.GOOS {
	case "darwin", "freebsd", "netbsd", "openbsd", "dragonfly":
		if isLocal, subnet, healthy := r.isPrefixInLocalSubnets(prefix); isLocal {
			if !healthy {
				return Nexthop{}, fmt.Errorf("prefix %s local-subnet ownership unverified: %w", prefix, vars.ErrRouteNotAllowed)
			}
			return Nexthop{}, fmt.Errorf("prefix %s is part of local subnet %s: %w", prefix, subnet, vars.ErrRouteNotAllowed)
		}
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

// isPrefixInLocalSubnets reports whether the prefix's own address falls inside a locally
// attached subnet. It deliberately does not require the whole prefix to be contained, unlike
// localSubnetOverlap: BSD blackholes any host route added inside a connected subnet, however
// much of the prefix that subnet covers. Healthy is false when discovery did not verify the
// answer; isLocal is then true so callers fail closed instead of installing.
func (r *SysOps) isPrefixInLocalSubnets(prefix netip.Prefix) (bool, *net.IPNet, bool) {
	subnets, healthy := r.localSubnets(localSubnetsCacheTTL)
	if !healthy {
		return true, nil, false
	}
	for _, subnet := range subnets {
		if subnet.Contains(prefix.Addr().AsSlice()) {
			return true, subnet, true
		}
	}

	return false, nil, true
}

// localSubnetOverlap returns the directly attached subnet that contains the prefix, if any.
// The host already reaches such a subnet over its own link, and a VPN route inside it would
// shadow that link: longest-prefix match ignores the route metric, so a /32 host route on the
// overlay beats the native /24 no matter how the two are weighted.
//
// A prefix broader than the local subnet is deliberately not reported. Longest-prefix match
// already leaves the local subnet's own addresses on the local link, and the overlay still has
// to carry the rest of the prefix. The default route is exempt for the same reason.
//
// Healthy is false when discovery did not verify the answer. Callers must then fail closed
// (withhold the route) rather than treat the missing overlap as verified non-overlap.
func (r *SysOps) localSubnetOverlap(prefix netip.Prefix) (*net.IPNet, bool, bool) {
	if !prefix.IsValid() || prefix.Bits() == 0 {
		return nil, false, true
	}

	subnets, healthy := r.localSubnets(localSubnetsGuardTTL)
	if !healthy {
		return nil, false, false
	}
	for _, subnet := range subnets {
		local, ok := ipNetToPrefix(subnet)
		if !ok {
			continue
		}
		if prefix.Bits() >= local.Bits() && local.Contains(prefix.Addr()) {
			return subnet, true, true
		}
	}

	return nil, false, true
}

// trackInstalledVPNRoute mirrors a successful table install with the interface that owns it.
func (r *SysOps) trackInstalledVPNRoute(prefix netip.Prefix, intf *net.Interface) {
	r.vpnRoutesMu.Lock()
	defer r.vpnRoutesMu.Unlock()
	if r.installedVPNRoutes == nil {
		r.installedVPNRoutes = make(map[netip.Prefix]*net.Interface)
	}
	r.installedVPNRoutes[prefix] = intf
	delete(r.suppressedVPNRoutes, prefix)
}

// suppressVPNRoute records a withheld prefix with the interface needed to install it later.
// Only ever called for prefixes the caller's refcounter counts, so holder accounting stays
// balanced; the mark merely notes that no OS route exists.
func (r *SysOps) suppressVPNRoute(prefix netip.Prefix, intf *net.Interface) {
	r.vpnRoutesMu.Lock()
	defer r.vpnRoutesMu.Unlock()
	if r.suppressedVPNRoutes == nil {
		r.suppressedVPNRoutes = make(map[netip.Prefix]*net.Interface)
	}
	delete(r.installedVPNRoutes, prefix)
	r.suppressedVPNRoutes[prefix] = intf
}

// unsuppressVPNRoute drops the suppressed mark, e.g. after a verified install.
func (r *SysOps) unsuppressVPNRoute(prefix netip.Prefix) {
	r.vpnRoutesMu.Lock()
	defer r.vpnRoutesMu.Unlock()
	delete(r.suppressedVPNRoutes, prefix)
}

// takeSuppressedVPNRoute clears the suppressed mark and reports whether it was set. A set
// mark means no OS route was installed, so the caller can skip the table removal.
func (r *SysOps) takeSuppressedVPNRoute(prefix netip.Prefix) bool {
	r.vpnRoutesMu.Lock()
	defer r.vpnRoutesMu.Unlock()
	if _, ok := r.suppressedVPNRoutes[prefix]; !ok {
		return false
	}
	delete(r.suppressedVPNRoutes, prefix)
	return true
}

// takeInstalledVPNRoute clears the installed mirror and reports the owning interface.
func (r *SysOps) takeInstalledVPNRoute(prefix netip.Prefix) (*net.Interface, bool) {
	r.vpnRoutesMu.Lock()
	defer r.vpnRoutesMu.Unlock()
	intf, ok := r.installedVPNRoutes[prefix]
	if !ok {
		return nil, false
	}
	delete(r.installedVPNRoutes, prefix)
	return intf, true
}

// isSuppressedVPNRoute reports whether the prefix is currently withheld.
func (r *SysOps) isSuppressedVPNRoute(prefix netip.Prefix) bool {
	r.vpnRoutesMu.Lock()
	defer r.vpnRoutesMu.Unlock()
	_, ok := r.suppressedVPNRoutes[prefix]
	return ok
}

// vpnRoutesSnapshot copies both guard sets so reconciliation can act on them without holding
// the mirror mutex while calling into route programming or the refcounter.
func (r *SysOps) vpnRoutesSnapshot() (map[netip.Prefix]*net.Interface, map[netip.Prefix]*net.Interface) {
	r.vpnRoutesMu.Lock()
	defer r.vpnRoutesMu.Unlock()
	installed := make(map[netip.Prefix]*net.Interface, len(r.installedVPNRoutes))
	for prefix, intf := range r.installedVPNRoutes {
		installed[prefix] = intf
	}
	suppressed := make(map[netip.Prefix]*net.Interface, len(r.suppressedVPNRoutes))
	for prefix, intf := range r.suppressedVPNRoutes {
		suppressed[prefix] = intf
	}
	return installed, suppressed
}

// ReconcileLocalSubnets converges installed and withheld VPN routes with the host's current
// topology. It force-refreshes discovery, removes table routes that now overlap a local
// subnet, reinstalls withheld routes that are routable again, and drops stale marks whose
// holder is gone. Holder accounting is untouched: every flip keeps the refcounter entry and
// only changes the OS route plus the guard marks, so per-holder add/remove stays balanced.
// A flip is recorded only after its table operation succeeds, otherwise the old state is
// kept for the next pass. Concurrent adds and removes race safely: table programs tolerate
// already-there and not-there, and a key whose holder vanished mid-pass is rolled back
// instead of leaked.
//
// Advanced routing on Linux is out of scope: VPN routes live in a separate table the main
// table already outranks, so the guard never withholds there and there is nothing to converge.
func (r *SysOps) ReconcileLocalSubnets(counter *refcounter.RouteRefCounter) error {
	if r == nil || counter == nil {
		return nil
	}
	if runtime.GOOS == "linux" && nbnet.AdvancedRouting() {
		return nil
	}

	r.localSubnetsCacheMu.Lock()
	r.refreshLocalSubnetsCache()
	healthy := r.localSubnetsHealthy
	r.localSubnetsCacheMu.Unlock()

	if !healthy {
		return nil
	}

	installed, suppressed := r.vpnRoutesSnapshot()

	var merr *multierror.Error
	for prefix, intf := range installed {
		if _, ok := counter.Get(prefix); !ok {
			r.takeInstalledVPNRoute(prefix)
			continue
		}
		if _, overlap, _ := r.localSubnetOverlap(prefix); !overlap {
			continue
		}
		if err := r.removeTableRoute(prefix, intf); err != nil {
			merr = multierror.Append(merr, fmt.Errorf("remove shadowing route %s: %w", prefix, err))
			continue
		}
		r.suppressVPNRoute(prefix, intf)
	}

	for prefix, intf := range suppressed {
		if _, ok := counter.Get(prefix); !ok {
			r.unsuppressVPNRoute(prefix)
			continue
		}
		if _, overlap, _ := r.localSubnetOverlap(prefix); overlap {
			continue
		}
		if err := r.installTableRoute(prefix, intf); err != nil {
			merr = multierror.Append(merr, fmt.Errorf("reinstall route %s: %w", prefix, err))
			continue
		}
		r.trackInstalledVPNRoute(prefix, intf)
		if _, ok := counter.Get(prefix); !ok {
			if err := r.removeTableRoute(prefix, intf); err != nil {
				merr = multierror.Append(merr, fmt.Errorf("roll back orphaned route %s: %w", prefix, err))
				continue
			}
			r.takeInstalledVPNRoute(prefix)
		}
	}

	return nberrors.FormatErrorOrNil(merr)
}

// installTableRoute installs a guard-managed prefix, defaulting to the platform AddVPNRoute
// (which re-evaluates the guard and mirrors the outcome) unless tests override the seam.
func (r *SysOps) installTableRoute(prefix netip.Prefix, intf *net.Interface) error {
	if r.installGuardedRoute != nil {
		return r.installGuardedRoute(prefix, intf)
	}
	return r.AddVPNRoute(prefix, intf)
}

// removeTableRoute removes a guard-managed prefix, defaulting to the platform RemoveVPNRoute
// (which clears the guard marks on success) unless tests override the seam.
func (r *SysOps) removeTableRoute(prefix netip.Prefix, intf *net.Interface) error {
	if r.removeGuardedRoute != nil {
		return r.removeGuardedRoute(prefix, intf)
	}
	return r.RemoveVPNRoute(prefix, intf)
}

// localSubnets returns the last validated snapshot and whether it is verified. A fresh
// attempt window collapses bursts into one enumeration; a failed attempt keeps serving the
// last validated snapshot with healthy=false so the guard fails closed. A nil snapshot with
// healthy=false means no attempt has ever succeeded and nothing may be installed.
func (r *SysOps) localSubnets(maxAge time.Duration) ([]*net.IPNet, bool) {
	r.localSubnetsCacheMu.RLock()
	fresh := time.Since(r.localSubnetsCacheTime) <= maxAge
	subnets, healthy := r.localSubnetsCache, r.localSubnetsHealthy
	r.localSubnetsCacheMu.RUnlock()

	if fresh {
		return subnets, healthy
	}

	r.localSubnetsCacheMu.Lock()
	defer r.localSubnetsCacheMu.Unlock()

	if time.Since(r.localSubnetsCacheTime) <= maxAge {
		return r.localSubnetsCache, r.localSubnetsHealthy
	}
	r.refreshLocalSubnetsCache()
	return r.localSubnetsCache, r.localSubnetsHealthy
}

// refreshLocalSubnetsCache rebuilds the cache from the host's current interfaces. A fully
// successful enumeration publishes the new snapshot as validated; any failure retains the
// last validated snapshot and marks discovery unhealthy. Skipped interfaces and addresses
// (down, loopback, overlay, link-local) are deliberate filtering, not failure.
// The caller must hold localSubnetsCacheMu for writing.
func (r *SysOps) refreshLocalSubnetsCache() {
	localInterfaces, err := r.listHostInterfaces()
	if err != nil {
		log.Errorf("Failed to get local interfaces: %v", err)
		r.localSubnetsCacheTime = time.Now()
		r.localSubnetsHealthy = false
		return
	}

	var newSubnets []*net.IPNet
	incomplete := false
	for _, intf := range localInterfaces {
		if r.skipLocalInterface(intf) {
			continue
		}

		addrs, err := r.hostInterfaceAddrs(intf)
		if err != nil {
			log.Errorf("Failed to get addresses for interface %s: %v", intf.Name, err)
			incomplete = true
			continue
		}

		for _, addr := range addrs {
			ipnet, ok := addr.(*net.IPNet)
			if !ok {
				log.Errorf("Failed to convert address to IPNet: %v", addr)
				incomplete = true
				continue
			}
			if r.skipLocalSubnet(ipnet) {
				continue
			}
			newSubnets = append(newSubnets, ipnet)
		}
	}

	r.localSubnetsCacheTime = time.Now()
	if incomplete {
		log.Warnf("Local-subnet discovery incomplete, retaining last validated snapshot")
		r.localSubnetsHealthy = false
		return
	}
	r.localSubnetsCache = newSubnets
	r.localSubnetsHealthy = true
}

// listHostInterfaces enumerates host interfaces, or the test override when set.
func (r *SysOps) listHostInterfaces() ([]net.Interface, error) {
	if r.listInterfaces != nil {
		return r.listInterfaces()
	}
	return net.Interfaces()
}

// hostInterfaceAddrs returns the addresses of an interface, or the test override when set.
func (r *SysOps) hostInterfaceAddrs(intf net.Interface) ([]net.Addr, error) {
	if r.interfaceAddrs != nil {
		return r.interfaceAddrs(intf)
	}
	return intf.Addrs()
}

// skipLocalInterface reports whether an interface contributes no locally reachable
// subnet: it is down or loopback, or it is the overlay interface itself, whose
// subnet would otherwise make every mesh prefix look local.
func (r *SysOps) skipLocalInterface(intf net.Interface) bool {
	if intf.Flags&net.FlagUp == 0 || intf.Flags&net.FlagLoopback != 0 {
		return true
	}
	return r.wgInterface != nil && intf.Name == r.wgInterface.Name()
}

// skipLocalSubnet drops addresses that cannot stand in for a reachable LAN.
//
// It deliberately does not filter on overlay pool membership. The overlay's own addresses
// are already excluded by interface in skipLocalInterface, and validateRoute rejects any
// prefix inside the pool before the guard runs. Filtering by pool membership here would
// instead discard a physical subnet that legitimately overlaps the pool, which happens
// whenever the host sits behind CGNAT and the overlay uses the default 100.64.0.0/10.
func (r *SysOps) skipLocalSubnet(ipnet *net.IPNet) bool {
	addr, ok := netip.AddrFromSlice(ipnet.IP)
	if !ok {
		return true
	}
	addr = addr.Unmap()

	return addr.IsLoopback() ||
		addr.IsLinkLocalUnicast() ||
		addr.IsLinkLocalMulticast()
}

// ipNetToPrefix converts a net.IPNet to a canonical netip.Prefix, unmapping v4-in-v6
// addresses so IPv4 comparisons match. It reports false for a non-contiguous mask.
func ipNetToPrefix(ipnet *net.IPNet) (netip.Prefix, bool) {
	if ipnet == nil {
		return netip.Prefix{}, false
	}

	addr, ok := netip.AddrFromSlice(ipnet.IP)
	if !ok {
		return netip.Prefix{}, false
	}
	addr = addr.Unmap()

	ones, bits := ipnet.Mask.Size()
	if bits == 0 {
		return netip.Prefix{}, false
	}
	// A v4 address carrying a 16-byte mask counts the 96-bit v4-mapped prefix.
	if addr.Is4() && bits == 128 {
		ones -= 96
	}
	if ones < 0 {
		return netip.Prefix{}, false
	}

	prefix := netip.PrefixFrom(addr, ones)
	if !prefix.IsValid() {
		return netip.Prefix{}, false
	}
	return prefix.Masked(), true
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

		// When the interface has no v6, add v6 split-default as blackhole so
		// unroutable v6 goes to WG (dropped, no AllowedIPs) instead of leaking
		// to the system default route. When v6 is active, management sends ::/0
		// as a separate route that the dedicated handler adds.
		// Soft-fail: v6 blackhole is best-effort, don't abort v4 routing on failure.
		if !r.wgInterface.Address().HasIPv6() {
			if err := r.addV6SplitDefault(nextHop); err != nil {
				log.Warnf("failed to add v6 split-default blackhole: %s", err)
			}
		}

		return nil
	case vars.Defaultv6:
		return r.addV6SplitDefault(nextHop)
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

		if !r.wgInterface.Address().HasIPv6() {
			result = multierror.Append(result, r.removeV6SplitDefault(nextHop))
		}

		return nberrors.FormatErrorOrNil(result)
	case vars.Defaultv6:
		return nberrors.FormatErrorOrNil(r.removeV6SplitDefault(nextHop))
	default:
		return r.removeFromRouteTable(prefix, nextHop)
	}
}

func (r *SysOps) addV6SplitDefault(nextHop Nexthop) error {
	if err := r.addToRouteTable(splitDefaultv6_1, nextHop); err != nil {
		return fmt.Errorf("add split 1: %w", err)
	}
	if err := r.addToRouteTable(splitDefaultv6_2, nextHop); err != nil {
		if err2 := r.removeFromRouteTable(splitDefaultv6_1, nextHop); err2 != nil {
			log.Warnf("Failed to rollback v6 split-default: %s", err2)
		}
		return fmt.Errorf("add split 2: %w", err)
	}
	return nil
}

func (r *SysOps) removeV6SplitDefault(nextHop Nexthop) *multierror.Error {
	var result *multierror.Error
	if err := r.removeFromRouteTable(splitDefaultv6_1, nextHop); err != nil {
		result = multierror.Append(result, err)
	}
	if err := r.removeFromRouteTable(splitDefaultv6_2, nextHop); err != nil {
		result = multierror.Append(result, err)
	}
	return result
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

	// go-netroute v0.4.0 rejects unspecified destinations on Linux with a hard
	// client-side check. Substitute the lowest non-loopback address so the
	// lookup falls through to the default route (::1 / 127.0.0.1 would match
	// loopback, ::/0.0.0.0 are unspec). BSD/Windows pass the query straight to
	// the kernel and need no substitution.
	if runtime.GOOS == "linux" && ip.IsUnspecified() {
		if ip.Is6() {
			// ::2
			ip = netip.AddrFrom16([16]byte{15: 2})
		} else {
			// 0.0.0.1
			ip = netip.AddrFrom4([4]byte{0, 0, 0, 1})
		}
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
// When advanced routing is active the WG socket is bound to the physical interface (fwmark on linux,
// IP_UNICAST_IF on windows, IP_BOUND_IF on darwin) and bypasses the main routing table, so the check is skipped.
func IsAddrRouted(addr netip.Addr, vpnRoutes []netip.Prefix) (bool, netip.Prefix) {
	if nbnet.AdvancedRouting() {
		return false, netip.Prefix{}
	}

	localRoutes, err := GetRoutesFromTable()
	if err != nil {
		log.Errorf("Failed to get routes: %v", err)
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
