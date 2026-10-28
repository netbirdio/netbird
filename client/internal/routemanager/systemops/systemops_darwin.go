//go:build darwin && !ios

package systemops

import (
	"errors"
	"fmt"
	"net/netip"
	"os"
	"time"

	"github.com/hashicorp/go-multierror"
	log "github.com/sirupsen/logrus"
	"golang.org/x/net/route"
	"golang.org/x/sys/unix"

	nberrors "github.com/netbirdio/netbird/client/errors"
	"github.com/netbirdio/netbird/client/internal/routemanager/vars"
	nbnet "github.com/netbirdio/netbird/client/net"
)

// scopedRouteBudget bounds retries for the scoped default route. Installing or
// deleting it matters enough that we're willing to spend longer waiting for the
// kernel reply than for per-prefix exclusion routes.
const scopedRouteBudget = 5 * time.Second

// setupAdvancedRouting installs an RTF_IFSCOPE default route per address family
// pinned to the current physical egress, so IP_BOUND_IF scoped lookups can
// resolve gateway'd destinations while the VPN's split default owns the
// unscoped table.
//
// Timing note: this runs during routeManager.Init, which happens before the
// VPN interface is created and before any peer routes propagate. The initial
// mgmt / signal / relay TCP dials always fire before this runs, so those
// sockets miss the IP_BOUND_IF binding and rely on the kernel's normal route
// lookup, which at that point correctly picks the physical default. Those
// already-established TCP flows keep their originally-selected interface for
// their lifetime on Darwin because the kernel caches the egress route
// per-socket at connect time; adding the VPN's 0/1 + 128/1 split default
// afterwards does not migrate them since the original en0 default stays in
// the table. Any subsequent reconnect via nbnet.NewDialer picks up the
// populated bound-iface cache and gets IP_BOUND_IF set cleanly.
func (r *SysOps) setupAdvancedRouting() error {
	installed, err := r.setupAdvancedRoutingWith(GetNextHop)
	if installed == 0 {
		return err
	}
	if err != nil {
		log.Warnf("advanced routing setup partially succeeded: %v", err)
	}
	return nil
}

// nexthopLookup resolves the default next hop for the family of an
// unspecified address.
type nexthopLookup func(unspec netip.Addr) (Nexthop, error)

// setupAdvancedRoutingWith is setupAdvancedRouting with the default next hop
// resolved by lookup. It returns how many address families got a scoped
// default, and the failures of the others.
func (r *SysOps) setupAdvancedRoutingWith(lookup nexthopLookup) (int, error) {
	// Drop any previously-cached egress interface before reinstalling. On a
	// refresh, a family that no longer resolves would otherwise keep the stale
	// binding, causing new sockets to scope to an interface without a matching
	// scoped default.
	nbnet.ClearBoundInterfaces()

	if err := r.flushScopedDefaults(); err != nil {
		log.Warnf("flush residual scoped defaults: %v", err)
	}

	var merr *multierror.Error
	installed := 0

	for _, unspec := range []netip.Addr{netip.IPv4Unspecified(), netip.IPv6Unspecified()} {
		ok, err := r.installScopedDefaultFor(unspec, lookup)
		if err != nil {
			merr = multierror.Append(merr, err)
			continue
		}
		if ok {
			installed++
		}
	}

	return installed, nberrors.FormatErrorOrNil(merr)
}

// installScopedDefaultFor resolves the physical default nexthop for the given
// address family, installs a scoped default via it, and caches the iface for
// subsequent IP_BOUND_IF / IPV6_BOUND_IF socket binds.
func (r *SysOps) installScopedDefaultFor(unspec netip.Addr, lookup nexthopLookup) (bool, error) {
	nexthop, err := lookup(unspec)
	if err != nil {
		if errors.Is(err, vars.ErrRouteNotFound) {
			return false, nil
		}
		return false, fmt.Errorf("get default nexthop for %s: %w", unspec, err)
	}
	if nexthop.Intf == nil {
		return false, fmt.Errorf("unusable default nexthop for %s (no interface)", unspec)
	}

	reused := false
	if err := r.addScopedDefault(unspec, nexthop); err != nil {
		if !errors.Is(err, unix.EEXIST) {
			return false, fmt.Errorf("add scoped default on %s: %w", nexthop.Intf.Name, err)
		}
		// macOS installs its own RTF_IFSCOPE defaults for primary service
		// selection on multi-NIC setups, so a route on this ifindex can
		// already exist before we try. Binding to it via IP[V6]_BOUND_IF
		// still produces the scoped lookup we need.
		reused = true
	}

	af := unix.AF_INET
	if unspec.Is6() {
		af = unix.AF_INET6
	}
	nbnet.SetBoundInterface(af, nexthop.Intf)
	via := "point-to-point"
	if nexthop.IP.IsValid() {
		via = nexthop.IP.String()
	}
	verb := "installed"
	if reused {
		verb = "reused existing"
	}
	log.Infof("%s scoped default route via %s on %s for %s", verb, via, nexthop.Intf.Name, afOf(unspec))
	return true, nil
}

// physicalDefault is the physical default next hop of one address family.
type physicalDefault struct {
	unspec  netip.Addr
	nexthop Nexthop
}

// scopedKey identifies a scoped default by address family and interface.
type scopedKey struct {
	is6   bool
	index int
}

// refreshUnderlay moves the scoped defaults and the cached egress interface
// to the current physical default.
//
// Unlike engine start, a refresh runs with the NetBird routes in place: with
// an exit node the plain lookup resolves 0/1 on the NetBird interface and
// would bind NetBird's own traffic to the tunnel. For the same reason the
// binding must never be empty here: a socket dialed meanwhile would follow
// 0/1 into the tunnel. So the new routes and binding go in before the old
// ones come out.
func (r *SysOps) refreshUnderlay(advancedRouting bool) error {
	if !advancedRouting {
		return nil
	}
	defaults, err := lookupUnderlayDefaults(nbnet.GetVPNInterfaceName())
	// Unlike engine start, a family left unbound here keeps sockets on the
	// old network or sends them into the tunnel: any failure restarts.
	if err != nil {
		return err
	}
	// The refresh only runs on a change with a default in place. Finding none
	// leaves NetBird's sockets unbound, following 0/1 into the tunnel: fail, so
	// the engine falls back to a restart.
	if len(defaults) == 0 {
		return errors.New("no physical default found to bind NetBird's traffic to")
	}

	keep := make(map[scopedKey]bool)
	for _, d := range defaults {
		if err := r.replaceScopedDefault(d.unspec, d.nexthop); err != nil {
			return fmt.Errorf("install scoped default on %s: %w", d.nexthop.Intf.Name, err)
		}
		nbnet.SetBoundInterface(afNumOf(d.unspec), d.nexthop.Intf)
		keep[scopedKey{is6: d.unspec.Is6(), index: d.nexthop.Intf.Index}] = true
		log.Infof("moved the %s scoped default and binding to %s", afOf(d.unspec), d.nexthop.Intf.Name)
	}
	for _, unspec := range []netip.Addr{netip.IPv4Unspecified(), netip.IPv6Unspecified()} {
		if !hasDefaultFor(defaults, unspec) {
			nbnet.ClearBoundInterface(afNumOf(unspec))
		}
	}

	// NetBird's sockets are already bound to the new interface: a leftover
	// scoped default on the old one is unused, not worth a restart.
	if err := r.flushScopedDefaultsExcept(func(dst netip.Prefix, index int) bool {
		return keep[scopedKey{is6: dst.Addr().Is6(), index: index}]
	}); err != nil {
		log.Warnf("remove old scoped defaults: %v", err)
	}
	return nil
}

// lookupUnderlayDefaults resolves the physical default of each address family,
// skipping the NetBird interface. A family without a default is left out.
func lookupUnderlayDefaults(vpnIntf string) ([]physicalDefault, error) {
	var defaults []physicalDefault
	for _, unspec := range []netip.Addr{netip.IPv4Unspecified(), netip.IPv6Unspecified()} {
		nexthop, err := GetUnderlayNextHop(unspec, vpnIntf)
		if errors.Is(err, vars.ErrRouteNotFound) {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("get default nexthop for %s: %w", unspec, err)
		}
		if nexthop.Intf == nil {
			return nil, fmt.Errorf("unusable default nexthop for %s (no interface)", unspec)
		}
		defaults = append(defaults, physicalDefault{unspec: unspec, nexthop: nexthop})
	}
	return defaults, nil
}

// replaceScopedDefault installs the scoped default via nexthop. RTM_ADD
// refuses a second scoped default on the same interface, so one already there
// (ours with the old gateway, or macOS's own) is repointed in place instead.
func (r *SysOps) replaceScopedDefault(unspec netip.Addr, nexthop Nexthop) error {
	err := r.addScopedDefault(unspec, nexthop)
	if !errors.Is(err, unix.EEXIST) {
		return err
	}
	return r.scopedRouteSocket(unix.RTM_CHANGE, unspec, nexthop)
}

func hasDefaultFor(defaults []physicalDefault, unspec netip.Addr) bool {
	for _, d := range defaults {
		if d.unspec == unspec {
			return true
		}
	}
	return false
}

func afNumOf(unspec netip.Addr) int {
	if unspec.Is6() {
		return unix.AF_INET6
	}
	return unix.AF_INET
}

func (r *SysOps) cleanupAdvancedRouting() error {
	nbnet.ClearBoundInterfaces()
	return r.flushScopedDefaults()
}

// flushPlatformExtras runs darwin-specific residual cleanup hooked into the
// generic FlushMarkedRoutes path, so a crashed daemon's scoped defaults get
// removed on the next boot regardless of whether a profile is brought up.
func (r *SysOps) flushPlatformExtras() error {
	return r.flushScopedDefaults()
}

// flushScopedDefaults removes any scoped default routes tagged with routeProtoFlag.
// Safe to call at startup to clear residual entries from a prior session.
func (r *SysOps) flushScopedDefaults() error {
	return r.flushScopedDefaultsExcept(func(netip.Prefix, int) bool { return false })
}

// flushScopedDefaultsExcept removes the scoped default routes tagged with
// routeProtoFlag, except those keep reports for their destination and
// interface index.
func (r *SysOps) flushScopedDefaultsExcept(keep func(dst netip.Prefix, index int) bool) error {
	rib, err := retryFetchRIB()
	if err != nil {
		return fmt.Errorf("fetch routing table: %w", err)
	}

	msgs, err := route.ParseRIB(route.RIBTypeRoute, rib)
	if err != nil {
		return fmt.Errorf("parse routing table: %w", err)
	}

	var merr *multierror.Error
	removed := 0

	for _, msg := range msgs {
		rtMsg, ok := msg.(*route.RouteMessage)
		if !ok {
			continue
		}
		if rtMsg.Flags&routeProtoFlag == 0 {
			continue
		}
		if rtMsg.Flags&unix.RTF_IFSCOPE == 0 {
			continue
		}

		info, err := MsgToRoute(rtMsg)
		if err != nil {
			log.Debugf("skip scoped flush: %v", err)
			continue
		}
		if !info.Dst.IsValid() || info.Dst.Bits() != 0 {
			continue
		}
		if keep(info.Dst, rtMsg.Index) {
			continue
		}

		if err := r.deleteScopedRoute(rtMsg); err != nil {
			merr = multierror.Append(merr, fmt.Errorf("delete scoped default %s on index %d: %w",
				info.Dst, rtMsg.Index, err))
			continue
		}
		removed++
		log.Debugf("flushed residual scoped default %s on index %d", info.Dst, rtMsg.Index)
	}

	if removed > 0 {
		log.Infof("flushed %d residual scoped default route(s)", removed)
	}
	return nberrors.FormatErrorOrNil(merr)
}

func (r *SysOps) addScopedDefault(unspec netip.Addr, nexthop Nexthop) error {
	return r.scopedRouteSocket(unix.RTM_ADD, unspec, nexthop)
}

func (r *SysOps) deleteScopedRoute(rtMsg *route.RouteMessage) error {
	// Preserve identifying flags from the stored route (including RTF_GATEWAY
	// only if present); kernel-set bits like RTF_DONE don't belong on RTM_DELETE.
	keep := unix.RTF_UP | unix.RTF_STATIC | unix.RTF_GATEWAY | unix.RTF_IFSCOPE | routeProtoFlag
	del := &route.RouteMessage{
		Type:    unix.RTM_DELETE,
		Flags:   rtMsg.Flags & keep,
		Version: unix.RTM_VERSION,
		Seq:     r.getSeq(),
		Index:   rtMsg.Index,
		Addrs:   rtMsg.Addrs,
	}
	return r.writeRouteMessage(del, scopedRouteBudget)
}

func (r *SysOps) scopedRouteSocket(action int, unspec netip.Addr, nexthop Nexthop) error {
	flags := unix.RTF_UP | unix.RTF_STATIC | unix.RTF_IFSCOPE | routeProtoFlag

	msg := &route.RouteMessage{
		Type:    action,
		Flags:   flags,
		Version: unix.RTM_VERSION,
		ID:      uintptr(os.Getpid()),
		Seq:     r.getSeq(),
		Index:   nexthop.Intf.Index,
	}

	const numAddrs = unix.RTAX_NETMASK + 1
	addrs := make([]route.Addr, numAddrs)

	dst, err := addrToRouteAddr(unspec)
	if err != nil {
		return fmt.Errorf("build destination: %w", err)
	}
	mask, err := prefixToRouteNetmask(netip.PrefixFrom(unspec, 0))
	if err != nil {
		return fmt.Errorf("build netmask: %w", err)
	}
	addrs[unix.RTAX_DST] = dst
	addrs[unix.RTAX_NETMASK] = mask

	if nexthop.IP.IsValid() {
		msg.Flags |= unix.RTF_GATEWAY
		gw, err := addrToRouteAddr(nexthop.IP.Unmap())
		if err != nil {
			return fmt.Errorf("build gateway: %w", err)
		}
		addrs[unix.RTAX_GATEWAY] = gw
	} else {
		addrs[unix.RTAX_GATEWAY] = &route.LinkAddr{
			Index: nexthop.Intf.Index,
			Name:  nexthop.Intf.Name,
		}
	}
	msg.Addrs = addrs

	return r.writeRouteMessage(msg, scopedRouteBudget)
}

func afOf(a netip.Addr) string {
	if a.Is4() {
		return "IPv4"
	}
	return "IPv6"
}
