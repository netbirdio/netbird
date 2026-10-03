package dns

import (
	"net/netip"
	"os"
	"strings"

	log "github.com/sirupsen/logrus"

	nbdns "github.com/netbirdio/netbird/dns"
	"github.com/netbirdio/netbird/route"
)

// envRoutedUpstreamGating selects when an upstream nameserver that is only
// reachable through a routing peer may be configured. Accepted values are
// "off", "startup" and "always"; anything else falls back to "off".
const envRoutedUpstreamGating = "NB_DNS_ROUTED_UPSTREAM_GATING"

// routedUpstreamGating decides how long the "is there a route to this
// nameserver" check keeps influencing the configuration.
type routedUpstreamGating int

// routeSnapshot is the route state a gating decision is made on. It is
// captured by the caller before taking DefaultServer.mux: resolving the route
// accessors re-enters the route manager's lock, and the route manager takes
// DefaultServer.mux on its own paths, so reading them while holding it would
// invert the lock order (see refreshHealth for the same constraint).
type routeSnapshot struct {
	// selected are the admin-enabled client routes, used to tell whether an
	// upstream is reached through a routing peer at all.
	selected route.HAMap
	// installed are the prefixes whose allowed IPs are currently on the
	// interface, i.e. the ones a packet can actually take.
	installed []netip.Prefix
}

// longestPrefixMatch returns the most specific prefix in the set covering ip,
// the counterpart of haMapLongestMatch for a plain prefix list.
func longestPrefixMatch(prefixes []netip.Prefix, ip netip.Addr) (netip.Prefix, bool) {
	var best netip.Prefix
	found := false
	for _, p := range prefixes {
		if !p.Contains(ip) {
			continue
		}
		if !found || p.Bits() > best.Bits() {
			best = p
			found = true
		}
	}
	return best, found
}

// routedUpstreamGate answers whether a nameserver group may be configured,
// given whether a route to its upstreams exists. Not safe for concurrent use:
// it is only ever touched on the configuration path, under DefaultServer.mux.
type routedUpstreamGate struct {
	mode routedUpstreamGating
	// latched holds the groups that passed the check at least once. Only
	// gatingStartup reads it, so that a routing peer going away later never
	// withdraws a group. Bounded by the number of distinct nameserver groups
	// the account has ever configured.
	latched map[nsGroupID]struct{}
}

const (
	// gatingOff configures every nameserver group as soon as management
	// sends it, regardless of whether its upstreams are reachable.
	gatingOff routedUpstreamGating = iota
	// gatingStartup withholds a group until a route to its upstreams
	// exists for the first time, then keeps it configured for good. A
	// routing peer going away later does not withdraw the group.
	gatingStartup
	// gatingAlways re-evaluates continuously: a group is withdrawn again
	// when the route to its upstreams goes away.
	gatingAlways
)

func newRoutedUpstreamGate(mode routedUpstreamGating) *routedUpstreamGate {
	return &routedUpstreamGate{
		mode:    mode,
		latched: make(map[nsGroupID]struct{}),
	}
}

func (g routedUpstreamGating) String() string {
	switch g {
	case gatingStartup:
		return "startup"
	case gatingAlways:
		return "always"
	default:
		return "off"
	}
}

// allow reports whether nsGroup may be configured. A group is allowed as soon
// as one of its nameservers is usable, which means either that it is not
// reached through a routing peer (a public resolver, or an overlay address
// because the nameserver is a peer itself) or that the route to it is
// installed. A group all of whose nameservers sit behind a routing peer with
// no installed route is withheld.
//
// "Reached through a routing peer" is decided by longest prefix match, because
// a default route covers every address. A nameserver sitting behind an exit
// node is served by that default route and must stay configured while it is up;
// a nameserver that had its own specific route must be withheld when that route
// goes, even though the default route still nominally covers it — traffic would
// leave through the exit node, which has no path to it.
//
// Only a concrete prefix counts. A dynamic (domain) route carries a placeholder
// Network that can be neither matched nor ranked, so honouring it would withhold
// every nameserver of any account that has a single domain route.
// groupHasImmediateUpstream makes the opposite choice on the same unknown
// because there the cost of being wrong is a delayed warning, not a resolver
// that never gets configured.
func (g *routedUpstreamGate) allow(nsGroup *nbdns.NameServerGroup, snap routeSnapshot) bool {
	if g == nil || g.mode == gatingOff {
		return true
	}
	if nsGroup == nil || len(nsGroup.NameServers) == 0 {
		return true
	}

	key := generateGroupKey(nsGroup)
	if g.mode == gatingStartup {
		if _, ok := g.latched[key]; ok {
			return true
		}
	}

	for _, ns := range nsGroup.NameServers {
		ip := ns.IP.Unmap()

		// The prefix that would carry traffic to this address is the most
		// specific one covering it, not just any one that happens to.
		want, routed := haMapLongestMatch(snap.selected, ip)
		if !routed {
			g.remember(key)
			return true
		}

		// Installed is a subset of selected, so an equally specific match is
		// the same prefix: the route that should carry this address is up.
		// A shorter one means it is gone and something broader has taken over,
		// which is not a path to this nameserver.
		if have, ok := longestPrefixMatch(snap.installed, ip); ok && have.Bits() == want.Bits() {
			g.remember(key)
			return true
		}
	}

	return false
}

// remember records a group that passed the check so gatingStartup never
// withdraws it again. No-op in the other modes.
func (g *routedUpstreamGate) remember(key nsGroupID) {
	if g.mode != gatingStartup {
		return
	}
	g.latched[key] = struct{}{}
}

func routedUpstreamGatingFromEnv() routedUpstreamGating {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(envRoutedUpstreamGating))) {
	case "":
		return gatingOff
	case "off":
		return gatingOff
	case "startup":
		return gatingStartup
	case "always":
		return gatingAlways
	default:
		log.Warnf("invalid %s value %q, using %s", envRoutedUpstreamGating, os.Getenv(envRoutedUpstreamGating), gatingOff)
		return gatingOff
	}
}
