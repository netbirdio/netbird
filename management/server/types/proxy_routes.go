package types

import (
	"net/netip"
	"slices"
)

// ProxyRouteSet collects and deduplicates the routes that need to be pushed to
// source peers for transparent proxy rules. CIDR rules create specific routes;
// domain-only rules require a catch-all (0.0.0.0/0).
type ProxyRouteSet struct {
	// routes is the deduplicated set of destination prefixes to route through the proxy.
	routes map[netip.Prefix]struct{}
	// needsCatchAll is true if any rule has domains without CIDRs.
	needsCatchAll bool
}

// NewProxyRouteSet creates a new route set.
func NewProxyRouteSet() *ProxyRouteSet {
	return &ProxyRouteSet{
		routes: make(map[netip.Prefix]struct{}),
	}
}

// AddFromRule adds route entries derived from a proxy rule's destinations.
// - CIDR destinations create specific routes
// - Domain-only rules (no CIDRs) trigger a catch-all route
// - Rules with neither domains nor CIDRs also trigger catch-all (match all traffic)
func (s *ProxyRouteSet) AddFromRule(rule *InspectionPolicyRule) {
	if rule.HasCIDRDestination() {
		for _, cidr := range rule.Networks {
			prefix, err := netip.ParsePrefix(cidr)
			if err != nil {
				continue
			}
			s.routes[prefix] = struct{}{}
		}
		return
	}

	// Domain-only or no destination: need catch-all
	s.needsCatchAll = true
}

// Routes returns the deduplicated list of prefixes to route through the proxy.
// If any rule requires catch-all, returns only ["0.0.0.0/0"] since it subsumes
// all specific CIDRs.
func (s *ProxyRouteSet) Routes() []netip.Prefix {
	if s.needsCatchAll {
		return []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")}
	}

	result := make([]netip.Prefix, 0, len(s.routes))
	for prefix := range s.routes {
		result = append(result, prefix)
	}

	// Sort for deterministic output
	slices.SortFunc(result, func(a, b netip.Prefix) int {
		if c := a.Addr().Compare(b.Addr()); c != 0 {
			return c
		}
		return a.Bits() - b.Bits()
	})

	// Remove CIDRs that are subsets of larger CIDRs
	return deduplicatePrefixes(result)
}

// deduplicatePrefixes removes prefixes that are contained within other prefixes.
// Input must be sorted.
func deduplicatePrefixes(prefixes []netip.Prefix) []netip.Prefix {
	if len(prefixes) <= 1 {
		return prefixes
	}

	var result []netip.Prefix
	for _, p := range prefixes {
		subsumed := false
		for _, existing := range result {
			if existing.Contains(p.Addr()) && existing.Bits() <= p.Bits() {
				subsumed = true
				break
			}
		}
		if !subsumed {
			result = append(result, p)
		}
	}
	return result
}
