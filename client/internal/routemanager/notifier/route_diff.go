package notifier

import (
	"slices"
	"sort"

	"github.com/netbirdio/netbird/route"
)

// routePrefixes returns the distinct prefixes a route set covers, sorted.
// Duplicates are dropped deliberately: an HA group hands us one route per
// peer serving the same prefix, and the platform is given the prefix, not the
// candidates. Counting them would report a change every time a peer joins or
// leaves a group, and on Android each report renews the TUN.
func routePrefixes(routes []*route.Route) []string {
	nets := make([]string, 0, len(routes))
	for _, r := range routes {
		nets = append(nets, r.NetString())
	}
	sort.Strings(nets)
	return slices.Compact(nets)
}

// hasRouteDiff reports whether the prefixes the two route sets cover differ.
func hasRouteDiff(a []*route.Route, b []*route.Route) bool {
	return !slices.Equal(routePrefixes(a), routePrefixes(b))
}
