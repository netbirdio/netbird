package types

import (
	"net/netip"
	"sort"
)

// SortPrefixes sorts the given slice of netip.Prefix in place.
// It sorts first by IP address, then by prefix length (most specific to least specific).
func SortPrefixes(prefixes []netip.Prefix) {
	sort.Slice(prefixes, func(i, j int) bool {
		addrCmp := prefixes[i].Addr().Compare(prefixes[j].Addr())
		if addrCmp != 0 {
			return addrCmp < 0
		}

		// If IP addresses are the same, compare prefix lengths (longer prefixes first)
		return prefixes[i].Bits() > prefixes[j].Bits()
	})
}
