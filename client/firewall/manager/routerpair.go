package manager

import (
	"net/netip"

	"github.com/netbirdio/netbird/route"
)

type RouterPair struct {
	ID          route.ID
	Source      Network
	Destination Network
	Masquerade  bool
	Inverse     bool
}

func GetInversePair(pair RouterPair) RouterPair {
	return RouterPair{
		ID: pair.ID,
		// invert Source/Destination
		Source:      pair.Destination,
		Destination: pair.Source,
		Masquerade:  pair.Masquerade,
		Inverse:     true,
	}
}

// NeedsV6NATDuplicate reports whether a v4 NAT pair should be duplicated to
// the v6 table. This is true for DomainSets (resolved IPs can be either
// family) and for the v4 default wildcard 0.0.0.0/0 used by the legacy DNS
// resolver path for dynamic routes.
func NeedsV6NATDuplicate(pair RouterPair) bool {
	if pair.Destination.IsSet() {
		return true
	}
	return pair.Destination.IsPrefix() &&
		pair.Destination.Prefix.Bits() == 0 &&
		pair.Destination.Prefix.Addr().Is4()
}

// ToV6NatPair creates a v6 counterpart of a v4 NAT pair with `::/0` source
// and, for prefix destinations, `::/0` destination.
func ToV6NatPair(pair RouterPair) RouterPair {
	v6 := pair
	v6.Source = Network{Prefix: netip.PrefixFrom(netip.IPv6Unspecified(), 0)}
	if v6.Destination.IsPrefix() {
		v6.Destination = Network{Prefix: netip.PrefixFrom(netip.IPv6Unspecified(), 0)}
	}
	return v6
}
