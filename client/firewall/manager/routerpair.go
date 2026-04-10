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
	// Dynamic indicates the route is domain-based. NAT rules for dynamic
	// routes are duplicated to the v6 table so that resolved AAAA records
	// are masqueraded correctly.
	Dynamic bool
}

func GetInversePair(pair RouterPair) RouterPair {
	return RouterPair{
		ID: pair.ID,
		// invert Source/Destination
		Source:      pair.Destination,
		Destination: pair.Source,
		Masquerade:  pair.Masquerade,
		Inverse:     true,
		Dynamic:     pair.Dynamic,
	}
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
