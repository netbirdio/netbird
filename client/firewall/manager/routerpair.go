package manager

import (
	"net/netip"

	"github.com/netbirdio/netbird/route"
)

type RouterPair struct {
	ID          route.ID
	Source      netip.Prefix
	Destination netip.Prefix
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
