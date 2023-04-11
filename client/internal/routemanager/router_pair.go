package routemanager

import (
	"net/netip"

	"github.com/netbirdio/netbird/route"
)

type routerPair struct {
	ID          string
	source      string
	destination string
	masquerade  bool
}

func routeToRouterPair(source string, route *route.Route) routerPair {
	parsed := netip.MustParsePrefix(source).Masked()
	return routerPair{
		ID:          route.ID,
		source:      parsed.String(),
		destination: route.Network.Masked().String(),
		masquerade:  route.Masquerade,
	}
}
