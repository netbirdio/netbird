//go:build !windows

package routemanager

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/netbirdio/netbird/client/iface/wgaddr"
	"github.com/netbirdio/netbird/client/internal/routeselector"
	"github.com/netbirdio/netbird/route"
)

func TestCurrentRouteRange_OverlayNetworkWithClientRoutesDisabled(t *testing.T) {
	m := &DefaultManager{
		wgInterface:         &reconcileWGMock{addr: wgaddr.MustParseWGAddress("100.91.96.107/16")},
		disableClientRoutes: true,
	}

	assert.Equal(t, []string{"100.91.0.0/16"}, m.CurrentRouteRange(), "overlay network must be routed even when client routes are disabled")
}

func TestCurrentRouteRange_OverlayNetworksAndClientRoutes(t *testing.T) {
	addr := wgaddr.MustParseWGAddress("100.91.96.107/16")
	addr.IPv6 = netip.MustParseAddr("fd00:1234::1")
	addr.IPv6Net = netip.MustParsePrefix("fd00:1234::/64")

	static := &route.Route{ID: "static", NetID: "lan", Network: netip.MustParsePrefix("192.168.50.0/24"), NetworkType: route.IPv4Network}
	dynamic := &route.Route{ID: "dynamic", NetID: "dyn", NetworkType: route.DomainNetwork}

	m := &DefaultManager{
		wgInterface:   &reconcileWGMock{addr: addr},
		routeSelector: routeselector.NewRouteSelector(),
		clientRoutes: route.HAMap{
			static.GetHAUniqueID():  {static},
			dynamic.GetHAUniqueID(): {dynamic},
		},
	}

	assert.Equal(t, []string{"100.91.0.0/16", "192.168.50.0/24", "fd00:1234::/64"}, m.CurrentRouteRange(), "overlay networks and static client routes must be listed, dynamic routes skipped")
}

func TestCurrentRouteRange_NoInterfaceAddress(t *testing.T) {
	m := &DefaultManager{
		wgInterface:         &reconcileWGMock{},
		disableClientRoutes: true,
	}

	assert.Empty(t, m.CurrentRouteRange(), "an unset interface address must not produce a route entry")
}

func TestCurrentRouteRange_IPv6WithoutIPv4Network(t *testing.T) {
	addr := wgaddr.Address{
		IPv6:    netip.MustParseAddr("fd00:1234::1"),
		IPv6Net: netip.MustParsePrefix("fd00:1234::/64"),
	}
	m := &DefaultManager{
		wgInterface:         &reconcileWGMock{addr: addr},
		disableClientRoutes: true,
	}

	assert.Equal(t, []string{"fd00:1234::/64"}, m.CurrentRouteRange(), "a v6 overlay network must not depend on a v4 network being set")
}

func TestCurrentRouteRange_IPv6AddressWithoutNetwork(t *testing.T) {
	addr := wgaddr.MustParseWGAddress("100.91.96.107/16")
	addr.IPv6 = netip.MustParseAddr("fd00:1234::1")

	m := &DefaultManager{
		wgInterface:         &reconcileWGMock{addr: addr},
		disableClientRoutes: true,
	}

	assert.Equal(t, []string{"100.91.0.0/16"}, m.CurrentRouteRange(), "a v6 address without a network must not produce a route entry")
}

func TestCurrentRouteRange_DeduplicatesPrefixes(t *testing.T) {
	// Two HA peers serve the same prefix, and a client route announces the overlay network itself.
	haPeerA := &route.Route{ID: "ha-a", NetID: "lan", Peer: "peer-a", Network: netip.MustParsePrefix("192.168.50.0/24"), NetworkType: route.IPv4Network}
	haPeerB := &route.Route{ID: "ha-b", NetID: "lan", Peer: "peer-b", Network: netip.MustParsePrefix("192.168.50.0/24"), NetworkType: route.IPv4Network}
	overlay := &route.Route{ID: "overlay", NetID: "overlay", Network: netip.MustParsePrefix("100.91.0.0/16"), NetworkType: route.IPv4Network}

	m := &DefaultManager{
		wgInterface:   &reconcileWGMock{addr: wgaddr.MustParseWGAddress("100.91.96.107/16")},
		routeSelector: routeselector.NewRouteSelector(),
		clientRoutes: route.HAMap{
			haPeerA.GetHAUniqueID(): {haPeerA, haPeerB},
			overlay.GetHAUniqueID(): {overlay},
		},
	}

	assert.Equal(t, []string{"100.91.0.0/16", "192.168.50.0/24"}, m.CurrentRouteRange(), "every prefix must be listed once regardless of how many routes carry it")
}
