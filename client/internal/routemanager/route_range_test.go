//go:build !windows

package routemanager

import (
	"net"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"golang.zx2c4.com/wireguard/tun/netstack"

	"github.com/netbirdio/netbird/client/iface/device"
	"github.com/netbirdio/netbird/client/iface/wgaddr"
	"github.com/netbirdio/netbird/client/internal/routeselector"
	"github.com/netbirdio/netbird/route"
)

type routeRangeWGMock struct {
	addr wgaddr.Address
}

func (m *routeRangeWGMock) AddAllowedIP(string, netip.Prefix) error    { return nil }
func (m *routeRangeWGMock) RemoveAllowedIP(string, netip.Prefix) error { return nil }
func (m *routeRangeWGMock) Name() string                               { return "utun-test" }
func (m *routeRangeWGMock) Address() wgaddr.Address                    { return m.addr }
func (m *routeRangeWGMock) ToInterface() *net.Interface                { return nil }
func (m *routeRangeWGMock) IsUserspaceBind() bool                      { return false }
func (m *routeRangeWGMock) GetFilter() device.PacketFilter             { return nil }
func (m *routeRangeWGMock) GetDevice() *device.FilteredDevice          { return nil }
func (m *routeRangeWGMock) GetNet() *netstack.Net                      { return nil }

func TestCurrentRouteRange_OverlayNetworkWithClientRoutesDisabled(t *testing.T) {
	m := &DefaultManager{
		wgInterface:         &routeRangeWGMock{addr: wgaddr.MustParseWGAddress("100.91.96.107/16")},
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
		wgInterface:   &routeRangeWGMock{addr: addr},
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
		wgInterface:         &routeRangeWGMock{},
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
		wgInterface:         &routeRangeWGMock{addr: addr},
		disableClientRoutes: true,
	}

	assert.Equal(t, []string{"fd00:1234::/64"}, m.CurrentRouteRange(), "a v6 overlay network must not depend on a v4 network being set")
}

func TestCurrentRouteRange_IPv6AddressWithoutNetwork(t *testing.T) {
	addr := wgaddr.MustParseWGAddress("100.91.96.107/16")
	addr.IPv6 = netip.MustParseAddr("fd00:1234::1")

	m := &DefaultManager{
		wgInterface:         &routeRangeWGMock{addr: addr},
		disableClientRoutes: true,
	}

	assert.Equal(t, []string{"100.91.0.0/16"}, m.CurrentRouteRange(), "a v6 address without a network must not produce a route entry")
}
