package static

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/client/iface/device"
	"github.com/netbirdio/netbird/client/iface/wgaddr"
	"github.com/netbirdio/netbird/client/iface/wgbackend"
	"github.com/netbirdio/netbird/client/internal/routemanager/common"
	"github.com/netbirdio/netbird/client/internal/routemanager/refcounter"
	"github.com/netbirdio/netbird/route"
)

// hostState stands in for the OS routing table and the interface's allowed IPs, which the
// real refcounters program through their add and remove functions.
type hostState struct {
	routes        map[netip.Prefix]struct{}
	allowedIPs    map[netip.Prefix]string
	failRoute     netip.Prefix
	failAllowedIP netip.Prefix
}

func newHostState() *hostState {
	return &hostState{
		routes:     map[netip.Prefix]struct{}{},
		allowedIPs: map[netip.Prefix]string{},
	}
}

func (h *hostState) params(r *route.Route) common.HandlerParams {
	return common.HandlerParams{
		Route: r,
		RouteRefCounter: refcounter.New(
			func(prefix netip.Prefix, _ struct{}) (struct{}, error) {
				if prefix == h.failRoute {
					return struct{}{}, errors.New("route table full")
				}
				h.routes[prefix] = struct{}{}
				return struct{}{}, nil
			},
			func(prefix netip.Prefix, _ struct{}) error {
				delete(h.routes, prefix)
				return nil
			},
		),
		AllowedIPsRefCounter: refcounter.NewAllowedIPs(
			func(prefix netip.Prefix, peerKey string) (string, error) {
				if prefix == h.failAllowedIP {
					return "", errors.New("allowed IP refused")
				}
				h.allowedIPs[prefix] = peerKey
				return peerKey, nil
			},
			func(prefix netip.Prefix, _ string) error {
				delete(h.allowedIPs, prefix)
				return nil
			},
		),
	}
}

// testWGIface reports an interface address; the handlers use nothing else of it.
type testWGIface struct {
	addr wgaddr.Address
}

func (w *testWGIface) AddAllowedIP(string, netip.Prefix) error    { return nil }
func (w *testWGIface) RemoveAllowedIP(string, netip.Prefix) error { return nil }
func (w *testWGIface) Name() string                               { return "wt-test" }
func (w *testWGIface) Address() wgaddr.Address                    { return w.addr }
func (w *testWGIface) ToInterface() *net.Interface                { return nil }
func (w *testWGIface) IsUserspaceBind() bool                      { return false }
func (w *testWGIface) GetFilter() device.PacketFilter             { return nil }
func (w *testWGIface) GetDevice() *device.FilteredDevice          { return nil }
func (w *testWGIface) GetNet() *wgbackend.NetstackNet             { return nil }
func (w *testWGIface) GetInterfaceGUIDString() (string, error)    { return "", nil }

func TestRoute_InstallsEveryPrefix(t *testing.T) {
	host := newHostState()
	prefixes := []netip.Prefix{
		netip.MustParsePrefix("10.0.0.0/24"),
		netip.MustParsePrefix("10.1.0.0/16"),
	}
	r := newRoute(host.params(&route.Route{Network: prefixes[0]}), prefixes)

	require.NoError(t, r.AddRoute(context.Background()))
	assert.Len(t, host.routes, 2, "every prefix should get an OS route")

	require.NoError(t, r.AddAllowedIPs("peerA"))
	assert.Equal(t, map[netip.Prefix]string{prefixes[0]: "peerA", prefixes[1]: "peerA"}, host.allowedIPs,
		"every prefix should be routed to the chosen peer")

	require.NoError(t, r.RemoveAllowedIPs())
	assert.Empty(t, host.allowedIPs, "removing the allowed IPs should release every prefix")

	require.NoError(t, r.RemoveRoute())
	assert.Empty(t, host.routes, "removing the route should release every prefix")
}

func TestRoute_AddRouteRollsBackOnFailure(t *testing.T) {
	host := newHostState()
	host.failRoute = netip.MustParsePrefix("10.1.0.0/16")
	prefixes := []netip.Prefix{netip.MustParsePrefix("10.0.0.0/24"), host.failRoute}
	r := newRoute(host.params(&route.Route{Network: prefixes[0]}), prefixes)

	require.Error(t, r.AddRoute(context.Background()))
	assert.Empty(t, host.routes, "a failed add must not leave earlier prefixes installed")
}

func TestRoute_AddAllowedIPsRollsBackOnFailure(t *testing.T) {
	host := newHostState()
	host.failAllowedIP = netip.MustParsePrefix("10.1.0.0/16")
	prefixes := []netip.Prefix{netip.MustParsePrefix("10.0.0.0/24"), host.failAllowedIP}
	r := newRoute(host.params(&route.Route{Network: prefixes[0]}), prefixes)

	require.Error(t, r.AddAllowedIPs("peerA"))
	assert.Empty(t, host.allowedIPs, "a failed add must not leave earlier prefixes routed to the peer")
}

func TestCountryRoute(t *testing.T) {
	usV4 := netip.MustParsePrefix("8.8.8.0/24")
	usV6 := netip.MustParsePrefix("2001:4860::/32")
	caV4 := netip.MustParsePrefix("24.48.0.0/12")
	fetch := func(_ context.Context, country string) ([]netip.Prefix, error) {
		switch country {
		case "US":
			return []netip.Prefix{usV4, usV6}, nil
		case "CA":
			return []netip.Prefix{caV4}, nil
		default:
			return nil, errors.New("unknown country")
		}
	}
	v4Only := wgaddr.MustParseWGAddress("100.64.0.1/16")
	dualStack := v4Only
	dualStack.IPv6 = netip.MustParseAddr("fd00::1")
	dualStack.IPv6Net = netip.MustParsePrefix("fd00::/64")

	tests := []struct {
		name      string
		countries []string
		address   wgaddr.Address
		expected  []netip.Prefix
		expectErr bool
	}{
		{name: "dual stack interface", countries: []string{"US", "CA"}, address: dualStack, expected: []netip.Prefix{usV4, usV6, caV4}},
		{name: "v4 only interface skips v6 prefixes", countries: []string{"US", "CA"}, address: v4Only, expected: []netip.Prefix{usV4, caV4}},
		{name: "fetch failure installs nothing", countries: []string{"US", "ZZ"}, address: dualStack, expectErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			host := newHostState()
			params := host.params(&route.Route{
				NetID:       "us-exit",
				Network:     netip.MustParsePrefix("192.0.2.0/32"),
				NetworkType: route.CountryNetwork,
				Countries:   tt.countries,
			})
			params.WgInterface = &testWGIface{addr: tt.address}
			params.CountryPrefixes = fetch
			r := NewCountryRoute(params)

			err := r.AddRoute(context.Background())
			if tt.expectErr {
				require.Error(t, err)
				assert.Empty(t, host.routes, "nothing should be installed when a country cannot be resolved")
				assert.ErrorIs(t, r.AddAllowedIPs("peerA"), errCountryPrefixesNotResolved)
				return
			}
			require.NoError(t, err)

			require.NoError(t, r.AddAllowedIPs("peerA"))
			var routed []netip.Prefix
			for prefix, peer := range host.allowedIPs {
				assert.Equal(t, "peerA", peer, "prefix %s should go to the chosen peer", prefix)
				routed = append(routed, prefix)
			}
			assert.ElementsMatch(t, tt.expected, routed, "routed prefixes")
			assert.Len(t, host.routes, len(tt.expected), "every routed prefix needs an OS route")

			require.NoError(t, r.RemoveAllowedIPs())
			require.NoError(t, r.RemoveRoute())
			assert.Empty(t, host.routes)
			assert.Empty(t, host.allowedIPs)
		})
	}
}

// TestCountryRoute_SharedLookup adds two routes that both name US through one cached lookup, as
// the route manager does within an update: US is fetched once, and the v4-only route dropping
// the v6 prefixes must not change the prefixes the other route installs.
func TestCountryRoute_SharedLookup(t *testing.T) {
	usV4 := netip.MustParsePrefix("8.8.8.0/24")
	usV6 := netip.MustParsePrefix("2001:4860::/32")
	fetches := map[string]int{}
	fetch := func(_ context.Context, country string) ([]netip.Prefix, error) {
		fetches[country]++
		return []netip.Prefix{usV4, usV6}, nil
	}
	cached, release := common.CachedCountryPrefixes(fetch)
	defer release()

	v4Only := wgaddr.MustParseWGAddress("100.64.0.1/16")
	dualStack := v4Only
	dualStack.IPv6 = netip.MustParseAddr("fd00::1")
	dualStack.IPv6Net = netip.MustParsePrefix("fd00::/64")

	newHost := func(address wgaddr.Address, netID route.NetID) (*hostState, *CountryRoute) {
		host := newHostState()
		params := host.params(&route.Route{
			NetID:       netID,
			Network:     netip.MustParsePrefix("192.0.2.0/32"),
			NetworkType: route.CountryNetwork,
			Countries:   []string{"US"},
		})
		params.WgInterface = &testWGIface{addr: address}
		params.CountryPrefixes = cached
		return host, NewCountryRoute(params)
	}
	v4Host, v4Route := newHost(v4Only, "us-exit-a")
	dualHost, dualRoute := newHost(dualStack, "us-exit-b")

	require.NoError(t, v4Route.AddRoute(context.Background()))
	require.NoError(t, dualRoute.AddRoute(context.Background()))

	assert.Equal(t, map[string]int{"US": 1}, fetches, "a country shared by routes should be fetched once")
	assert.Equal(t, map[netip.Prefix]struct{}{usV4: {}}, v4Host.routes, "the v4-only route should install the v4 prefix only")
	assert.Equal(t, map[netip.Prefix]struct{}{usV4: {}, usV6: {}}, dualHost.routes,
		"the dual stack route should install both prefixes despite the other route's filtering")
}
