package dns

import (
	"context"
	"fmt"
	"net/netip"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/client/internal/dns/local"
	"github.com/netbirdio/netbird/client/internal/peer"
	"github.com/netbirdio/netbird/client/internal/statemanager"
	nbdns "github.com/netbirdio/netbird/dns"
	"github.com/netbirdio/netbird/route"
	"github.com/netbirdio/netbird/shared/management/domain"
)

func TestRoutedUpstreamGatingFromEnv(t *testing.T) {
	tests := []struct {
		name     string
		value    string
		set      bool
		expected routedUpstreamGating
	}{
		{name: "unset", set: false, expected: gatingOff},
		{name: "empty", value: "", set: true, expected: gatingOff},
		{name: "off", value: "off", set: true, expected: gatingOff},
		{name: "startup", value: "startup", set: true, expected: gatingStartup},
		{name: "always", value: "always", set: true, expected: gatingAlways},
		{name: "mixed case", value: "Startup", set: true, expected: gatingStartup},
		{name: "padded", value: "  always  ", set: true, expected: gatingAlways},
		{name: "garbage falls back to off", value: "sometimes", set: true, expected: gatingOff},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// t.Setenv registers the restore, so unsetting afterwards is
			// still cleaned up when the test ends.
			t.Setenv(envRoutedUpstreamGating, tc.value)
			if !tc.set {
				require.NoError(t, os.Unsetenv(envRoutedUpstreamGating))
			}
			assert.Equal(t, tc.expected, routedUpstreamGatingFromEnv())
		})
	}
}

func nsGroupWith(ips ...string) *nbdns.NameServerGroup {
	group := &nbdns.NameServerGroup{Domains: []string{"corp.example.com"}}
	for _, ip := range ips {
		group.NameServers = append(group.NameServers, nbdns.NameServer{
			IP:     netip.MustParseAddr(ip),
			NSType: nbdns.UDPNameServerType,
			Port:   nbdns.DefaultDNSPort,
		})
	}
	return group
}

func haMapWith(prefixes ...string) route.HAMap {
	hm := route.HAMap{}
	for i, prefix := range prefixes {
		id := route.HAUniqueID(fmt.Sprintf("net%d|%s", i, prefix))
		hm[id] = []*route.Route{{
			ID:      route.ID(fmt.Sprintf("route%d", i)),
			Network: netip.MustParsePrefix(prefix),
			Peer:    "peer",
		}}
	}
	return hm
}

func TestRoutedUpstreamGateAllow(t *testing.T) {
	const routedNS = "10.10.0.53"
	const publicNS = "1.1.1.1"

	tests := []struct {
		name      string
		mode      routedUpstreamGating
		group     *nbdns.NameServerGroup
		selected  route.HAMap
		installed route.HAMap
		expected  bool
	}{
		{
			name:      "off allows a routed upstream with no installed route",
			mode:      gatingOff,
			group:     nsGroupWith(routedNS),
			selected:  haMapWith("10.10.0.0/24"),
			installed: route.HAMap{},
			expected:  true,
		},
		{
			name:      "routed with no installed route is withheld",
			mode:      gatingAlways,
			group:     nsGroupWith(routedNS),
			selected:  haMapWith("10.10.0.0/24"),
			installed: route.HAMap{},
			expected:  false,
		},
		{
			name:      "routed with an installed route is allowed",
			mode:      gatingAlways,
			group:     nsGroupWith(routedNS),
			selected:  haMapWith("10.10.0.0/24"),
			installed: haMapWith("10.10.0.0/24"),
			expected:  true,
		},
		{
			name:      "a public upstream is never withheld",
			mode:      gatingAlways,
			group:     nsGroupWith(publicNS),
			selected:  haMapWith("10.10.0.0/24"),
			installed: route.HAMap{},
			expected:  true,
		},
		{
			name:      "one usable nameserver allows the whole group",
			mode:      gatingAlways,
			group:     nsGroupWith(routedNS, publicNS),
			selected:  haMapWith("10.10.0.0/24"),
			installed: route.HAMap{},
			expected:  true,
		},
		{
			name:      "an empty nameserver list is allowed",
			mode:      gatingAlways,
			group:     nsGroupWith(),
			selected:  haMapWith("10.10.0.0/24"),
			installed: route.HAMap{},
			expected:  true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			gate := newRoutedUpstreamGate(tc.mode)
			snap := routeSnapshot{selected: tc.selected, installed: tc.installed}
			assert.Equal(t, tc.expected, gate.allow(tc.group, snap))
		})
	}
}

// A dynamic route makes the routed-ness of an upstream unprovable. Honouring
// that unknown would withhold every nameserver of any account that has one, so
// it must not gate.
func TestRoutedUpstreamGateIgnoresDynamicRoutes(t *testing.T) {
	dynamic := route.HAMap{
		"dyn|example.com": []*route.Route{{
			ID:          "dynroute",
			NetworkType: route.DomainNetwork,
			Domains:     domain.List{"example.com"},
			Peer:        "peer",
		}},
	}
	require.True(t, dynamic["dyn|example.com"][0].IsDynamic())

	gate := newRoutedUpstreamGate(gatingAlways)
	snap := routeSnapshot{selected: dynamic, installed: route.HAMap{}}
	assert.True(t, gate.allow(nsGroupWith("10.10.0.53"), snap))
}

// gatingStartup withholds a group until a route exists once, then keeps it
// configured even after the route goes away. gatingAlways withdraws it again.
func TestRoutedUpstreamGateLatch(t *testing.T) {
	group := nsGroupWith("10.10.0.53")
	selected := haMapWith("10.10.0.0/24")
	withRoute := routeSnapshot{selected: selected, installed: haMapWith("10.10.0.0/24")}
	withoutRoute := routeSnapshot{selected: selected, installed: route.HAMap{}}

	startup := newRoutedUpstreamGate(gatingStartup)
	assert.False(t, startup.allow(group, withoutRoute), "withheld before the route exists")
	assert.True(t, startup.allow(group, withRoute), "allowed once the route exists")
	assert.True(t, startup.allow(group, withoutRoute), "stays allowed after the route goes away")

	always := newRoutedUpstreamGate(gatingAlways)
	assert.False(t, always.allow(group, withoutRoute))
	assert.True(t, always.allow(group, withRoute))
	assert.False(t, always.allow(group, withoutRoute), "withdrawn again when the route goes away")
}

// A withheld group must leave no trace in the host config: neither its match
// domains nor, for a Primary group, the RouteAll flag that hands the whole
// resolver path to NetBird.
func TestApplyConfigurationWithholdsRoutedNSGroup(t *testing.T) {
	routedGroup := nsGroupWith("10.10.0.53")
	routedGroup.Domains = []string{"corp.example.com"}

	primaryGroup := nsGroupWith("10.10.0.54")
	primaryGroup.Domains = nil
	primaryGroup.Primary = true

	update := nbdns.Config{
		ServiceEnable:    true,
		NameServerGroups: []*nbdns.NameServerGroup{routedGroup, primaryGroup},
	}

	selected := haMapWith("10.10.0.0/24")

	tests := []struct {
		name             string
		mode             routedUpstreamGating
		installed        route.HAMap
		expectedDomains  []string
		expectedRouteAll bool
	}{
		{
			name:             "off keeps the group even with no route",
			mode:             gatingOff,
			installed:        route.HAMap{},
			expectedDomains:  []string{"corp.example.com."},
			expectedRouteAll: true,
		},
		{
			name:             "no route withholds domains and RouteAll",
			mode:             gatingAlways,
			installed:        route.HAMap{},
			expectedDomains:  nil,
			expectedRouteAll: false,
		},
		{
			name:             "an installed route restores both",
			mode:             gatingAlways,
			installed:        haMapWith("10.10.0.0/24"),
			expectedDomains:  []string{"corp.example.com."},
			expectedRouteAll: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var captured HostDNSConfig
			server := &DefaultServer{
				ctx:          context.Background(),
				handlerChain: NewHandlerChain(),
				hostManager: &mockHostConfigurator{
					applyDNSConfigFunc: func(config HostDNSConfig, _ *statemanager.Manager) error {
						captured = config
						return nil
					},
					supportCustomPortFunc: func() bool { return true },
					stringFunc:            func() string { return "mock" },
				},
				localResolver:      &local.Resolver{},
				service:            &mockService{},
				wgInterface:        &mocWGIface{},
				statusRecorder:     peer.NewRecorder("test"),
				extraDomains:       make(map[domain.Domain]int),
				currentConfigHash:  ^uint64(0),
				healthRefresh:      make(chan struct{}, 1),
				routedUpstreamGate: newRoutedUpstreamGate(tc.mode),
			}

			snap := routeSnapshot{selected: selected, installed: tc.installed}
			require.NoError(t, server.applyConfiguration(update, server.gateNameServerGroups(update.NameServerGroups, snap)))

			var domains []string
			for _, d := range captured.Domains {
				domains = append(domains, d.Domain)
			}
			assert.Equal(t, tc.expectedDomains, domains)
			assert.Equal(t, tc.expectedRouteAll, captured.RouteAll)
		})
	}
}

// A withheld group must also get no chain handler. Leaving one registered
// would answer SERVFAIL after its upstream times out, and SERVFAIL terminates
// the chain instead of descending to the default and fallback upstreams.
func TestBuildUpstreamHandlerUpdateSkipsWithheldGroups(t *testing.T) {
	routed := nsGroupWith("10.10.0.53")
	routed.Domains = []string{"corp.example.com"}

	public := nsGroupWith("1.1.1.1")
	public.Domains = []string{"other.example.com"}

	server := &DefaultServer{
		ctx:            context.Background(),
		handlerChain:   NewHandlerChain(),
		hostManager:    &noopHostConfigurator{},
		localResolver:  &local.Resolver{},
		service:        &mockService{},
		wgInterface:    &mocWGIface{},
		statusRecorder: peer.NewRecorder("test"),
		extraDomains:   make(map[domain.Domain]int),
	}

	groups := []*nbdns.NameServerGroup{routed, public}
	withheld := map[nsGroupID]bool{
		generateGroupKey(routed): false,
		generateGroupKey(public): true,
	}

	updates, err := server.buildUpstreamHandlerUpdate(groups, allowFuncFrom(withheld))
	require.NoError(t, err)
	t.Cleanup(func() {
		for _, u := range updates {
			u.handler.Stop()
		}
	})

	var domains []string
	for _, u := range updates {
		domains = append(domains, u.domain)
	}
	assert.Equal(t, []string{"other.example.com"}, domains)
}

// The route becoming installed after management already pushed the config is
// the ordinary startup order, so the server has to re-decide on its own rather
// than wait for the next sync.
func TestRefreshRoutedUpstreamsPicksUpANewRoute(t *testing.T) {
	group := nsGroupWith("10.10.0.53")
	group.Domains = []string{"corp.example.com"}
	update := nbdns.Config{
		ServiceEnable:    true,
		NameServerGroups: []*nbdns.NameServerGroup{group},
	}

	var captured HostDNSConfig
	installed := route.HAMap{}

	server := &DefaultServer{
		ctx:          context.Background(),
		handlerChain: NewHandlerChain(),
		hostManager: &mockHostConfigurator{
			applyDNSConfigFunc: func(config HostDNSConfig, _ *statemanager.Manager) error {
				captured = config
				return nil
			},
			supportCustomPortFunc: func() bool { return true },
			stringFunc:            func() string { return "mock" },
		},
		localResolver:      &local.Resolver{},
		service:            &mockService{},
		wgInterface:        &mocWGIface{},
		statusRecorder:     peer.NewRecorder("test"),
		extraDomains:       make(map[domain.Domain]int),
		currentConfigHash:  ^uint64(0),
		healthRefresh:      make(chan struct{}, 1),
		routeRefresh:       make(chan struct{}, 1),
		routedUpstreamGate: newRoutedUpstreamGate(gatingAlways),
		selectedRoutes:     func() route.HAMap { return haMapWith("10.10.0.0/24") },
		installedRoutes:    func() route.HAMap { return installed },
	}

	require.NoError(t, server.applyConfiguration(update, server.gateNameServerGroups(update.NameServerGroups, server.routeSnapshot())))
	assert.Empty(t, captured.Domains, "withheld while no route is installed")

	installed = haMapWith("10.10.0.0/24")
	server.refreshRoutedUpstreams()

	var domains []string
	for _, d := range captured.Domains {
		domains = append(domains, d.Domain)
	}
	assert.Equal(t, []string{"corp.example.com."}, domains)

	// And back again, because this is gatingAlways.
	installed = route.HAMap{}
	server.refreshRoutedUpstreams()
	assert.Empty(t, captured.Domains)
}

// OnInstalledRoutesChanged is called from the route manager while it holds its
// own lock, so it must never block and never re-apply inline.
func TestOnInstalledRoutesChangedNeverBlocks(t *testing.T) {
	server := &DefaultServer{
		routeRefresh:       make(chan struct{}, 1),
		routedUpstreamGate: newRoutedUpstreamGate(gatingAlways),
	}

	for i := 0; i < 5; i++ {
		server.OnInstalledRoutesChanged()
	}

	assert.Len(t, server.routeRefresh, 1, "repeated signals coalesce")
}

// A re-apply rebuilds the whole handler chain, so the default mode must not
// pay for it on every route change.
func TestOnInstalledRoutesChangedIsInertWhenGatingIsOff(t *testing.T) {
	for _, tc := range []struct {
		name string
		gate *routedUpstreamGate
	}{
		{name: "off", gate: newRoutedUpstreamGate(gatingOff)},
		{name: "no gate at all", gate: nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := &DefaultServer{
				routeRefresh:       make(chan struct{}, 1),
				routedUpstreamGate: tc.gate,
			}

			server.OnInstalledRoutesChanged()

			assert.Empty(t, server.routeRefresh, "no refresh should be signalled")
		})
	}
}

func TestRoutedUpstreamGatingString(t *testing.T) {
	assert.Equal(t, "off", gatingOff.String())
	assert.Equal(t, "startup", gatingStartup.String())
	assert.Equal(t, "always", gatingAlways.String())
}
