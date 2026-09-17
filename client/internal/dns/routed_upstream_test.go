package dns

import (
	"fmt"
	"net/netip"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

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

func TestRoutedUpstreamGatingString(t *testing.T) {
	assert.Equal(t, "off", gatingOff.String())
	assert.Equal(t, "startup", gatingStartup.String())
	assert.Equal(t, "always", gatingAlways.String())
}
