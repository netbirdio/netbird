//go:build windows

package systemops

import (
	"fmt"
	"net"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Windows compares metrics only between routes of equal prefix length, so an overlay route
// must carry a metric high enough to yield to a native route of the same length, while an
// exclusion route on a physical interface must stay low enough to outrank the overlay.
func TestSysOps_routeMetric(t *testing.T) {
	for _, metric := range []uint32{vpnRouteMetric, exclusionRouteMetric} {
		assert.GreaterOrEqual(t, metric, uint32(1), "metric must be within the range Windows accepts")
		assert.LessOrEqual(t, metric, uint32(9999), "metric must be within the range Windows accepts")
	}
	assert.Greater(t, vpnRouteMetric, exclusionRouteMetric, "an exclusion route must outrank an overlay route")

	sysOps := newSysOpsWithLocalSubnets(t)

	tests := []struct {
		name    string
		nexthop Nexthop
		want    uint32
	}{
		{
			name:    "overlay route yields to native routes",
			nexthop: Nexthop{Intf: &net.Interface{Index: 7, Name: "wt0"}},
			want:    vpnRouteMetric,
		},
		{
			name:    "exclusion route on a physical interface stays lowest",
			nexthop: Nexthop{Intf: &net.Interface{Index: 3, Name: "Ethernet"}},
			want:    exclusionRouteMetric,
		},
		{
			name:    "route without an interface is treated as an exclusion route",
			nexthop: Nexthop{IP: netip.MustParseAddr("192.168.1.1")},
			want:    exclusionRouteMetric,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, sysOps.routeMetric(tt.nexthop), "metric for %s", tt.name)
		})
	}
}

// A managed route must carry the metric it was built with and never expire.
func TestNewManagedRouteEntry(t *testing.T) {
	for _, prefix := range []string{"192.168.100.0/24", "2001:db8::/64"} {
		t.Run(prefix, func(t *testing.T) {
			route, err := newManagedRouteEntry(netip.MustParsePrefix(prefix), Nexthop{}, vpnRouteMetric)
			require.NoError(t, err, "building the route entry must succeed")

			assert.EqualValues(t, vpnRouteMetric, route.Metric, "managed route metric")
			assert.EqualValues(t, InfiniteLifetime, route.ValidLifetime, "valid lifetime")
			assert.EqualValues(t, InfiniteLifetime, route.PreferredLifetime, "preferred lifetime")
		})
	}
}

// The overlay metric only ever settles an equal-length race, and Windows ranks by the sum of
// route and interface metric. These cases pin the margin that sum leaves: a native route on
// an interface using any of Windows' automatic metrics, which top out at 65, still wins.
func TestVPNRouteMetricLosesToNativeRoute(t *testing.T) {
	const nativeRouteMetric = 256 // what Windows assigns a directly connected subnet route

	// Windows' automatic interface metric table, from 2 Gb/s down to sub-200 Kb/s links.
	automaticInterfaceMetrics := []int{5, 10, 20, 25, 35, 45, 55, 65}

	for _, ifMetric := range automaticInterfaceMetrics {
		t.Run(fmt.Sprintf("native interface metric %d", ifMetric), func(t *testing.T) {
			native := candidateRoute{interfaceIndex: 1, prefixLength: 24, routeMetric: nativeRouteMetric, interfaceMetric: ifMetric}
			overlay := candidateRoute{interfaceIndex: 2, prefixLength: 24, routeMetric: vpnRouteMetric, interfaceMetric: 5}

			candidates := []candidateRoute{overlay, native}
			sortRouteCandidates(candidates)
			assert.Equal(t, native, candidates[0], "the native route must outrank the overlay route")

			exclusion := candidateRoute{interfaceIndex: 1, prefixLength: 24, routeMetric: exclusionRouteMetric, interfaceMetric: ifMetric}
			candidates = []candidateRoute{overlay, exclusion}
			sortRouteCandidates(candidates)
			assert.Equal(t, exclusion, candidates[0], "an exclusion route must outrank the overlay route")
		})
	}
}

// A more specific overlay route still wins on prefix length whatever the metrics are, which is
// why the metric alone cannot fix host-route shadowing and the guard has to skip the install.
func TestVPNRouteMetricCannotBeatLongerPrefix(t *testing.T) {
	native := candidateRoute{interfaceIndex: 1, prefixLength: 24, routeMetric: 256, interfaceMetric: 5}
	overlayHostRoute := candidateRoute{interfaceIndex: 2, prefixLength: 32, routeMetric: vpnRouteMetric, interfaceMetric: 9999}

	candidates := []candidateRoute{native, overlayHostRoute}
	sortRouteCandidates(candidates)

	assert.Equal(t, overlayHostRoute, candidates[0],
		"longest prefix wins regardless of metric, so the guard is what prevents shadowing")
}
