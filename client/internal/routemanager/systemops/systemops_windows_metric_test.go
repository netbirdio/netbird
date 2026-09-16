//go:build windows

package systemops

import (
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
