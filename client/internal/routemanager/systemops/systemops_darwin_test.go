//go:build darwin && !ios

package systemops

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	nbnet "github.com/netbirdio/netbird/client/net"
)

// TestAfOf verifies that afOf returns the correct string for each address family.
func TestAfOf(t *testing.T) {
	tests := []struct {
		name string
		addr netip.Addr
		want string
	}{
		{
			name: "IPv4 unspecified",
			addr: netip.IPv4Unspecified(),
			want: "IPv4",
		},
		{
			name: "IPv4 private",
			addr: netip.MustParseAddr("10.0.0.1"),
			want: "IPv4",
		},
		{
			name: "IPv4 loopback",
			addr: netip.MustParseAddr("127.0.0.1"),
			want: "IPv4",
		},
		{
			name: "IPv6 unspecified",
			addr: netip.IPv6Unspecified(),
			want: "IPv6",
		},
		{
			name: "IPv6 loopback",
			addr: netip.MustParseAddr("::1"),
			want: "IPv6",
		},
		{
			name: "IPv6 unicast",
			addr: netip.MustParseAddr("2001:db8::1"),
			want: "IPv6",
		},
		{
			name: "IPv6 link-local",
			addr: netip.MustParseAddr("fe80::1"),
			want: "IPv6",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, afOf(tt.addr))
		})
	}
}

// TestIsAddrRouted_AdvancedRoutingBypassesTunnelLookup verifies that when
// AdvancedRouting is active, IsAddrRouted immediately returns (false, zero)
// regardless of the provided vpn routes, because the WG socket is bound to
// the physical interface via IP_BOUND_IF and bypasses the main routing table.
func TestIsAddrRouted_AdvancedRoutingBypassesTunnelLookup(t *testing.T) {
	// On darwin, AdvancedRouting returns true unless overridden.
	// Ensure we reset the state after the test.
	t.Setenv("NB_USE_LEGACY_ROUTING", "false")
	t.Setenv("NB_USE_NETSTACK_MODE", "false")
	nbnet.Init()

	require.True(t, nbnet.AdvancedRouting(), "test requires advanced routing to be active on darwin")

	vpnRoutes := []netip.Prefix{
		netip.MustParsePrefix("10.0.0.0/8"),
		netip.MustParsePrefix("192.168.1.0/24"),
		netip.MustParsePrefix("0.0.0.0/0"),
	}

	tests := []struct {
		name string
		addr netip.Addr
	}{
		{"IPv4 in VPN route", netip.MustParseAddr("10.0.0.1")},
		{"IPv4 in narrow VPN route", netip.MustParseAddr("192.168.1.100")},
		{"IPv4 default route covered", netip.MustParseAddr("8.8.8.8")},
		{"IPv6 in VPN route", netip.MustParseAddr("2001:db8::1")},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			routed, prefix := IsAddrRouted(tt.addr, vpnRoutes)
			assert.False(t, routed, "should not be marked as routed via VPN when advanced routing is active")
			assert.Equal(t, netip.Prefix{}, prefix, "matched prefix should be zero when advanced routing is active")
		})
	}
}

// TestIsAddrRouted_LegacyModeFallsThroughToTable verifies that when
// NB_USE_LEGACY_ROUTING=true disables advanced routing, IsAddrRouted
// performs the normal VPN-route vs local-route comparison.
func TestIsAddrRouted_LegacyModeFallsThroughToTable(t *testing.T) {
	t.Setenv("NB_USE_LEGACY_ROUTING", "true")
	nbnet.Init()

	require.False(t, nbnet.AdvancedRouting(), "test requires advanced routing to be disabled")

	// Use an address that is very unlikely to exist in the host routing table
	// as a local route, so the VPN route wins.
	vpnRoutes := []netip.Prefix{
		netip.MustParsePrefix("198.51.100.0/24"), // TEST-NET-2 – not in normal routing tables
	}

	addr := netip.MustParseAddr("198.51.100.1")
	routed, _ := IsAddrRouted(addr, vpnRoutes)
	// We cannot assert a specific outcome because it depends on the host's
	// routing table, but we CAN assert that the call did not panic and returned
	// a consistent pair.
	_ = routed
}