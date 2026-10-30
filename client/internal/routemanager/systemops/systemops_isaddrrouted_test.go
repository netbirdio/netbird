//go:build !android && !ios

package systemops

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"

	nbnet "github.com/netbirdio/netbird/client/net"
)

// withLegacyRouting forcibly puts the nbnet package into legacy (non-advanced)
// routing mode for the duration of the test, then restores the previous value.
func withLegacyRouting(t *testing.T) {
	t.Helper()
	t.Setenv("NB_USE_LEGACY_ROUTING", "true")
	t.Setenv("NB_USE_NETSTACK_MODE", "false")
	nbnet.Init()
	t.Cleanup(func() {
		// After the test, re-initialise with no overrides so that subsequent
		// tests start with a clean state.
		nbnet.Init()
	})
}

// withAdvancedRouting attempts to enable advanced routing for the test.
// On platforms where Init() cannot produce AdvancedRouting()=true (e.g. Linux
// without root), the calling test is skipped.
func withAdvancedRouting(t *testing.T) {
	t.Helper()
	t.Setenv("NB_USE_LEGACY_ROUTING", "false")
	t.Setenv("NB_USE_NETSTACK_MODE", "false")
	nbnet.Init()
	t.Cleanup(func() {
		nbnet.Init()
	})
	if !nbnet.AdvancedRouting() {
		t.Skip("advanced routing not available in this environment (need root or darwin)")
	}
}

// TestIsAddrRouted_AdvancedRoutingShortCircuit verifies that when
// AdvancedRouting() returns true, IsAddrRouted immediately returns
// (false, zero prefix) regardless of any VPN routes, because the WG socket is
// bound directly to the physical interface and bypasses the kernel routing table.
func TestIsAddrRouted_AdvancedRoutingShortCircuit(t *testing.T) {
	withAdvancedRouting(t)

	vpnRoutes := []netip.Prefix{
		netip.MustParsePrefix("10.0.0.0/8"),
		netip.MustParsePrefix("192.168.0.0/16"),
		netip.MustParsePrefix("0.0.0.0/0"),
		netip.MustParsePrefix("::/0"),
	}

	tests := []struct {
		name string
		addr string
	}{
		{"IPv4 matched by 10/8", "10.0.0.1"},
		{"IPv4 matched by 192.168/16", "192.168.1.1"},
		{"IPv4 caught by default", "8.8.8.8"},
		{"IPv6 caught by default", "2001:db8::1"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			addr := netip.MustParseAddr(tt.addr)
			routed, prefix := IsAddrRouted(addr, vpnRoutes)
			assert.False(t, routed, "advanced routing must short-circuit VPN route check")
			assert.Equal(t, netip.Prefix{}, prefix, "returned prefix must be zero under advanced routing")
		})
	}
}

// TestIsAddrRouted_AdvancedRouting_EmptyRoutes verifies the short-circuit with
// an empty vpnRoutes slice — the result must still be (false, zero).
func TestIsAddrRouted_AdvancedRouting_EmptyRoutes(t *testing.T) {
	withAdvancedRouting(t)

	routed, prefix := IsAddrRouted(netip.MustParseAddr("10.0.0.1"), nil)
	assert.False(t, routed)
	assert.Equal(t, netip.Prefix{}, prefix)
}

// TestIsAddrRouted_LegacyMode_NonVPNAddress verifies that under legacy routing
// an address that is not covered by any VPN prefix returns false.
func TestIsAddrRouted_LegacyMode_NonVPNAddress(t *testing.T) {
	withLegacyRouting(t)

	// 198.51.100.x (TEST-NET-2) is not normally in any routing table.
	vpnRoutes := []netip.Prefix{
		netip.MustParsePrefix("10.0.0.0/8"),
	}

	addr := netip.MustParseAddr("198.51.100.1")
	routed, _ := IsAddrRouted(addr, vpnRoutes)
	assert.False(t, routed, "address not in VPN routes should not be marked as VPN-routed")
}

// TestIsAddrRouted_LegacyMode_EmptyVPNRoutes verifies that an empty vpnRoutes
// slice always yields (false, zero prefix) even under legacy routing.
func TestIsAddrRouted_LegacyMode_EmptyVPNRoutes(t *testing.T) {
	withLegacyRouting(t)

	routed, prefix := IsAddrRouted(netip.MustParseAddr("10.0.0.1"), nil)
	assert.False(t, routed)
	assert.Equal(t, netip.Prefix{}, prefix)
}

// TestIsAddrRouted_AdvancedVsLegacy_ContrastiveBehaviour documents the
// contract difference between the two modes: with a VPN default route and an
// address that matches it, legacy mode may mark it as VPN-routed while advanced
// mode must never do so.
func TestIsAddrRouted_AdvancedVsLegacy_ContrastiveBehaviour(t *testing.T) {
	vpnRoutes := []netip.Prefix{
		netip.MustParsePrefix("0.0.0.0/0"),
	}
	addr := netip.MustParseAddr("8.8.8.8")

	// --- advanced routing: must always return false ---
	t.Run("advanced routing", func(t *testing.T) {
		withAdvancedRouting(t)
		routed, prefix := IsAddrRouted(addr, vpnRoutes)
		assert.False(t, routed, "advanced routing must bypass VPN route lookup")
		assert.Equal(t, netip.Prefix{}, prefix)
	})

	// --- legacy routing: delegates to kernel table check, does not panic ---
	t.Run("legacy routing", func(t *testing.T) {
		withLegacyRouting(t)
		// We don't assert true/false here because it depends on the host
		// routing table, but the call must not panic and must return
		// a valid (bool, prefix) pair.
		routed, prefix := IsAddrRouted(addr, vpnRoutes)
		t.Logf("legacy IsAddrRouted(%s, %v) = (%v, %v)", addr, vpnRoutes, routed, prefix)
	})
}