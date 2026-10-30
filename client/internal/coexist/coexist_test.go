package coexist

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/client/iface/wgaddr"
	"github.com/netbirdio/netbird/client/internal/instance"
)

func pfx(s string) netip.Prefix { return netip.MustParsePrefix(s) }

func TestIsOverlayInterface(t *testing.T) {
	for name, want := range map[string]bool{
		"wt0": true, "wt_acme": true, "wt_x": true, "Ethernet": false, "utun100": false, "Wi-Fi": false, "WT0": false,
	} {
		assert.Equal(t, want, IsOverlayInterface(name), "interface %s", name)
	}
}

// SBS-COEX-04: an overlay that overlaps another NetBird adapter's prefix.
func TestFindOverlayConflict(t *testing.T) {
	others := []Adapter{
		{Name: "wt0", Prefixes: []netip.Prefix{pfx("10.20.0.0/16"), pfx("fd00:20::/64")}},
	}

	_, ok := FindOverlayConflict([]netip.Prefix{pfx("100.80.0.0/16")}, others)
	assert.False(t, ok, "GLOBEX and ACME do not overlap")

	c, ok := FindOverlayConflict([]netip.Prefix{pfx("10.20.0.0/16")}, others)
	require.True(t, ok, "identical overlays")
	assert.Equal(t, OverlayConflict{Adapter: "wt0", Own: pfx("10.20.0.0/16"), Other: pfx("10.20.0.0/16")}, c, "conflict")
	assert.Contains(t, c.Error(), "wt0", "error names the adapter")
	assert.Contains(t, c.Error(), "10.20.0.0/16", "error names the prefix")

	_, ok = FindOverlayConflict([]netip.Prefix{pfx("10.0.0.0/8")}, others)
	assert.True(t, ok, "a wider overlay overlaps too")

	_, ok = FindOverlayConflict([]netip.Prefix{pfx("100.80.0.0/16"), pfx("fd00:20::/48")}, others)
	assert.True(t, ok, "an IPv6 overlap counts")
}

func TestCheckOverlayOnlyForSecondary(t *testing.T) {
	primary, err := instance.ForPlatform("windows", "acme")
	require.NoError(t, err)
	primary = primary.WithRole(instance.RolePrimary)
	addr := wgaddr.Address{IP: netip.MustParseAddr("10.20.0.5"), Network: pfx("10.20.0.0/16")}
	assert.NoError(t, CheckOverlay(primary, "wt_acme", addr), "a primary is not checked")
	assert.NoError(t, CheckOverlay(instance.Default(), "wt0", addr), "the default installation is not checked")
}

// SBS-COEX-05: routes of another installation inside the overlay.
func TestPartialOverlaps(t *testing.T) {
	own := []netip.Prefix{pfx("100.80.0.0/16")}
	others := []netip.Prefix{pfx("100.80.4.0/24"), pfx("10.20.0.0/16"), pfx("100.0.0.0/8"), pfx("100.80.0.0/16")}
	assert.Equal(t, []netip.Prefix{pfx("100.80.4.0/24")}, PartialOverlaps(own, others), "only more specific routes inside the overlay")
}

// SBS-COEX-03: identical routes on another NetBird adapter.
func TestIdenticalRoutes(t *testing.T) {
	own := []netip.Prefix{pfx("192.168.77.0/24"), pfx("10.10.0.0/16")}
	others := []netip.Prefix{pfx("192.168.77.0/24"), pfx("10.10.0.0/24")}
	assert.Equal(t, []netip.Prefix{pfx("192.168.77.0/24")}, IdenticalRoutes(own, others), "identical prefixes only")
}

func TestOverlayPrefixes(t *testing.T) {
	addr := wgaddr.Address{
		IP: netip.MustParseAddr("100.80.1.2"), Network: pfx("100.80.0.0/16"),
		IPv6: netip.MustParseAddr("fd00::2"), IPv6Net: pfx("fd00::/64"),
	}
	assert.Equal(t, []netip.Prefix{pfx("100.80.0.0/16"), pfx("fd00::/64")}, OverlayPrefixes(addr), "v4 and v6")
	assert.Equal(t, []netip.Prefix{pfx("100.80.0.0/16")}, OverlayPrefixes(wgaddr.Address{Network: pfx("100.80.0.0/16")}), "v4 only")
}
