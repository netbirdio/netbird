//go:build darwin && !ios

package net

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

// resetBoundIfaces clears global state before each test that manipulates it.
func resetBoundIfaces(t *testing.T) {
	t.Helper()
	ClearBoundInterfaces()
	t.Cleanup(ClearBoundInterfaces)
}

// TestIsV6Network verifies the isV6Network helper correctly identifies v6 networks.
func TestIsV6Network(t *testing.T) {
	tests := []struct {
		network string
		want    bool
	}{
		{"tcp6", true},
		{"udp6", true},
		{"ip6", true},
		{"tcp", false},
		{"udp", false},
		{"tcp4", false},
		{"udp4", false},
		{"ip4", false},
		{"ip", false},
		{"", false},
		// Arbitrary suffix-6 strings
		{"unix6", true},
		{"custom6", true},
	}

	for _, tt := range tests {
		t.Run(tt.network, func(t *testing.T) {
			assert.Equal(t, tt.want, isV6Network(tt.network))
		})
	}
}

// TestSetBoundInterface_AFINET sets boundIface4 via AF_INET.
func TestSetBoundInterface_AFINET(t *testing.T) {
	resetBoundIfaces(t)

	iface := &net.Interface{Index: 5, Name: "en0"}
	SetBoundInterface(unix.AF_INET, iface)

	boundIfaceMu.RLock()
	got := boundIface4
	boundIfaceMu.RUnlock()

	require.NotNil(t, got)
	assert.Equal(t, 5, got.Index)
	assert.Equal(t, "en0", got.Name)
}

// TestSetBoundInterface_AFINET6 sets boundIface6 via AF_INET6.
func TestSetBoundInterface_AFINET6(t *testing.T) {
	resetBoundIfaces(t)

	iface := &net.Interface{Index: 7, Name: "utun0"}
	SetBoundInterface(unix.AF_INET6, iface)

	boundIfaceMu.RLock()
	got := boundIface6
	boundIfaceMu.RUnlock()

	require.NotNil(t, got)
	assert.Equal(t, 7, got.Index)
	assert.Equal(t, "utun0", got.Name)
}

// TestSetBoundInterface_Nil verifies nil iface is rejected without panicking.
func TestSetBoundInterface_Nil(t *testing.T) {
	resetBoundIfaces(t)

	// Should not panic, just log a warning and leave existing values untouched.
	iface := &net.Interface{Index: 1, Name: "en1"}
	SetBoundInterface(unix.AF_INET, iface)

	SetBoundInterface(unix.AF_INET, nil)

	boundIfaceMu.RLock()
	got := boundIface4
	boundIfaceMu.RUnlock()

	// Value must be unchanged after the rejected nil write.
	require.NotNil(t, got)
	assert.Equal(t, 1, got.Index)
}

// TestSetBoundInterface_UnknownAF verifies unknown address families are ignored.
func TestSetBoundInterface_UnknownAF(t *testing.T) {
	resetBoundIfaces(t)

	iface := &net.Interface{Index: 3, Name: "en2"}
	// Use an address family that is not AF_INET or AF_INET6.
	SetBoundInterface(99, iface)

	boundIfaceMu.RLock()
	v4, v6 := boundIface4, boundIface6
	boundIfaceMu.RUnlock()

	assert.Nil(t, v4, "unknown AF must not populate boundIface4")
	assert.Nil(t, v6, "unknown AF must not populate boundIface6")
}

// TestClearBoundInterfaces clears both cached interfaces.
func TestClearBoundInterfaces(t *testing.T) {
	iface4 := &net.Interface{Index: 1, Name: "en0"}
	iface6 := &net.Interface{Index: 2, Name: "en0"}

	SetBoundInterface(unix.AF_INET, iface4)
	SetBoundInterface(unix.AF_INET6, iface6)

	ClearBoundInterfaces()

	boundIfaceMu.RLock()
	v4, v6 := boundIface4, boundIface6
	boundIfaceMu.RUnlock()

	assert.Nil(t, v4, "boundIface4 must be nil after clear")
	assert.Nil(t, v6, "boundIface6 must be nil after clear")
}

// TestClearBoundInterfaces_Idempotent verifies clearing twice does not panic.
func TestClearBoundInterfaces_Idempotent(t *testing.T) {
	ClearBoundInterfaces()
	ClearBoundInterfaces()

	boundIfaceMu.RLock()
	v4, v6 := boundIface4, boundIface6
	boundIfaceMu.RUnlock()

	assert.Nil(t, v4)
	assert.Nil(t, v6)
}

// TestBoundInterfaceFor_PreferSameFamily verifies v4 iface returned for "tcp" and
// v6 iface returned for "tcp6" when both slots are populated.
func TestBoundInterfaceFor_PreferSameFamily(t *testing.T) {
	resetBoundIfaces(t)

	en0 := &net.Interface{Index: 1, Name: "en0"}
	en1 := &net.Interface{Index: 2, Name: "en1"}
	SetBoundInterface(unix.AF_INET, en0)
	SetBoundInterface(unix.AF_INET6, en1)

	got4 := boundInterfaceFor("tcp", "1.2.3.4:80")
	require.NotNil(t, got4)
	assert.Equal(t, "en0", got4.Name, "tcp should prefer v4 interface")

	got6 := boundInterfaceFor("tcp6", "[::1]:80")
	require.NotNil(t, got6)
	assert.Equal(t, "en1", got6.Name, "tcp6 should prefer v6 interface")
}

// TestBoundInterfaceFor_FallbackToOtherFamily returns the other family's iface
// when the preferred slot is empty.
func TestBoundInterfaceFor_FallbackToOtherFamily(t *testing.T) {
	resetBoundIfaces(t)

	// Only v4 populated.
	en0 := &net.Interface{Index: 1, Name: "en0"}
	SetBoundInterface(unix.AF_INET, en0)

	// Asking for v6 should fall back to en0.
	got := boundInterfaceFor("tcp6", "[::1]:80")
	require.NotNil(t, got)
	assert.Equal(t, "en0", got.Name)
}

// TestBoundInterfaceFor_BothEmpty returns nil when both slots are empty.
func TestBoundInterfaceFor_BothEmpty(t *testing.T) {
	resetBoundIfaces(t)

	got := boundInterfaceFor("tcp", "1.2.3.4:80")
	assert.Nil(t, got)

	got6 := boundInterfaceFor("tcp6", "[::1]:80")
	assert.Nil(t, got6)
}

// TestZoneInterface_Empty returns nil for empty address.
func TestZoneInterface_Empty(t *testing.T) {
	iface := zoneInterface("")
	assert.Nil(t, iface)
}

// TestZoneInterface_NoZone returns nil when address has no zone.
func TestZoneInterface_NoZone(t *testing.T) {
	// Regular IPv4 address with port — no zone identifier.
	iface := zoneInterface("192.168.1.1:80")
	assert.Nil(t, iface)

	// Regular IPv6 address with port — no zone identifier.
	iface = zoneInterface("[2001:db8::1]:80")
	assert.Nil(t, iface)

	// Plain IPv6 address without port or zone.
	iface = zoneInterface("2001:db8::1")
	assert.Nil(t, iface)
}

// TestZoneInterface_InvalidAddress returns nil for completely invalid strings.
func TestZoneInterface_InvalidAddress(t *testing.T) {
	iface := zoneInterface("not-an-address")
	assert.Nil(t, iface)

	iface = zoneInterface("::::")
	assert.Nil(t, iface)
}

// TestZoneInterface_NonExistentZoneName returns nil for a zone name that does
// not correspond to a real interface on the host.
func TestZoneInterface_NonExistentZoneName(t *testing.T) {
	// Use an interface name that is very unlikely to exist.
	iface := zoneInterface("fe80::1%nonexistentiface99999")
	assert.Nil(t, iface)
}

// TestZoneInterface_NonExistentZoneIndex returns nil for a zone expressed as an
// integer index that is not in use.
func TestZoneInterface_NonExistentZoneIndex(t *testing.T) {
	// Interface index 999999 should not exist on any test machine.
	iface := zoneInterface("fe80::1%999999")
	assert.Nil(t, iface)
}

// TestBoundInterfaceFor_SetThenClear verifies that clearing state causes
// boundInterfaceFor to return nil afterwards.
func TestBoundInterfaceFor_SetThenClear(t *testing.T) {
	resetBoundIfaces(t)

	en0 := &net.Interface{Index: 1, Name: "en0"}
	SetBoundInterface(unix.AF_INET, en0)

	got := boundInterfaceFor("tcp", "1.2.3.4:80")
	require.NotNil(t, got, "should return iface while set")

	ClearBoundInterfaces()

	got = boundInterfaceFor("tcp", "1.2.3.4:80")
	assert.Nil(t, got, "should return nil after clear")
}

// TestSetBoundInterface_OverwritesPreviousValue verifies that calling
// SetBoundInterface again updates the stored pointer.
func TestSetBoundInterface_OverwritesPreviousValue(t *testing.T) {
	resetBoundIfaces(t)

	first := &net.Interface{Index: 1, Name: "en0"}
	second := &net.Interface{Index: 3, Name: "en1"}

	SetBoundInterface(unix.AF_INET, first)
	SetBoundInterface(unix.AF_INET, second)

	boundIfaceMu.RLock()
	got := boundIface4
	boundIfaceMu.RUnlock()

	require.NotNil(t, got)
	assert.Equal(t, "en1", got.Name, "second call should overwrite first")
}

// TestBoundInterfaceFor_OnlyV6Populated returns v6 iface for v4 network
// when only v6 slot is filled.
func TestBoundInterfaceFor_OnlyV6Populated(t *testing.T) {
	resetBoundIfaces(t)

	en1 := &net.Interface{Index: 2, Name: "en1"}
	SetBoundInterface(unix.AF_INET6, en1)

	// v4 network, v4 slot empty → should fall back to v6 slot.
	got := boundInterfaceFor("tcp", "1.2.3.4:80")
	require.NotNil(t, got)
	assert.Equal(t, "en1", got.Name)
}