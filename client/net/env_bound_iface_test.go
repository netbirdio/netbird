//go:build (darwin && !ios) || windows

package net

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// resetAdvancedRoutingState resets the package-level advancedRoutingSupported variable
// and cleans up after the test.
func resetAdvancedRoutingState(t *testing.T) {
	t.Helper()
	orig := advancedRoutingSupported
	t.Cleanup(func() { advancedRoutingSupported = orig })
}

// TestCheckAdvancedRoutingSupport_LegacyRoutingTrue verifies that setting
// NB_USE_LEGACY_ROUTING=true disables advanced routing.
func TestCheckAdvancedRoutingSupport_LegacyRoutingTrue(t *testing.T) {
	t.Setenv(envUseLegacyRouting, "true")
	assert.False(t, checkAdvancedRoutingSupport())
}

// TestCheckAdvancedRoutingSupport_LegacyRoutingFalse verifies that
// NB_USE_LEGACY_ROUTING=false still allows advanced routing when netstack is off.
func TestCheckAdvancedRoutingSupport_LegacyRoutingFalse(t *testing.T) {
	t.Setenv(envUseLegacyRouting, "false")
	t.Setenv("NB_USE_NETSTACK_MODE", "false")
	assert.True(t, checkAdvancedRoutingSupport())
}

// TestCheckAdvancedRoutingSupport_LegacyRoutingInvalid verifies that an invalid
// value for NB_USE_LEGACY_ROUTING is ignored (treated as false), so advanced
// routing remains enabled when netstack is off.
func TestCheckAdvancedRoutingSupport_LegacyRoutingInvalid(t *testing.T) {
	t.Setenv(envUseLegacyRouting, "notabool")
	t.Setenv("NB_USE_NETSTACK_MODE", "false")
	// The invalid value is ignored; the default (false) is kept, so advanced routing
	// is not suppressed by the legacy-routing flag.
	assert.True(t, checkAdvancedRoutingSupport())
}

// TestCheckAdvancedRoutingSupport_NetstackEnabled verifies that netstack mode
// disables advanced routing.
func TestCheckAdvancedRoutingSupport_NetstackEnabled(t *testing.T) {
	t.Setenv(envUseLegacyRouting, "false")
	t.Setenv("NB_USE_NETSTACK_MODE", "true")
	assert.False(t, checkAdvancedRoutingSupport())
}

// TestCheckAdvancedRoutingSupport_NoEnvVars verifies that with no env overrides
// advanced routing is supported (the happy path).
func TestCheckAdvancedRoutingSupport_NoEnvVars(t *testing.T) {
	// Unset both controlling variables so we hit the default path.
	t.Setenv(envUseLegacyRouting, "")
	t.Setenv("NB_USE_NETSTACK_MODE", "false")
	assert.True(t, checkAdvancedRoutingSupport())
}

// TestCheckAdvancedRoutingSupport_LegacyRoutingEmptyString verifies that an
// empty NB_USE_LEGACY_ROUTING is treated as "not set" and does not disable
// advanced routing.
func TestCheckAdvancedRoutingSupport_LegacyRoutingEmptyString(t *testing.T) {
	t.Setenv(envUseLegacyRouting, "")
	t.Setenv("NB_USE_NETSTACK_MODE", "false")
	assert.True(t, checkAdvancedRoutingSupport())
}

// TestAdvancedRouting_ReflectsInit verifies that after calling Init() with
// NB_USE_LEGACY_ROUTING=true, AdvancedRouting() returns false.
func TestAdvancedRouting_ReflectsInit(t *testing.T) {
	resetAdvancedRoutingState(t)

	t.Setenv(envUseLegacyRouting, "true")
	Init()

	assert.False(t, AdvancedRouting(), "AdvancedRouting should return false after Init with legacy routing")
}

// TestAdvancedRouting_ReflectsInit_Advanced verifies that after calling Init()
// without legacy overrides, AdvancedRouting() returns true.
func TestAdvancedRouting_ReflectsInit_Advanced(t *testing.T) {
	resetAdvancedRoutingState(t)

	t.Setenv(envUseLegacyRouting, "false")
	t.Setenv("NB_USE_NETSTACK_MODE", "false")
	Init()

	assert.True(t, AdvancedRouting(), "AdvancedRouting should return true after Init without legacy overrides")
}

// TestSetAndGetVPNInterfaceName verifies SetVPNInterfaceName and GetVPNInterfaceName
// are consistent.
func TestSetAndGetVPNInterfaceName(t *testing.T) {
	orig := GetVPNInterfaceName()
	t.Cleanup(func() { SetVPNInterfaceName(orig) })

	SetVPNInterfaceName("utun3")
	assert.Equal(t, "utun3", GetVPNInterfaceName())
}

// TestSetVPNInterfaceName_Empty verifies that setting an empty name is accepted.
func TestSetVPNInterfaceName_Empty(t *testing.T) {
	orig := GetVPNInterfaceName()
	t.Cleanup(func() { SetVPNInterfaceName(orig) })

	SetVPNInterfaceName("")
	assert.Equal(t, "", GetVPNInterfaceName())
}

// TestSetVPNInterfaceName_OverwritesPrevious verifies that the second call wins.
func TestSetVPNInterfaceName_OverwritesPrevious(t *testing.T) {
	orig := GetVPNInterfaceName()
	t.Cleanup(func() { SetVPNInterfaceName(orig) })

	SetVPNInterfaceName("utun1")
	SetVPNInterfaceName("utun9")
	assert.Equal(t, "utun9", GetVPNInterfaceName())
}