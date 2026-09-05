//go:build ios || android

package net

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestAdvancedRouting_Mobile verifies that AdvancedRouting always returns true
// on mobile platforms.
func TestAdvancedRouting_Mobile(t *testing.T) {
	assert.True(t, AdvancedRouting(), "AdvancedRouting must always be true on mobile")
}

// TestInit_Mobile verifies that Init is a no-op and does not panic.
func TestInit_Mobile(t *testing.T) {
	// Should not panic.
	Init()
	// After Init, AdvancedRouting must still return true.
	assert.True(t, AdvancedRouting())
}

// TestSetVPNInterfaceName_Mobile verifies that SetVPNInterfaceName is a no-op
// and does not panic.
func TestSetVPNInterfaceName_Mobile(t *testing.T) {
	// Should not panic for any input.
	SetVPNInterfaceName("utun0")
	SetVPNInterfaceName("")
}

// TestGetVPNInterfaceName_Mobile verifies that GetVPNInterfaceName always
// returns an empty string on mobile.
func TestGetVPNInterfaceName_Mobile(t *testing.T) {
	// Even after a SetVPNInterfaceName call (no-op), the getter returns "".
	SetVPNInterfaceName("utun0")
	assert.Equal(t, "", GetVPNInterfaceName(), "GetVPNInterfaceName must return empty string on mobile")
}