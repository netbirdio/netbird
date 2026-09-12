package auth

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestShouldUseDeviceFlow_ForcedAlwaysTrue(t *testing.T) {
	// The --use-device-auth flag relies on force=true overriding the
	// automatic PKCE-vs-device selection, even on a desktop client where
	// PKCE would otherwise be chosen.
	assert.True(t, shouldUseDeviceFlow(true, true), "force should select device flow on a desktop client")
	assert.True(t, shouldUseDeviceFlow(true, false), "force should select device flow on a non-desktop client")
}

func TestShouldUseDeviceFlow_NotForcedRespectsDesktop(t *testing.T) {
	// Without force, a desktop client must not be pushed to device flow.
	assert.False(t, shouldUseDeviceFlow(false, true), "desktop client without force should not use device flow")
}
