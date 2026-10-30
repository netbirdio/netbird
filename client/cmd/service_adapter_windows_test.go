//go:build windows

package cmd

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestHasHardwareID(t *testing.T) {
	assert.True(t, hasHardwareID([]string{"Wintun"}, wintunHardwareID), "wintun")
	assert.True(t, hasHardwareID([]string{"PCI\\VEN_8086", "WINTUN"}, wintunHardwareID), "case-insensitive, any position")
	assert.False(t, hasHardwareID([]string{"Wintun2", "ROOT\\Wintun"}, wintunHardwareID), "only an exact ID")
	assert.False(t, hasHardwareID("Wintun", wintunHardwareID), "a plain string is not a hardware ID list")
	assert.False(t, hasHardwareID(nil, wintunHardwareID), "no value")
}

// SBS-SVC-06: with no device of the derived GUID nothing is removed. The real
// device list is read, so this also runs the SetupAPI calls.
func TestRemoveAdapterByGUIDWithoutDevice(t *testing.T) {
	removed, err := removeAdapterByGUID("{00000000-0000-5000-8000-0000000000a1}")
	assert.NoError(t, err)
	assert.False(t, removed, "no adapter has this GUID")

	_, err = removeAdapterByGUID("not-a-guid")
	assert.Error(t, err, "an invalid GUID is refused")
}
