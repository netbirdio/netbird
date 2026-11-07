package internal

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/client/internal/instance"
	"github.com/netbirdio/netbird/client/mdm"
)

// SBS-POL-04: a named installation does not connect when policy forbids named
// installations; the default installation is not affected.
func TestCheckNamedAllowed(t *testing.T) {
	named, err := instance.ForPlatform("windows", "acme")
	require.NoError(t, err)
	forbid := mdm.NewPolicy(map[string]any{mdm.KeyDisableNamedInstallations: true})

	assert.ErrorIs(t, checkNamedAllowed(named, forbid), errNamedInstallationsDisabled, "named, forbidden")
	assert.NoError(t, checkNamedAllowed(named, mdm.NewPolicy(nil)), "named, allowed")
	assert.NoError(t, checkNamedAllowed(instance.Default(), forbid), "default installation")
}

func TestCheckCoexistenceSkipsDefault(t *testing.T) {
	assert.NoError(t, checkCoexistence(nil, instance.Default(), &EngineConfig{WgIfaceName: "wt0"}), "default installation")
}
