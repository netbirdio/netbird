package services

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/client/internal/instance"
)

// SBS-UI-03: a named installation's window titles carry its label; the
// default installation's are unchanged.
func TestInstallationTitleSuffix(t *testing.T) {
	assert.Equal(t, "", installationTitleSuffix(), "default installation")

	named, err := instance.ForPlatform("windows", "ACME")
	require.NoError(t, err)
	instance.SetCurrent(named)
	t.Cleanup(func() { instance.SetCurrent(instance.Default()) })
	assert.Equal(t, " (ACME)", installationTitleSuffix(), "named installation")
}
