package updater

import (
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/client/internal/instance"
	"github.com/netbirdio/netbird/client/internal/updater/installer"
)

// T-UPD-U1: a named installation never installs an update.
func TestNamedInstallationNeverInstalls(t *testing.T) {
	named, err := instance.ForPlatform("windows", "acme")
	require.NoError(t, err)

	assert.False(t, autoUpdateSupportedFor(named)(), "named installation")
	assert.Equal(t, isAutoUpdateSupported(), autoUpdateSupportedFor(instance.Default())(), "default installation")

	m := &Manager{autoUpdateSupported: autoUpdateSupportedFor(named), mgmUpdateChan: make(chan struct{}, 1)}
	m.SetVersion("0.99.0", true)
	assert.Equal(t, modeDownloadOnly, m.mode, "a forced update becomes download-only")
	assert.Error(t, m.Install(t.Context()), "TriggerUpdate is refused")
}

// SBS-UPD-03: the updater's folder is inside the installation's state folder.
func TestNamedInstallationTempDir(t *testing.T) {
	named, err := instance.ForPlatform("windows", "acme")
	require.NoError(t, err)
	instance.SetCurrent(named)
	t.Cleanup(func() { instance.SetCurrent(instance.Default()) })

	assert.Equal(t, named.StateDir()+`\tmp-install`, named.UpdaterTempDir(), "temp folder")
	if runtime.GOOS == "windows" {
		assert.Equal(t, named.UpdaterTempDir(), installer.New().TempDir(), "installer temp folder")
	}
}
