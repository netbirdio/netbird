package ipcauth

import (
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/client/internal/instance"
)

// T-CLI-U1: suggested commands address the installation that suggests them, and
// the default installation's text is unchanged.
func TestSuggestedCommandsCarryInstallation(t *testing.T) {
	wantDefault := "netbird down; netbird up --enable-ssh-root"
	if runtime.GOOS != "windows" {
		wantDefault = "sudo netbird down; sudo netbird up --enable-ssh-root"
	}
	assert.Equal(t, wantDefault, UpCommand("--enable-ssh-root"), "default installation")
	assert.Equal(t, "netbird logout", CLICommand("logout"), "default installation")

	named, err := instance.ForPlatform("windows", "acme")
	require.NoError(t, err)
	instance.SetCurrent(named)
	t.Cleanup(func() { instance.SetCurrent(instance.Default()) })

	wantNamed := "netbird --instance acme down; netbird --instance acme up --enable-ssh-root"
	if runtime.GOOS != "windows" {
		wantNamed = "sudo netbird --instance acme down; sudo netbird --instance acme up --enable-ssh-root"
	}
	assert.Equal(t, wantNamed, UpCommand("--enable-ssh-root"), "named installation")
	assert.Equal(t, "netbird --instance acme logout", CLICommand("logout"), "named installation")
}
