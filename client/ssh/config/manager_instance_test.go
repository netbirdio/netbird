package config

import (
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/client/internal/instance"
)

// T-SSH-U1: a named installation writes its own file, and its commands call the
// writing executable with --instance.
func TestManager_NamedInstallation(t *testing.T) {
	named, err := instance.ForPlatform("windows", "acme")
	require.NoError(t, err)
	instance.SetCurrent(named)
	t.Cleanup(func() { instance.SetCurrent(instance.Default()) })

	m := New()
	assert.Equal(t, "99-netbird_acme.conf", m.GetSSHConfigFile(), "file name")

	m.sshConfigDir = filepath.Join(t.TempDir(), "ssh_config.d")
	require.NoError(t, m.SetupSSHClientConfig([]PeerSSHInfo{
		{Hostname: "peer1", IP: netip.MustParseAddr("100.80.1.1"), FQDN: "peer1.acme.internal"},
	}))
	content, err := os.ReadFile(filepath.Join(m.sshConfigDir, "99-netbird_acme.conf"))
	require.NoError(t, err)
	cfg := string(content)

	exe, err := m.getNetBirdExecutablePath()
	require.NoError(t, err)
	assert.Contains(t, cfg, `exec "`+exe+` --instance acme ssh detect %h %p"`, "Match exec")
	assert.Contains(t, cfg, "ProxyCommand "+exe+" --instance acme ssh proxy %h %p", "ProxyCommand")
	assert.Contains(t, cfg, "netbird --instance acme service reconfigure --service-env NB_DISABLE_SSH_CONFIG=true", "hint")
}

func TestManager_DefaultInstallationUnchanged(t *testing.T) {
	m := New()
	assert.Equal(t, "99-netbird.conf", m.GetSSHConfigFile(), "file name")

	m.sshConfigDir = filepath.Join(t.TempDir(), "ssh_config.d")
	require.NoError(t, m.SetupSSHClientConfig([]PeerSSHInfo{
		{Hostname: "peer1", IP: netip.MustParseAddr("100.80.1.1"), FQDN: "peer1.nb.internal"},
	}))
	content, err := os.ReadFile(filepath.Join(m.sshConfigDir, "99-netbird.conf"))
	require.NoError(t, err)
	cfg := string(content)

	exe, err := m.getNetBirdExecutablePath()
	require.NoError(t, err)
	assert.Contains(t, cfg, `exec "`+exe+` ssh detect %h %p"`, "Match exec")
	assert.Contains(t, cfg, "ProxyCommand "+exe+" ssh proxy %h %p", "ProxyCommand")
	assert.Contains(t, cfg, "#   netbird service reconfigure --service-env NB_DISABLE_SSH_CONFIG=true\n", "hint")
	assert.False(t, strings.Contains(cfg, "--instance"), "no installation flag")
}
