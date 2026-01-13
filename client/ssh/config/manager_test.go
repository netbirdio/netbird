package config

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestManager_SetupSSHClientConfig(t *testing.T) {
	// Create temporary directory for test
	tempDir, err := os.MkdirTemp("", "netbird-ssh-config-test")
	require.NoError(t, err)
	defer func() { assert.NoError(t, os.RemoveAll(tempDir)) }()

	// Override manager paths to use temp directory
	manager := &Manager{
		sshConfigDir:  filepath.Join(tempDir, "ssh_config.d"),
		sshConfigFile: "99-netbird.conf",
	}

	// Test SSH config generation with peers
	peers := []PeerSSHInfo{
		{
			Hostname: "peer1",
			IP:       "100.125.1.1",
			FQDN:     "peer1.nb.internal",
		},
		{
			Hostname: "peer2",
			IP:       "100.125.1.2",
			FQDN:     "peer2.nb.internal",
		},
	}

	err = manager.SetupSSHClientConfig(peers)
	require.NoError(t, err)

	// Read generated config
	configPath := filepath.Join(manager.sshConfigDir, manager.sshConfigFile)
	content, err := os.ReadFile(configPath)
	require.NoError(t, err)

	configStr := string(content)

	// Verify the basic SSH config structure exists
	assert.Contains(t, configStr, "# NetBird SSH client configuration")
	assert.Contains(t, configStr, "Generated automatically - do not edit manually")

	// Check that peer hostnames are included
	assert.Contains(t, configStr, "100.125.1.1")
	assert.Contains(t, configStr, "100.125.1.2")
	assert.Contains(t, configStr, "peer1.nb.internal")
	assert.Contains(t, configStr, "peer2.nb.internal")

	// Check platform-specific UserKnownHostsFile
	if runtime.GOOS == "windows" {
		assert.Contains(t, configStr, "UserKnownHostsFile NUL")
	} else {
		assert.Contains(t, configStr, "UserKnownHostsFile /dev/null")
	}
}

func TestGetSystemSSHConfigDir(t *testing.T) {
	configDir := getSystemSSHConfigDir()

	// Path should not be empty
	assert.NotEmpty(t, configDir)

	// Should be an absolute path
	assert.True(t, filepath.IsAbs(configDir))

	// On Unix systems, should start with /etc
	// On Windows, should contain ProgramData
	if runtime.GOOS == "windows" {
		assert.Contains(t, strings.ToLower(configDir), "programdata")
	} else {
		assert.Contains(t, configDir, "/etc/ssh")
	}
}

func TestManager_PeerLimit(t *testing.T) {
	// Create temporary directory for test
	tempDir, err := os.MkdirTemp("", "netbird-ssh-config-test")
	require.NoError(t, err)
	defer func() { assert.NoError(t, os.RemoveAll(tempDir)) }()

	// Override manager paths to use temp directory
	manager := &Manager{
		sshConfigDir:  filepath.Join(tempDir, "ssh_config.d"),
		sshConfigFile: "99-netbird.conf",
	}

	// Generate many peers (more than limit)
	var peers []PeerSSHInfo
	for i := 0; i < MaxPeersForSSHConfig+10; i++ {
		peers = append(peers, PeerSSHInfo{
			Hostname: fmt.Sprintf("peer%d", i),
			IP:       fmt.Sprintf("100.125.1.%d", i%254+1),
			FQDN:     fmt.Sprintf("peer%d.nb.internal", i),
		})
	}

	// Test that SSH config generation is skipped when too many peers
	err = manager.SetupSSHClientConfig(peers)
	require.NoError(t, err)

	// Config should not be created due to peer limit
	configPath := filepath.Join(manager.sshConfigDir, manager.sshConfigFile)
	_, err = os.Stat(configPath)
	assert.True(t, os.IsNotExist(err), "SSH config should not be created with too many peers")
}

func TestManager_ForcedSSHConfig(t *testing.T) {
	// Set force environment variable
	t.Setenv(EnvForceSSHConfig, "true")

	// Create temporary directory for test
	tempDir, err := os.MkdirTemp("", "netbird-ssh-config-test")
	require.NoError(t, err)
	defer func() { assert.NoError(t, os.RemoveAll(tempDir)) }()

	// Override manager paths to use temp directory
	manager := &Manager{
		sshConfigDir:  filepath.Join(tempDir, "ssh_config.d"),
		sshConfigFile: "99-netbird.conf",
	}

	// Generate many peers (more than limit)
	var peers []PeerSSHInfo
	for i := 0; i < MaxPeersForSSHConfig+10; i++ {
		peers = append(peers, PeerSSHInfo{
			Hostname: fmt.Sprintf("peer%d", i),
			IP:       fmt.Sprintf("100.125.1.%d", i%254+1),
			FQDN:     fmt.Sprintf("peer%d.nb.internal", i),
		})
	}

	// Test that SSH config generation is forced despite many peers
	err = manager.SetupSSHClientConfig(peers)
	require.NoError(t, err)

	// Config should be created despite peer limit due to force flag
	configPath := filepath.Join(manager.sshConfigDir, manager.sshConfigFile)
	_, err = os.Stat(configPath)
	require.NoError(t, err, "SSH config should be created when forced")

	// Verify config contains peer hostnames
	content, err := os.ReadFile(configPath)
	require.NoError(t, err)
	configStr := string(content)
	assert.Contains(t, configStr, "peer0.nb.internal")
	assert.Contains(t, configStr, "peer1.nb.internal")
}
