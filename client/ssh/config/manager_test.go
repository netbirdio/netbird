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
	"golang.org/x/crypto/ssh"

	nbssh "github.com/netbirdio/netbird/client/ssh"
)

func TestManager_UpdatePeerHostKeys(t *testing.T) {
	// Create temporary directory for test
	tempDir, err := os.MkdirTemp("", "netbird-ssh-config-test")
	require.NoError(t, err)
	defer func() { assert.NoError(t, os.RemoveAll(tempDir)) }()

	// Override manager paths to use temp directory
	manager := &Manager{
		sshConfigDir:   filepath.Join(tempDir, "ssh_config.d"),
		sshConfigFile:  "99-netbird.conf",
		knownHostsDir:  filepath.Join(tempDir, "ssh_known_hosts.d"),
		knownHostsFile: "99-netbird",
		userKnownHosts: "known_hosts_netbird",
	}

	// Generate test host keys
	hostKey1, err := nbssh.GeneratePrivateKey(nbssh.ED25519)
	require.NoError(t, err)
	pubKey1, err := ssh.ParsePrivateKey(hostKey1)
	require.NoError(t, err)

	hostKey2, err := nbssh.GeneratePrivateKey(nbssh.ED25519)
	require.NoError(t, err)
	pubKey2, err := ssh.ParsePrivateKey(hostKey2)
	require.NoError(t, err)

	// Create test peer host keys
	peerKeys := []PeerHostKey{
		{
			Hostname: "peer1",
			IP:       "100.125.1.1",
			FQDN:     "peer1.nb.internal",
			HostKey:  pubKey1.PublicKey(),
		},
		{
			Hostname: "peer2",
			IP:       "100.125.1.2",
			FQDN:     "peer2.nb.internal",
			HostKey:  pubKey2.PublicKey(),
		},
	}

	// Test updating known_hosts
	err = manager.UpdatePeerHostKeys(peerKeys)
	require.NoError(t, err)

	// Verify known_hosts file was created and contains entries
	knownHostsPath, err := manager.GetKnownHostsPath()
	require.NoError(t, err)

	content, err := os.ReadFile(knownHostsPath)
	require.NoError(t, err)

	contentStr := string(content)
	assert.Contains(t, contentStr, "100.125.1.1")
	assert.Contains(t, contentStr, "100.125.1.2")
	assert.Contains(t, contentStr, "peer1.nb.internal")
	assert.Contains(t, contentStr, "peer2.nb.internal")
	assert.Contains(t, contentStr, "[100.125.1.1]:22")
	assert.Contains(t, contentStr, "[100.125.1.1]:22022")

	// Test updating with empty list should preserve structure
	err = manager.UpdatePeerHostKeys([]PeerHostKey{})
	require.NoError(t, err)

	content, err = os.ReadFile(knownHostsPath)
	require.NoError(t, err)
	assert.Contains(t, string(content), "# NetBird SSH known hosts")
}

func TestManager_SetupSSHClientConfig(t *testing.T) {
	// Create temporary directory for test
	tempDir, err := os.MkdirTemp("", "netbird-ssh-config-test")
	require.NoError(t, err)
	defer func() { assert.NoError(t, os.RemoveAll(tempDir)) }()

	// Override manager paths to use temp directory
	manager := &Manager{
		sshConfigDir:   filepath.Join(tempDir, "ssh_config.d"),
		sshConfigFile:  "99-netbird.conf",
		knownHostsDir:  filepath.Join(tempDir, "ssh_known_hosts.d"),
		knownHostsFile: "99-netbird",
		userKnownHosts: "known_hosts_netbird",
	}

	// Test SSH config generation
	domains := []string{"example.nb.internal", "test.nb.internal"}
	err = manager.SetupSSHClientConfig(domains)
	require.NoError(t, err)

	// Read generated config
	configPath := filepath.Join(manager.sshConfigDir, manager.sshConfigFile)
	content, err := os.ReadFile(configPath)
	require.NoError(t, err)

	configStr := string(content)

	// Since we now use per-peer configurations instead of domain patterns,
	// we should verify the basic SSH config structure exists
	assert.Contains(t, configStr, "# NetBird SSH client configuration")
	assert.Contains(t, configStr, "Generated automatically - do not edit manually")

	// Should not contain /dev/null since we have a proper known_hosts setup
	assert.NotContains(t, configStr, "UserKnownHostsFile /dev/null")
}

func TestManager_GetHostnameVariants(t *testing.T) {
	manager := NewManager()

	peerKey := PeerHostKey{
		Hostname: "testpeer",
		IP:       "100.125.1.10",
		FQDN:     "testpeer.nb.internal",
		HostKey:  nil, // Not needed for this test
	}

	variants := manager.getHostnameVariants(peerKey)

	expectedVariants := []string{
		"100.125.1.10",
		"testpeer.nb.internal",
		"testpeer",
		"[100.125.1.10]:22",
		"[100.125.1.10]:22022",
	}

	assert.ElementsMatch(t, expectedVariants, variants)
}

func TestManager_IsNetBirdEntry(t *testing.T) {
	manager := NewManager()

	tests := []struct {
		entry    string
		expected bool
	}{
		{"100.125.1.1 ssh-ed25519 AAAAC3...", true},
		{"peer.nb.internal ssh-rsa AAAAB3...", true},
		{"test.netbird.com ssh-ed25519 AAAAC3...", true},
		{"github.com ssh-rsa AAAAB3...", false},
		{"192.168.1.1 ssh-ed25519 AAAAC3...", false},
		{"example.com ssh-rsa AAAAB3...", false},
	}

	for _, test := range tests {
		result := manager.isNetBirdEntry(test.entry)
		assert.Equal(t, test.expected, result, "Entry: %s", test.entry)
	}
}

func TestManager_FormatKnownHostsEntry(t *testing.T) {
	manager := NewManager()

	// Generate test key
	hostKeyPEM, err := nbssh.GeneratePrivateKey(nbssh.ED25519)
	require.NoError(t, err)
	parsedKey, err := ssh.ParsePrivateKey(hostKeyPEM)
	require.NoError(t, err)

	peerKey := PeerHostKey{
		Hostname: "testpeer",
		IP:       "100.125.1.10",
		FQDN:     "testpeer.nb.internal",
		HostKey:  parsedKey.PublicKey(),
	}

	entry := manager.formatKnownHostsEntry(peerKey)

	// Should contain all hostname variants
	assert.Contains(t, entry, "100.125.1.10")
	assert.Contains(t, entry, "testpeer.nb.internal")
	assert.Contains(t, entry, "testpeer")
	assert.Contains(t, entry, "[100.125.1.10]:22")
	assert.Contains(t, entry, "[100.125.1.10]:22022")

	// Should contain the public key
	keyString := string(ssh.MarshalAuthorizedKey(parsedKey.PublicKey()))
	keyString = strings.TrimSpace(keyString)
	assert.Contains(t, entry, keyString)

	// Should be properly formatted (hostnames followed by key)
	parts := strings.Fields(entry)
	assert.GreaterOrEqual(t, len(parts), 2, "Entry should have hostnames and key parts")
}

func TestManager_DirectoryFallback(t *testing.T) {
	// Create temporary directory for test where system dirs will fail
	tempDir, err := os.MkdirTemp("", "netbird-ssh-config-test")
	require.NoError(t, err)
	defer func() { assert.NoError(t, os.RemoveAll(tempDir)) }()

	// Set HOME to temp directory to control user fallback
	t.Setenv("HOME", tempDir)

	// Create manager with non-writable system directories
	// Use paths that will fail on all systems
	var failPath string
	if runtime.GOOS == "windows" {
		failPath = "NUL:" // Special device that can't be used as directory on Windows
	} else {
		failPath = "/dev/null" // Special device that can't be used as directory on Unix
	}

	manager := &Manager{
		sshConfigDir:   failPath + "/ssh_config.d", // Should fail
		sshConfigFile:  "99-netbird.conf",
		knownHostsDir:  failPath + "/ssh_known_hosts.d", // Should fail
		knownHostsFile: "99-netbird",
		userKnownHosts: "known_hosts_netbird",
	}

	// Should fall back to user directory
	knownHostsPath, err := manager.setupKnownHostsFile()
	require.NoError(t, err)

	// Get the actual user home directory as determined by os.UserHomeDir()
	userHome, err := os.UserHomeDir()
	require.NoError(t, err)

	expectedUserPath := filepath.Join(userHome, ".ssh", "known_hosts_netbird")
	assert.Equal(t, expectedUserPath, knownHostsPath)

	// Verify file was created
	_, err = os.Stat(knownHostsPath)
	require.NoError(t, err)
}

func TestGetSystemSSHPaths(t *testing.T) {
	configDir, knownHostsDir := getSystemSSHPaths()

	// Paths should not be empty
	assert.NotEmpty(t, configDir)
	assert.NotEmpty(t, knownHostsDir)

	// Should be absolute paths
	assert.True(t, filepath.IsAbs(configDir))
	assert.True(t, filepath.IsAbs(knownHostsDir))

	// On Unix systems, should start with /etc
	// On Windows, should contain ProgramData
	if runtime.GOOS == "windows" {
		assert.Contains(t, strings.ToLower(configDir), "programdata")
		assert.Contains(t, strings.ToLower(knownHostsDir), "programdata")
	} else {
		assert.Contains(t, configDir, "/etc/ssh")
		assert.Contains(t, knownHostsDir, "/etc/ssh")
	}
}

func TestManager_PeerLimit(t *testing.T) {
	// Create temporary directory for test
	tempDir, err := os.MkdirTemp("", "netbird-ssh-config-test")
	require.NoError(t, err)
	defer func() { assert.NoError(t, os.RemoveAll(tempDir)) }()

	// Override manager paths to use temp directory
	manager := &Manager{
		sshConfigDir:   filepath.Join(tempDir, "ssh_config.d"),
		sshConfigFile:  "99-netbird.conf",
		knownHostsDir:  filepath.Join(tempDir, "ssh_known_hosts.d"),
		knownHostsFile: "99-netbird",
		userKnownHosts: "known_hosts_netbird",
	}

	// Generate many peer keys (more than limit)
	var peerKeys []PeerHostKey
	for i := 0; i < MaxPeersForSSHConfig+10; i++ {
		hostKey, err := nbssh.GeneratePrivateKey(nbssh.ED25519)
		require.NoError(t, err)
		pubKey, err := ssh.ParsePrivateKey(hostKey)
		require.NoError(t, err)

		peerKeys = append(peerKeys, PeerHostKey{
			Hostname: fmt.Sprintf("peer%d", i),
			IP:       fmt.Sprintf("100.125.1.%d", i%254+1),
			FQDN:     fmt.Sprintf("peer%d.nb.internal", i),
			HostKey:  pubKey.PublicKey(),
		})
	}

	// Test that SSH config generation is skipped when too many peers
	err = manager.SetupSSHClientConfigWithPeers([]string{"nb.internal"}, peerKeys)
	require.NoError(t, err)

	// Config should not be created due to peer limit
	configPath := filepath.Join(manager.sshConfigDir, manager.sshConfigFile)
	_, err = os.Stat(configPath)
	assert.True(t, os.IsNotExist(err), "SSH config should not be created with too many peers")

	// Test that known_hosts update is also skipped
	err = manager.UpdatePeerHostKeys(peerKeys)
	require.NoError(t, err)

	// Known hosts should not be created due to peer limit
	knownHostsPath := filepath.Join(manager.knownHostsDir, manager.knownHostsFile)
	_, err = os.Stat(knownHostsPath)
	assert.True(t, os.IsNotExist(err), "Known hosts should not be created with too many peers")
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
		sshConfigDir:   filepath.Join(tempDir, "ssh_config.d"),
		sshConfigFile:  "99-netbird.conf",
		knownHostsDir:  filepath.Join(tempDir, "ssh_known_hosts.d"),
		knownHostsFile: "99-netbird",
		userKnownHosts: "known_hosts_netbird",
	}

	// Generate many peer keys (more than limit)
	var peerKeys []PeerHostKey
	for i := 0; i < MaxPeersForSSHConfig+10; i++ {
		hostKey, err := nbssh.GeneratePrivateKey(nbssh.ED25519)
		require.NoError(t, err)
		pubKey, err := ssh.ParsePrivateKey(hostKey)
		require.NoError(t, err)

		peerKeys = append(peerKeys, PeerHostKey{
			Hostname: fmt.Sprintf("peer%d", i),
			IP:       fmt.Sprintf("100.125.1.%d", i%254+1),
			FQDN:     fmt.Sprintf("peer%d.nb.internal", i),
			HostKey:  pubKey.PublicKey(),
		})
	}

	// Test that SSH config generation is forced despite many peers
	err = manager.SetupSSHClientConfigWithPeers([]string{"nb.internal"}, peerKeys)
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
