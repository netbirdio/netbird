package config

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"

	nbssh "github.com/netbirdio/netbird/client/ssh"
)

const (
	EnvDisableSSHConfig = "NB_DISABLE_SSH_CONFIG"

	EnvForceSSHConfig = "NB_FORCE_SSH_CONFIG"

	MaxPeersForSSHConfig = 200

	fileWriteTimeout = 2 * time.Second
)

func isSSHConfigDisabled() bool {
	value := os.Getenv(EnvDisableSSHConfig)
	if value == "" {
		return false
	}

	disabled, err := strconv.ParseBool(value)
	if err != nil {
		return true
	}
	return disabled
}

func isSSHConfigForced() bool {
	value := os.Getenv(EnvForceSSHConfig)
	if value == "" {
		return false
	}

	forced, err := strconv.ParseBool(value)
	if err != nil {
		return true
	}
	return forced
}

// shouldGenerateSSHConfig checks if SSH config should be generated based on peer count
func shouldGenerateSSHConfig(peerCount int) bool {
	if isSSHConfigDisabled() {
		return false
	}

	if isSSHConfigForced() {
		return true
	}

	return peerCount <= MaxPeersForSSHConfig
}

// writeFileWithTimeout writes data to a file with a timeout
func writeFileWithTimeout(filename string, data []byte, perm os.FileMode) error {
	ctx, cancel := context.WithTimeout(context.Background(), fileWriteTimeout)
	defer cancel()

	done := make(chan error, 1)
	go func() {
		done <- os.WriteFile(filename, data, perm)
	}()

	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		return fmt.Errorf("file write timeout after %v: %s", fileWriteTimeout, filename)
	}
}

// Manager handles SSH client configuration for NetBird peers
type Manager struct {
	sshConfigDir  string
	sshConfigFile string
}

// PeerSSHInfo represents a peer's SSH configuration information
type PeerSSHInfo struct {
	Hostname string
	IP       string
	FQDN     string
}

// New creates a new SSH config manager
func New() *Manager {
	sshConfigDir := getSystemSSHConfigDir()
	return &Manager{
		sshConfigDir:  sshConfigDir,
		sshConfigFile: nbssh.NetBirdSSHConfigFile,
	}
}

// getSystemSSHConfigDir returns platform-specific SSH configuration directory
func getSystemSSHConfigDir() string {
	if runtime.GOOS == "windows" {
		return getWindowsSSHConfigDir()
	}
	return nbssh.UnixSSHConfigDir
}

func getWindowsSSHConfigDir() string {
	programData := os.Getenv("PROGRAMDATA")
	if programData == "" {
		programData = `C:\ProgramData`
	}
	return filepath.Join(programData, nbssh.WindowsSSHConfigDir)
}

// SetupSSHClientConfig creates SSH client configuration for NetBird peers
func (m *Manager) SetupSSHClientConfig(peers []PeerSSHInfo) error {
	if !shouldGenerateSSHConfig(len(peers)) {
		m.logSkipReason(len(peers))
		return nil
	}

	sshConfig, err := m.buildSSHConfig(peers)
	if err != nil {
		return fmt.Errorf("build SSH config: %w", err)
	}
	return m.writeSSHConfig(sshConfig)
}

func (m *Manager) logSkipReason(peerCount int) {
	if isSSHConfigDisabled() {
		log.Debugf("SSH config management disabled via %s", EnvDisableSSHConfig)
	} else {
		log.Infof("SSH config generation skipped: too many peers (%d > %d). Use %s=true to force.",
			peerCount, MaxPeersForSSHConfig, EnvForceSSHConfig)
	}
}

func (m *Manager) buildSSHConfig(peers []PeerSSHInfo) (string, error) {
	sshConfig := m.buildConfigHeader()

	var allHostPatterns []string
	for _, peer := range peers {
		hostPatterns := m.buildHostPatterns(peer)
		allHostPatterns = append(allHostPatterns, hostPatterns...)
	}

	if len(allHostPatterns) > 0 {
		peerConfig, err := m.buildPeerConfig(allHostPatterns)
		if err != nil {
			return "", err
		}
		sshConfig += peerConfig
	}

	return sshConfig, nil
}

func (m *Manager) buildConfigHeader() string {
	return "# NetBird SSH client configuration\n" +
		"# Generated automatically - do not edit manually\n" +
		"#\n" +
		"# To disable SSH config management, use:\n" +
		"#   netbird service reconfigure --service-env NB_DISABLE_SSH_CONFIG=true\n" +
		"#\n\n"
}

func (m *Manager) buildPeerConfig(allHostPatterns []string) (string, error) {
	uniquePatterns := make(map[string]bool)
	var deduplicatedPatterns []string
	for _, pattern := range allHostPatterns {
		if !uniquePatterns[pattern] {
			uniquePatterns[pattern] = true
			deduplicatedPatterns = append(deduplicatedPatterns, pattern)
		}
	}

	execPath, err := m.getNetBirdExecutablePath()
	if err != nil {
		return "", fmt.Errorf("get NetBird executable path: %w", err)
	}

	hostLine := strings.Join(deduplicatedPatterns, " ")
	config := fmt.Sprintf("Host %s\n", hostLine)
	config += fmt.Sprintf("    Match exec \"%s ssh detect %%h %%p\"\n", execPath)
	config += "        PreferredAuthentications password,publickey,keyboard-interactive\n"
	config += "        PasswordAuthentication yes\n"
	config += "        PubkeyAuthentication yes\n"
	config += "        BatchMode no\n"
	config += fmt.Sprintf("        ProxyCommand %s ssh proxy %%h %%p\n", execPath)
	config += "        StrictHostKeyChecking no\n"

	if runtime.GOOS == "windows" {
		config += "        UserKnownHostsFile NUL\n"
	} else {
		config += "        UserKnownHostsFile /dev/null\n"
	}

	config += "        CheckHostIP no\n"
	config += "        LogLevel ERROR\n\n"

	return config, nil
}

func (m *Manager) buildHostPatterns(peer PeerSSHInfo) []string {
	var hostPatterns []string
	if peer.IP != "" {
		hostPatterns = append(hostPatterns, peer.IP)
	}
	if peer.FQDN != "" {
		hostPatterns = append(hostPatterns, peer.FQDN)
	}
	if peer.Hostname != "" && peer.Hostname != peer.FQDN {
		hostPatterns = append(hostPatterns, peer.Hostname)
	}
	return hostPatterns
}

func (m *Manager) writeSSHConfig(sshConfig string) error {
	sshConfigPath := filepath.Join(m.sshConfigDir, m.sshConfigFile)

	if err := os.MkdirAll(m.sshConfigDir, 0755); err != nil {
		return fmt.Errorf("create SSH config directory %s: %w", m.sshConfigDir, err)
	}

	if err := writeFileWithTimeout(sshConfigPath, []byte(sshConfig), 0644); err != nil {
		return fmt.Errorf("write SSH config file %s: %w", sshConfigPath, err)
	}

	log.Infof("Created NetBird SSH client config: %s", sshConfigPath)
	return nil
}

// RemoveSSHClientConfig removes NetBird SSH configuration
func (m *Manager) RemoveSSHClientConfig() error {
	sshConfigPath := filepath.Join(m.sshConfigDir, m.sshConfigFile)
	err := os.Remove(sshConfigPath)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove SSH config %s: %w", sshConfigPath, err)
	}
	if err == nil {
		log.Infof("Removed NetBird SSH config: %s", sshConfigPath)
	}
	return nil
}

func (m *Manager) getNetBirdExecutablePath() (string, error) {
	execPath, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("retrieve executable path: %w", err)
	}

	realPath, err := filepath.EvalSymlinks(execPath)
	if err != nil {
		log.Debugf("symlink resolution failed: %v", err)
		return execPath, nil
	}

	return realPath, nil
}

// GetSSHConfigDir returns the SSH config directory path
func (m *Manager) GetSSHConfigDir() string {
	return m.sshConfigDir
}

// GetSSHConfigFile returns the SSH config file name
func (m *Manager) GetSSHConfigFile() string {
	return m.sshConfigFile
}
