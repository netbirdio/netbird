package config

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/ssh"
)

const (
	// EnvDisableSSHConfig is the environment variable to disable SSH config management
	EnvDisableSSHConfig = "NB_DISABLE_SSH_CONFIG"

	// EnvForceSSHConfig is the environment variable to force SSH config generation even with many peers
	EnvForceSSHConfig = "NB_FORCE_SSH_CONFIG"

	// MaxPeersForSSHConfig is the default maximum number of peers before SSH config generation is disabled
	MaxPeersForSSHConfig = 200

	// fileWriteTimeout is the timeout for file write operations
	fileWriteTimeout = 2 * time.Second
)

// isSSHConfigDisabled checks if SSH config management is disabled via environment variable
func isSSHConfigDisabled() bool {
	value := os.Getenv(EnvDisableSSHConfig)
	if value == "" {
		return false
	}

	// Parse as boolean, default to true if non-empty but invalid
	disabled, err := strconv.ParseBool(value)
	if err != nil {
		// If not a valid boolean, treat any non-empty value as true
		return true
	}
	return disabled
}

// isSSHConfigForced checks if SSH config generation is forced via environment variable
func isSSHConfigForced() bool {
	value := os.Getenv(EnvForceSSHConfig)
	if value == "" {
		return false
	}

	// Parse as boolean, default to true if non-empty but invalid
	forced, err := strconv.ParseBool(value)
	if err != nil {
		// If not a valid boolean, treat any non-empty value as true
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

// writeFileOperationWithTimeout performs a file operation with timeout
func writeFileOperationWithTimeout(filename string, operation func() error) error {
	ctx, cancel := context.WithTimeout(context.Background(), fileWriteTimeout)
	defer cancel()

	done := make(chan error, 1)
	go func() {
		done <- operation()
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
	sshConfigDir   string
	sshConfigFile  string
	knownHostsDir  string
	knownHostsFile string
	userKnownHosts string
}

// PeerHostKey represents a peer's SSH host key information
type PeerHostKey struct {
	Hostname string
	IP       string
	FQDN     string
	HostKey  ssh.PublicKey
}

// NewManager creates a new SSH config manager
func NewManager() *Manager {
	sshConfigDir, knownHostsDir := getSystemSSHPaths()
	return &Manager{
		sshConfigDir:   sshConfigDir,
		sshConfigFile:  "99-netbird.conf",
		knownHostsDir:  knownHostsDir,
		knownHostsFile: "99-netbird",
		userKnownHosts: "known_hosts_netbird",
	}
}

// getSystemSSHPaths returns platform-specific SSH configuration paths
func getSystemSSHPaths() (configDir, knownHostsDir string) {
	switch runtime.GOOS {
	case "windows":
		// Windows OpenSSH paths
		programData := os.Getenv("PROGRAMDATA")
		if programData == "" {
			programData = `C:\ProgramData`
		}
		configDir = filepath.Join(programData, "ssh", "ssh_config.d")
		knownHostsDir = filepath.Join(programData, "ssh", "ssh_known_hosts.d")
	default:
		// Unix-like systems (Linux, macOS, etc.)
		configDir = "/etc/ssh/ssh_config.d"
		knownHostsDir = "/etc/ssh/ssh_known_hosts.d"
	}
	return configDir, knownHostsDir
}

// SetupSSHClientConfig creates SSH client configuration for NetBird domains
func (m *Manager) SetupSSHClientConfig(domains []string) error {
	return m.SetupSSHClientConfigWithPeers(domains, nil)
}

// SetupSSHClientConfigWithPeers creates SSH client configuration for peer hostnames
func (m *Manager) SetupSSHClientConfigWithPeers(domains []string, peerKeys []PeerHostKey) error {
	peerCount := len(peerKeys)

	// Check if SSH config should be generated
	if !shouldGenerateSSHConfig(peerCount) {
		if isSSHConfigDisabled() {
			log.Debugf("SSH config management disabled via %s", EnvDisableSSHConfig)
		} else {
			log.Infof("SSH config generation skipped: too many peers (%d > %d). Use %s=true to force.",
				peerCount, MaxPeersForSSHConfig, EnvForceSSHConfig)
		}
		return nil
	}
	// Try to set up known_hosts for host key verification
	knownHostsPath, err := m.setupKnownHostsFile()
	if err != nil {
		log.Warnf("Failed to setup known_hosts file: %v", err)
		// Continue with fallback to no verification
		knownHostsPath = "/dev/null"
	}

	sshConfigPath := filepath.Join(m.sshConfigDir, m.sshConfigFile)

	// Build SSH client configuration
	sshConfig := "# NetBird SSH client configuration\n"
	sshConfig += "# Generated automatically - do not edit manually\n"
	sshConfig += "#\n"
	sshConfig += "# To disable SSH config management, use:\n"
	sshConfig += "#   netbird service reconfigure --service-env NB_DISABLE_SSH_CONFIG=true\n"
	sshConfig += "#\n\n"

	// Add specific peer entries with multiple hostnames in one Host line
	for _, peer := range peerKeys {
		var hostPatterns []string

		// Add IP address
		if peer.IP != "" {
			hostPatterns = append(hostPatterns, peer.IP)
		}

		// Add FQDN
		if peer.FQDN != "" {
			hostPatterns = append(hostPatterns, peer.FQDN)
		}

		// Add short hostname if different from FQDN
		if peer.Hostname != "" && peer.Hostname != peer.FQDN {
			hostPatterns = append(hostPatterns, peer.Hostname)
		}

		if len(hostPatterns) > 0 {
			hostLine := strings.Join(hostPatterns, " ")
			sshConfig += fmt.Sprintf("Host %s\n", hostLine)
			sshConfig += "    # NetBird peer-specific configuration\n"
			sshConfig += "    PreferredAuthentications password,publickey,keyboard-interactive\n"
			sshConfig += "    PasswordAuthentication yes\n"
			sshConfig += "    PubkeyAuthentication yes\n"
			sshConfig += "    BatchMode no\n"
			if knownHostsPath == "/dev/null" {
				sshConfig += "    StrictHostKeyChecking no\n"
				sshConfig += "    UserKnownHostsFile /dev/null\n"
			} else {
				sshConfig += "    StrictHostKeyChecking yes\n"
				sshConfig += fmt.Sprintf("    UserKnownHostsFile %s\n", knownHostsPath)
			}
			sshConfig += "    LogLevel ERROR\n\n"
		}
	}

	// Try to create system-wide SSH config
	if err := os.MkdirAll(m.sshConfigDir, 0755); err != nil {
		log.Warnf("Failed to create SSH config directory %s: %v", m.sshConfigDir, err)
		return m.setupUserConfig(sshConfig, domains)
	}

	if err := writeFileWithTimeout(sshConfigPath, []byte(sshConfig), 0644); err != nil {
		log.Warnf("Failed to write SSH config file %s: %v", sshConfigPath, err)
		return m.setupUserConfig(sshConfig, domains)
	}

	log.Infof("Created NetBird SSH client config: %s", sshConfigPath)
	return nil
}

// setupUserConfig creates SSH config in user's directory as fallback
func (m *Manager) setupUserConfig(sshConfig string, domains []string) error {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("get user home directory: %w", err)
	}

	userSSHDir := filepath.Join(homeDir, ".ssh")
	userConfigPath := filepath.Join(userSSHDir, "config")

	if err := os.MkdirAll(userSSHDir, 0700); err != nil {
		return fmt.Errorf("create user SSH directory: %w", err)
	}

	// Check if NetBird config already exists in user config
	exists, err := m.configExists(userConfigPath)
	if err != nil {
		return fmt.Errorf("check existing config: %w", err)
	}

	if exists {
		log.Debugf("NetBird SSH config already exists in %s", userConfigPath)
		return nil
	}

	// Append NetBird config to user's SSH config with timeout
	if err := writeFileOperationWithTimeout(userConfigPath, func() error {
		file, err := os.OpenFile(userConfigPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
		if err != nil {
			return fmt.Errorf("open user SSH config: %w", err)
		}
		defer func() {
			if err := file.Close(); err != nil {
				log.Debugf("user SSH config file close error: %v", err)
			}
		}()

		if _, err := fmt.Fprintf(file, "\n%s", sshConfig); err != nil {
			return fmt.Errorf("write to user SSH config: %w", err)
		}
		return nil
	}); err != nil {
		return err
	}

	log.Infof("Added NetBird SSH config to user config: %s", userConfigPath)
	return nil
}

// configExists checks if NetBird SSH config already exists
func (m *Manager) configExists(configPath string) (bool, error) {
	file, err := os.Open(configPath)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, fmt.Errorf("open SSH config file: %w", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.Contains(line, "NetBird SSH client configuration") {
			return true, nil
		}
	}

	return false, scanner.Err()
}

// RemoveSSHClientConfig removes NetBird SSH configuration
func (m *Manager) RemoveSSHClientConfig() error {
	sshConfigPath := filepath.Join(m.sshConfigDir, m.sshConfigFile)

	// Remove system-wide config if it exists
	if err := os.Remove(sshConfigPath); err != nil && !os.IsNotExist(err) {
		log.Warnf("Failed to remove system SSH config %s: %v", sshConfigPath, err)
	} else if err == nil {
		log.Infof("Removed NetBird SSH config: %s", sshConfigPath)
	}

	// Also try to clean up user config
	homeDir, err := os.UserHomeDir()
	if err != nil {
		log.Debugf("failed to get user home directory: %v", err)
		return nil
	}

	userConfigPath := filepath.Join(homeDir, ".ssh", "config")
	if err := m.removeFromUserConfig(userConfigPath); err != nil {
		log.Warnf("Failed to clean user SSH config: %v", err)
	}

	return nil
}

// removeFromUserConfig removes NetBird section from user's SSH config
func (m *Manager) removeFromUserConfig(configPath string) error {
	// This is complex to implement safely, so for now just log
	// In practice, the system-wide config takes precedence anyway
	log.Debugf("NetBird SSH config cleanup from user config not implemented")
	return nil
}

// setupKnownHostsFile creates and returns the path to NetBird known_hosts file
func (m *Manager) setupKnownHostsFile() (string, error) {
	// Try system-wide known_hosts first
	knownHostsPath := filepath.Join(m.knownHostsDir, m.knownHostsFile)
	if err := os.MkdirAll(m.knownHostsDir, 0755); err == nil {
		// Create empty file if it doesn't exist
		if _, err := os.Stat(knownHostsPath); os.IsNotExist(err) {
			if err := writeFileWithTimeout(knownHostsPath, []byte("# NetBird SSH known hosts\n"), 0644); err == nil {
				log.Debugf("Created NetBird known_hosts file: %s", knownHostsPath)
				return knownHostsPath, nil
			}
		} else if err == nil {
			return knownHostsPath, nil
		}
	}

	// Fallback to user directory
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("get user home directory: %w", err)
	}

	userSSHDir := filepath.Join(homeDir, ".ssh")
	if err := os.MkdirAll(userSSHDir, 0700); err != nil {
		return "", fmt.Errorf("create user SSH directory: %w", err)
	}

	userKnownHostsPath := filepath.Join(userSSHDir, m.userKnownHosts)
	if _, err := os.Stat(userKnownHostsPath); os.IsNotExist(err) {
		if err := writeFileWithTimeout(userKnownHostsPath, []byte("# NetBird SSH known hosts\n"), 0600); err != nil {
			return "", fmt.Errorf("create user known_hosts file: %w", err)
		}
		log.Debugf("Created NetBird user known_hosts file: %s", userKnownHostsPath)
	}

	return userKnownHostsPath, nil
}

// UpdatePeerHostKeys updates the known_hosts file with peer host keys
func (m *Manager) UpdatePeerHostKeys(peerKeys []PeerHostKey) error {
	peerCount := len(peerKeys)

	// Check if SSH config should be generated
	if !shouldGenerateSSHConfig(peerCount) {
		if isSSHConfigDisabled() {
			log.Debugf("SSH config management disabled via %s", EnvDisableSSHConfig)
		} else {
			log.Infof("SSH known_hosts update skipped: too many peers (%d > %d). Use %s=true to force.",
				peerCount, MaxPeersForSSHConfig, EnvForceSSHConfig)
		}
		return nil
	}
	knownHostsPath, err := m.setupKnownHostsFile()
	if err != nil {
		return fmt.Errorf("setup known_hosts file: %w", err)
	}

	// Read existing entries
	existingEntries, err := m.readKnownHosts(knownHostsPath)
	if err != nil {
		return fmt.Errorf("read existing known_hosts: %w", err)
	}

	// Build new entries map for efficient lookup
	newEntries := make(map[string]string)
	for _, peerKey := range peerKeys {
		entry := m.formatKnownHostsEntry(peerKey)
		// Use all possible hostnames as keys
		hostnames := m.getHostnameVariants(peerKey)
		for _, hostname := range hostnames {
			newEntries[hostname] = entry
		}
	}

	// Create updated known_hosts content
	var updatedContent strings.Builder
	updatedContent.WriteString("# NetBird SSH known hosts\n")
	updatedContent.WriteString("# Generated automatically - do not edit manually\n\n")

	// Add existing non-NetBird entries
	for _, entry := range existingEntries {
		if !m.isNetBirdEntry(entry) {
			updatedContent.WriteString(entry)
			updatedContent.WriteString("\n")
		}
	}

	// Add new NetBird entries
	for _, entry := range newEntries {
		updatedContent.WriteString(entry)
		updatedContent.WriteString("\n")
	}

	// Write updated content
	if err := writeFileWithTimeout(knownHostsPath, []byte(updatedContent.String()), 0644); err != nil {
		return fmt.Errorf("write known_hosts file: %w", err)
	}

	log.Debugf("Updated NetBird known_hosts with %d peer keys: %s", len(peerKeys), knownHostsPath)
	return nil
}

// readKnownHosts reads and returns all entries from the known_hosts file
func (m *Manager) readKnownHosts(knownHostsPath string) ([]string, error) {
	file, err := os.Open(knownHostsPath)
	if err != nil {
		if os.IsNotExist(err) {
			return []string{}, nil
		}
		return nil, fmt.Errorf("open known_hosts file: %w", err)
	}
	defer file.Close()

	var entries []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			entries = append(entries, line)
		}
	}

	return entries, scanner.Err()
}

// formatKnownHostsEntry formats a peer host key as a known_hosts entry
func (m *Manager) formatKnownHostsEntry(peerKey PeerHostKey) string {
	hostnames := m.getHostnameVariants(peerKey)
	hostnameList := strings.Join(hostnames, ",")
	keyString := string(ssh.MarshalAuthorizedKey(peerKey.HostKey))
	keyString = strings.TrimSpace(keyString)
	return fmt.Sprintf("%s %s", hostnameList, keyString)
}

// getHostnameVariants returns all possible hostname variants for a peer
func (m *Manager) getHostnameVariants(peerKey PeerHostKey) []string {
	var hostnames []string

	// Add IP address
	if peerKey.IP != "" {
		hostnames = append(hostnames, peerKey.IP)
	}

	// Add FQDN
	if peerKey.FQDN != "" {
		hostnames = append(hostnames, peerKey.FQDN)
	}

	// Add hostname if different from FQDN
	if peerKey.Hostname != "" && peerKey.Hostname != peerKey.FQDN {
		hostnames = append(hostnames, peerKey.Hostname)
	}

	// Add bracketed IP for non-standard ports (SSH standard)
	if peerKey.IP != "" {
		hostnames = append(hostnames, fmt.Sprintf("[%s]:22", peerKey.IP))
		hostnames = append(hostnames, fmt.Sprintf("[%s]:22022", peerKey.IP))
	}

	return hostnames
}

// isNetBirdEntry checks if a known_hosts entry appears to be NetBird-managed
func (m *Manager) isNetBirdEntry(entry string) bool {
	// Check if entry contains NetBird IP ranges or domains
	return strings.Contains(entry, "100.125.") ||
		strings.Contains(entry, ".nb.internal") ||
		strings.Contains(entry, "netbird")
}

// GetKnownHostsPath returns the path to the NetBird known_hosts file
func (m *Manager) GetKnownHostsPath() (string, error) {
	return m.setupKnownHostsFile()
}

// RemoveKnownHostsFile removes the NetBird known_hosts file
func (m *Manager) RemoveKnownHostsFile() error {
	// Remove system-wide known_hosts if it exists
	knownHostsPath := filepath.Join(m.knownHostsDir, m.knownHostsFile)
	if err := os.Remove(knownHostsPath); err != nil && !os.IsNotExist(err) {
		log.Warnf("Failed to remove system known_hosts %s: %v", knownHostsPath, err)
	} else if err == nil {
		log.Infof("Removed NetBird known_hosts: %s", knownHostsPath)
	}

	// Also try to clean up user known_hosts
	homeDir, err := os.UserHomeDir()
	if err != nil {
		log.Debugf("failed to get user home directory: %v", err)
		return nil
	}

	userKnownHostsPath := filepath.Join(homeDir, ".ssh", m.userKnownHosts)
	if err := os.Remove(userKnownHostsPath); err != nil && !os.IsNotExist(err) {
		log.Warnf("Failed to remove user known_hosts %s: %v", userKnownHostsPath, err)
	} else if err == nil {
		log.Infof("Removed NetBird user known_hosts: %s", userKnownHostsPath)
	}

	return nil
}
