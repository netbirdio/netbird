package config

// ShutdownState represents SSH configuration state that needs to be cleaned up.
type ShutdownState struct {
	SSHConfigDir  string
	SSHConfigFile string
}

// Name returns the state name for the state manager.
func (s *ShutdownState) Name() string {
	return "ssh_config_state"
}

// Cleanup removes SSH client configuration files.
func (s *ShutdownState) Cleanup() error {
	manager := &Manager{
		sshConfigDir:  s.SSHConfigDir,
		sshConfigFile: s.SSHConfigFile,
	}

	return manager.RemoveSSHClientConfig()
}
