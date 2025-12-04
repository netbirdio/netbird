package cmd

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSSHCommand_FlagParsing(t *testing.T) {
	tests := []struct {
		name         string
		args         []string
		expectedHost string
		expectedUser string
		expectedPort int
		expectedCmd  string
		expectError  bool
	}{
		{
			name:         "basic host",
			args:         []string{"hostname"},
			expectedHost: "hostname",
			expectedUser: "",
			expectedPort: 22,
			expectedCmd:  "",
		},
		{
			name:         "user@host format",
			args:         []string{"user@hostname"},
			expectedHost: "hostname",
			expectedUser: "user",
			expectedPort: 22,
			expectedCmd:  "",
		},
		{
			name:         "host with command",
			args:         []string{"hostname", "echo", "hello"},
			expectedHost: "hostname",
			expectedUser: "",
			expectedPort: 22,
			expectedCmd:  "echo hello",
		},
		{
			name:         "command with flags should be preserved",
			args:         []string{"hostname", "ls", "-la", "/tmp"},
			expectedHost: "hostname",
			expectedUser: "",
			expectedPort: 22,
			expectedCmd:  "ls -la /tmp",
		},
		{
			name:         "double dash separator",
			args:         []string{"hostname", "--", "ls", "-la"},
			expectedHost: "hostname",
			expectedUser: "",
			expectedPort: 22,
			expectedCmd:  "-- ls -la",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Reset global variables
			host = ""
			username = ""
			port = 22
			command = ""

			// Mock command for testing
			cmd := sshCmd
			cmd.SetArgs(tt.args)

			err := validateSSHArgsWithoutFlagParsing(cmd, tt.args)

			if tt.expectError {
				assert.Error(t, err)
				return
			}

			require.NoError(t, err, "SSH args validation should succeed for valid input")
			assert.Equal(t, tt.expectedHost, host, "host mismatch")
			if tt.expectedUser != "" {
				assert.Equal(t, tt.expectedUser, username, "username mismatch")
			}
			assert.Equal(t, tt.expectedPort, port, "port mismatch")
			assert.Equal(t, tt.expectedCmd, command, "command mismatch")
		})
	}
}

func TestSSHCommand_FlagConflictPrevention(t *testing.T) {
	// Test that SSH flags don't conflict with command flags
	tests := []struct {
		name        string
		args        []string
		expectedCmd string
		description string
	}{
		{
			name:        "ls with -la flags",
			args:        []string{"hostname", "ls", "-la"},
			expectedCmd: "ls -la",
			description: "ls flags should be passed to remote command",
		},
		{
			name:        "grep with -r flag",
			args:        []string{"hostname", "grep", "-r", "pattern", "/path"},
			expectedCmd: "grep -r pattern /path",
			description: "grep flags should be passed to remote command",
		},
		{
			name:        "ps with aux flags",
			args:        []string{"hostname", "ps", "aux"},
			expectedCmd: "ps aux",
			description: "ps flags should be passed to remote command",
		},
		{
			name:        "command with double dash",
			args:        []string{"hostname", "--", "ls", "-la"},
			expectedCmd: "-- ls -la",
			description: "double dash should be preserved in command",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Reset global variables
			host = ""
			username = ""
			port = 22
			command = ""

			cmd := sshCmd
			err := validateSSHArgsWithoutFlagParsing(cmd, tt.args)
			require.NoError(t, err, "SSH args validation should succeed for valid input")

			assert.Equal(t, tt.expectedCmd, command, tt.description)
		})
	}
}

func TestSSHCommand_NonInteractiveExecution(t *testing.T) {
	// Test that commands with arguments should execute the command and exit,
	// not drop to an interactive shell
	tests := []struct {
		name        string
		args        []string
		expectedCmd string
		shouldExit  bool
		description string
	}{
		{
			name:        "ls command should execute and exit",
			args:        []string{"hostname", "ls"},
			expectedCmd: "ls",
			shouldExit:  true,
			description: "ls command should execute and exit, not drop to shell",
		},
		{
			name:        "ls with flags should execute and exit",
			args:        []string{"hostname", "ls", "-la"},
			expectedCmd: "ls -la",
			shouldExit:  true,
			description: "ls with flags should execute and exit, not drop to shell",
		},
		{
			name:        "pwd command should execute and exit",
			args:        []string{"hostname", "pwd"},
			expectedCmd: "pwd",
			shouldExit:  true,
			description: "pwd command should execute and exit, not drop to shell",
		},
		{
			name:        "echo command should execute and exit",
			args:        []string{"hostname", "echo", "hello"},
			expectedCmd: "echo hello",
			shouldExit:  true,
			description: "echo command should execute and exit, not drop to shell",
		},
		{
			name:        "no command should open shell",
			args:        []string{"hostname"},
			expectedCmd: "",
			shouldExit:  false,
			description: "no command should open interactive shell",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Reset global variables
			host = ""
			username = ""
			port = 22
			command = ""

			cmd := sshCmd
			err := validateSSHArgsWithoutFlagParsing(cmd, tt.args)
			require.NoError(t, err, "SSH args validation should succeed for valid input")

			assert.Equal(t, tt.expectedCmd, command, tt.description)

			// When command is present, it should execute the command and exit
			// When command is empty, it should open interactive shell
			hasCommand := command != ""
			assert.Equal(t, tt.shouldExit, hasCommand, "Command presence should match expected behavior")
		})
	}
}

func TestSSHCommand_FlagHandling(t *testing.T) {
	// Test that flags after hostname are not parsed by netbird but passed to SSH command
	tests := []struct {
		name         string
		args         []string
		expectedHost string
		expectedCmd  string
		expectError  bool
		description  string
	}{
		{
			name:         "ls with -la flag should not be parsed by netbird",
			args:         []string{"debian2", "ls", "-la"},
			expectedHost: "debian2",
			expectedCmd:  "ls -la",
			expectError:  false,
			description:  "ls -la should be passed as SSH command, not parsed as netbird flags",
		},
		{
			name:         "command with netbird-like flags should be passed through",
			args:         []string{"hostname", "echo", "--help"},
			expectedHost: "hostname",
			expectedCmd:  "echo --help",
			expectError:  false,
			description:  "--help should be passed to echo, not parsed by netbird",
		},
		{
			name:         "command with -p flag should not conflict with SSH port flag",
			args:         []string{"hostname", "ps", "-p", "1234"},
			expectedHost: "hostname",
			expectedCmd:  "ps -p 1234",
			expectError:  false,
			description:  "ps -p should be passed to ps command, not parsed as port",
		},
		{
			name:         "tar with flags should be passed through",
			args:         []string{"hostname", "tar", "-czf", "backup.tar.gz", "/home"},
			expectedHost: "hostname",
			expectedCmd:  "tar -czf backup.tar.gz /home",
			expectError:  false,
			description:  "tar flags should be passed to tar command",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Reset global variables
			host = ""
			username = ""
			port = 22
			command = ""

			cmd := sshCmd
			err := validateSSHArgsWithoutFlagParsing(cmd, tt.args)

			if tt.expectError {
				assert.Error(t, err)
				return
			}

			require.NoError(t, err, "SSH args validation should succeed for valid input")
			assert.Equal(t, tt.expectedHost, host, "host mismatch")
			assert.Equal(t, tt.expectedCmd, command, tt.description)
		})
	}
}

func TestSSHCommand_RegressionFlagParsing(t *testing.T) {
	// Regression test for the specific issue: "sudo ./netbird ssh debian2 ls -la"
	// should not parse -la as netbird flags but pass them to the SSH command
	tests := []struct {
		name         string
		args         []string
		expectedHost string
		expectedCmd  string
		expectError  bool
		description  string
	}{
		{
			name:         "original issue: ls -la should be preserved",
			args:         []string{"debian2", "ls", "-la"},
			expectedHost: "debian2",
			expectedCmd:  "ls -la",
			expectError:  false,
			description:  "The original failing case should now work",
		},
		{
			name:         "ls -l should be preserved",
			args:         []string{"hostname", "ls", "-l"},
			expectedHost: "hostname",
			expectedCmd:  "ls -l",
			expectError:  false,
			description:  "Single letter flags should be preserved",
		},
		{
			name:         "SSH port flag should work",
			args:         []string{"-p", "2222", "hostname", "ls", "-la"},
			expectedHost: "hostname",
			expectedCmd:  "ls -la",
			expectError:  false,
			description:  "SSH -p flag should be parsed, command flags preserved",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Reset global variables
			host = ""
			username = ""
			port = 22
			command = ""

			cmd := sshCmd
			err := validateSSHArgsWithoutFlagParsing(cmd, tt.args)

			if tt.expectError {
				assert.Error(t, err)
				return
			}

			require.NoError(t, err, "SSH args validation should succeed for valid input")
			assert.Equal(t, tt.expectedHost, host, "host mismatch")
			assert.Equal(t, tt.expectedCmd, command, tt.description)

			// Check port for the test case with -p flag
			if len(tt.args) > 0 && tt.args[0] == "-p" {
				assert.Equal(t, 2222, port, "port should be parsed from -p flag")
			}
		})
	}
}

func TestSSHCommand_PortForwardingFlagParsing(t *testing.T) {
	tests := []struct {
		name           string
		args           []string
		expectedHost   string
		expectedLocal  []string
		expectedRemote []string
		expectError    bool
		description    string
	}{
		{
			name:           "local port forwarding -L",
			args:           []string{"-L", "8080:localhost:80", "hostname"},
			expectedHost:   "hostname",
			expectedLocal:  []string{"8080:localhost:80"},
			expectedRemote: []string{},
			expectError:    false,
			description:    "Single -L flag should be parsed correctly",
		},
		{
			name:           "remote port forwarding -R",
			args:           []string{"-R", "8080:localhost:80", "hostname"},
			expectedHost:   "hostname",
			expectedLocal:  []string{},
			expectedRemote: []string{"8080:localhost:80"},
			expectError:    false,
			description:    "Single -R flag should be parsed correctly",
		},
		{
			name:           "multiple local port forwards",
			args:           []string{"-L", "8080:localhost:80", "-L", "9090:localhost:443", "hostname"},
			expectedHost:   "hostname",
			expectedLocal:  []string{"8080:localhost:80", "9090:localhost:443"},
			expectedRemote: []string{},
			expectError:    false,
			description:    "Multiple -L flags should be parsed correctly",
		},
		{
			name:           "multiple remote port forwards",
			args:           []string{"-R", "8080:localhost:80", "-R", "9090:localhost:443", "hostname"},
			expectedHost:   "hostname",
			expectedLocal:  []string{},
			expectedRemote: []string{"8080:localhost:80", "9090:localhost:443"},
			expectError:    false,
			description:    "Multiple -R flags should be parsed correctly",
		},
		{
			name:           "mixed local and remote forwards",
			args:           []string{"-L", "8080:localhost:80", "-R", "9090:localhost:443", "hostname"},
			expectedHost:   "hostname",
			expectedLocal:  []string{"8080:localhost:80"},
			expectedRemote: []string{"9090:localhost:443"},
			expectError:    false,
			description:    "Mixed -L and -R flags should be parsed correctly",
		},
		{
			name:           "port forwarding with bind address",
			args:           []string{"-L", "127.0.0.1:8080:localhost:80", "hostname"},
			expectedHost:   "hostname",
			expectedLocal:  []string{"127.0.0.1:8080:localhost:80"},
			expectedRemote: []string{},
			expectError:    false,
			description:    "Port forwarding with bind address should work",
		},
		{
			name:           "port forwarding with command",
			args:           []string{"-L", "8080:localhost:80", "hostname", "ls", "-la"},
			expectedHost:   "hostname",
			expectedLocal:  []string{"8080:localhost:80"},
			expectedRemote: []string{},
			expectError:    false,
			description:    "Port forwarding with command should work",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Reset global variables
			host = ""
			username = ""
			port = 22
			command = ""
			localForwards = nil
			remoteForwards = nil

			cmd := sshCmd
			err := validateSSHArgsWithoutFlagParsing(cmd, tt.args)

			if tt.expectError {
				assert.Error(t, err)
				return
			}

			require.NoError(t, err, "SSH args validation should succeed for valid input")
			assert.Equal(t, tt.expectedHost, host, "host mismatch")
			// Handle nil vs empty slice comparison
			if len(tt.expectedLocal) == 0 {
				assert.True(t, len(localForwards) == 0, tt.description+" - local forwards should be empty")
			} else {
				assert.Equal(t, tt.expectedLocal, localForwards, tt.description+" - local forwards")
			}
			if len(tt.expectedRemote) == 0 {
				assert.True(t, len(remoteForwards) == 0, tt.description+" - remote forwards should be empty")
			} else {
				assert.Equal(t, tt.expectedRemote, remoteForwards, tt.description+" - remote forwards")
			}
		})
	}
}

func TestParsePortForward(t *testing.T) {
	tests := []struct {
		name           string
		spec           string
		expectedLocal  string
		expectedRemote string
		expectError    bool
		description    string
	}{
		{
			name:           "simple port forward",
			spec:           "8080:localhost:80",
			expectedLocal:  "localhost:8080",
			expectedRemote: "localhost:80",
			expectError:    false,
			description:    "Simple port:host:port format should work",
		},
		{
			name:           "port forward with bind address",
			spec:           "127.0.0.1:8080:localhost:80",
			expectedLocal:  "127.0.0.1:8080",
			expectedRemote: "localhost:80",
			expectError:    false,
			description:    "bind_address:port:host:port format should work",
		},
		{
			name:           "port forward to different host",
			spec:           "8080:example.com:443",
			expectedLocal:  "localhost:8080",
			expectedRemote: "example.com:443",
			expectError:    false,
			description:    "Forwarding to different host should work",
		},
		{
			name:        "port forward with IPv6 (needs bracket support)",
			spec:        "::1:8080:localhost:80",
			expectError: true,
			description: "IPv6 without brackets fails as expected (feature to implement)",
		},
		{
			name:        "invalid format - too few parts",
			spec:        "8080:localhost",
			expectError: true,
			description: "Invalid format with too few parts should fail",
		},
		{
			name:        "invalid format - too many parts",
			spec:        "127.0.0.1:8080:localhost:80:extra",
			expectError: true,
			description: "Invalid format with too many parts should fail",
		},
		{
			name:        "empty spec",
			spec:        "",
			expectError: true,
			description: "Empty spec should fail",
		},
		{
			name:           "unix socket local forward",
			spec:           "8080:/tmp/socket",
			expectedLocal:  "localhost:8080",
			expectedRemote: "/tmp/socket",
			expectError:    false,
			description:    "Unix socket forwarding should work",
		},
		{
			name:           "unix socket with bind address",
			spec:           "127.0.0.1:8080:/tmp/socket",
			expectedLocal:  "127.0.0.1:8080",
			expectedRemote: "/tmp/socket",
			expectError:    false,
			description:    "Unix socket with bind address should work",
		},
		{
			name:           "wildcard bind all interfaces",
			spec:           "*:8080:localhost:80",
			expectedLocal:  "0.0.0.0:8080",
			expectedRemote: "localhost:80",
			expectError:    false,
			description:    "Wildcard * should bind to all interfaces (0.0.0.0)",
		},
		{
			name:           "wildcard for port only",
			spec:           "8080:*:80",
			expectedLocal:  "localhost:8080",
			expectedRemote: "*:80",
			expectError:    false,
			description:    "Wildcard in remote host should be preserved",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			localAddr, remoteAddr, err := parsePortForwardSpec(tt.spec)

			if tt.expectError {
				assert.Error(t, err, tt.description)
				return
			}

			require.NoError(t, err, tt.description)
			assert.Equal(t, tt.expectedLocal, localAddr, tt.description+" - local address")
			assert.Equal(t, tt.expectedRemote, remoteAddr, tt.description+" - remote address")
		})
	}
}

func TestSSHCommand_IntegrationPortForwarding(t *testing.T) {
	// Integration test for port forwarding with the actual SSH command implementation
	tests := []struct {
		name           string
		args           []string
		expectedHost   string
		expectedLocal  []string
		expectedRemote []string
		expectedCmd    string
		description    string
	}{
		{
			name:           "local forward with command",
			args:           []string{"-L", "8080:localhost:80", "hostname", "echo", "test"},
			expectedHost:   "hostname",
			expectedLocal:  []string{"8080:localhost:80"},
			expectedRemote: []string{},
			expectedCmd:    "echo test",
			description:    "Local forwarding should work with commands",
		},
		{
			name:           "remote forward with command",
			args:           []string{"-R", "8080:localhost:80", "hostname", "ls", "-la"},
			expectedHost:   "hostname",
			expectedLocal:  []string{},
			expectedRemote: []string{"8080:localhost:80"},
			expectedCmd:    "ls -la",
			description:    "Remote forwarding should work with commands",
		},
		{
			name:           "multiple forwards with user and command",
			args:           []string{"-L", "8080:localhost:80", "-R", "9090:localhost:443", "user@hostname", "ps", "aux"},
			expectedHost:   "hostname",
			expectedLocal:  []string{"8080:localhost:80"},
			expectedRemote: []string{"9090:localhost:443"},
			expectedCmd:    "ps aux",
			description:    "Complex case with multiple forwards, user, and command",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Reset global variables
			host = ""
			username = ""
			port = 22
			command = ""
			localForwards = nil
			remoteForwards = nil

			cmd := sshCmd
			err := validateSSHArgsWithoutFlagParsing(cmd, tt.args)
			require.NoError(t, err, "SSH args validation should succeed for valid input")

			assert.Equal(t, tt.expectedHost, host, "host mismatch")
			// Handle nil vs empty slice comparison
			if len(tt.expectedLocal) == 0 {
				assert.True(t, len(localForwards) == 0, tt.description+" - local forwards should be empty")
			} else {
				assert.Equal(t, tt.expectedLocal, localForwards, tt.description+" - local forwards")
			}
			if len(tt.expectedRemote) == 0 {
				assert.True(t, len(remoteForwards) == 0, tt.description+" - remote forwards should be empty")
			} else {
				assert.Equal(t, tt.expectedRemote, remoteForwards, tt.description+" - remote forwards")
			}
			assert.Equal(t, tt.expectedCmd, command, tt.description+" - command")
		})
	}
}

func TestSSHCommand_ParameterIsolation(t *testing.T) {
	tests := []struct {
		name        string
		args        []string
		expectedCmd string
	}{
		{
			name:        "cmd flag passed as command",
			args:        []string{"hostname", "--cmd", "echo test"},
			expectedCmd: "--cmd echo test",
		},
		{
			name:        "uid flag passed as command",
			args:        []string{"hostname", "--uid", "1000"},
			expectedCmd: "--uid 1000",
		},
		{
			name:        "shell flag passed as command",
			args:        []string{"hostname", "--shell", "/bin/bash"},
			expectedCmd: "--shell /bin/bash",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			host = ""
			username = ""
			port = 22
			command = ""

			err := validateSSHArgsWithoutFlagParsing(sshCmd, tt.args)
			require.NoError(t, err)

			assert.Equal(t, "hostname", host)
			assert.Equal(t, tt.expectedCmd, command)
		})
	}
}

func TestSSHCommand_InvalidFlagRejection(t *testing.T) {
	// Test that invalid flags are properly rejected and not misinterpreted as hostnames
	tests := []struct {
		name        string
		args        []string
		description string
	}{
		{
			name:        "invalid long flag before hostname",
			args:        []string{"--invalid-flag", "hostname"},
			description: "Invalid flag should return parse error, not treat flag as hostname",
		},
		{
			name:        "invalid short flag before hostname",
			args:        []string{"-x", "hostname"},
			description: "Invalid short flag should return parse error",
		},
		{
			name:        "invalid flag with value before hostname",
			args:        []string{"--invalid-option=value", "hostname"},
			description: "Invalid flag with value should return parse error",
		},
		{
			name:        "typo in known flag",
			args:        []string{"--por", "2222", "hostname"},
			description: "Typo in flag name should return parse error (not silently ignored)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Reset global variables
			host = ""
			username = ""
			port = 22
			command = ""

			err := validateSSHArgsWithoutFlagParsing(sshCmd, tt.args)

			// Should return an error for invalid flags
			assert.Error(t, err, tt.description)

			// Should not have set host to the invalid flag
			assert.NotEqual(t, tt.args[0], host, "Invalid flag should not be interpreted as hostname")
		})
	}
}
