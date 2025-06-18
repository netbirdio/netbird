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
			expectedPort: 22022,
			expectedCmd:  "",
		},
		{
			name:         "user@host format",
			args:         []string{"user@hostname"},
			expectedHost: "hostname",
			expectedUser: "user",
			expectedPort: 22022,
			expectedCmd:  "",
		},
		{
			name:         "host with command",
			args:         []string{"hostname", "echo", "hello"},
			expectedHost: "hostname",
			expectedUser: "",
			expectedPort: 22022,
			expectedCmd:  "echo hello",
		},
		{
			name:         "command with flags should be preserved",
			args:         []string{"hostname", "ls", "-la", "/tmp"},
			expectedHost: "hostname",
			expectedUser: "",
			expectedPort: 22022,
			expectedCmd:  "ls -la /tmp",
		},
		{
			name:         "double dash separator",
			args:         []string{"hostname", "--", "ls", "-la"},
			expectedHost: "hostname",
			expectedUser: "",
			expectedPort: 22022,
			expectedCmd:  "-- ls -la",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Reset global variables
			host = ""
			username = ""
			port = 22022
			command = ""

			// Mock command for testing
			cmd := sshCmd
			cmd.SetArgs(tt.args)

			err := validateSSHArgsWithoutFlagParsing(cmd, tt.args)

			if tt.expectError {
				assert.Error(t, err)
				return
			}

			require.NoError(t, err)
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
			port = 22022
			command = ""

			cmd := sshCmd
			err := validateSSHArgsWithoutFlagParsing(cmd, tt.args)
			require.NoError(t, err)

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
			port = 22022
			command = ""

			cmd := sshCmd
			err := validateSSHArgsWithoutFlagParsing(cmd, tt.args)
			require.NoError(t, err)

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
			port = 22022
			command = ""

			cmd := sshCmd
			err := validateSSHArgsWithoutFlagParsing(cmd, tt.args)

			if tt.expectError {
				assert.Error(t, err)
				return
			}

			require.NoError(t, err)
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
			port = 22022
			command = ""

			cmd := sshCmd
			err := validateSSHArgsWithoutFlagParsing(cmd, tt.args)

			if tt.expectError {
				assert.Error(t, err)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.expectedHost, host, "host mismatch")
			assert.Equal(t, tt.expectedCmd, command, tt.description)

			// Check port for the test case with -p flag
			if len(tt.args) > 0 && tt.args[0] == "-p" {
				assert.Equal(t, 2222, port, "port should be parsed from -p flag")
			}
		})
	}
}
