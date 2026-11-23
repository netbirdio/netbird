package cmd

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/pflag"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// parseSSHCommandLine runs args through the flag parsing and argument
// validation cobra applies to netbird ssh, starting from default flag values.
func parseSSHCommandLine(t *testing.T, args []string) error {
	t.Helper()

	sshCmd.LocalFlags().VisitAll(func(f *pflag.Flag) {
		if sv, ok := f.Value.(pflag.SliceValue); ok {
			require.NoError(t, sv.Replace(nil))
		} else {
			require.NoError(t, f.Value.Set(f.DefValue))
		}
		f.Changed = false
	})
	host = ""
	hostUser = ""
	command = ""
	// Parse keeps the position of an earlier "--", Init clears it.
	sshCmd.Flags().Init(sshCmd.Name(), pflag.ContinueOnError)

	if err := sshCmd.ParseFlags(args); err != nil {
		return err
	}
	return sshCmd.ValidateArgs(sshCmd.Flags().Args())
}

// runSSHPreRun mirrors what cobra does between argument validation and
// sshFn: it runs the root PersistentPreRunE, then resolves the SSH user.
func runSSHPreRun(t *testing.T, args []string) {
	t.Helper()

	savedDaemonAddr := daemonAddr
	t.Cleanup(func() { daemonAddr = savedDaemonAddr })

	require.NoError(t, parseSSHCommandLine(t, args))
	require.NoError(t, rootCmd.PersistentPreRunE(sshCmd, sshCmd.Flags().Args()))
	username = resolveSSHUsername()
}

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
			expectedCmd:  "ls -la",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := parseSSHCommandLine(t, tt.args)

			if tt.expectError {
				assert.Error(t, err)
				return
			}

			require.NoError(t, err, "SSH args validation should succeed for valid input")
			assert.Equal(t, tt.expectedHost, host, "host mismatch")
			if tt.expectedUser != "" {
				assert.Equal(t, tt.expectedUser, resolveSSHUsername(), "username mismatch")
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
			expectedCmd: "ls -la",
			description: "double dash after the host ends the flags, as in OpenSSH",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := parseSSHCommandLine(t, tt.args)
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
			err := parseSSHCommandLine(t, tt.args)
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
			err := parseSSHCommandLine(t, tt.args)

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
			err := parseSSHCommandLine(t, tt.args)

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
			err := parseSSHCommandLine(t, tt.args)

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
			expectedLocal:  ":8080",
			expectedRemote: "localhost:80",
			expectError:    false,
			description:    "Wildcard * should bind to all interfaces (dual-stack)",
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
			err := parseSSHCommandLine(t, tt.args)
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
	// Flags of other commands right after the host are rejected, as OpenSSH rejects
	// unknown options there. After a remote command they belong to that command.
	for _, args := range [][]string{
		{"hostname", "--cmd", "echo test"},
		{"hostname", "--uid", "1000"},
		{"hostname", "--shell", "/bin/bash"},
	} {
		assert.Error(t, parseSSHCommandLine(t, args), "args %v must be rejected", args)
	}

	require.NoError(t, parseSSHCommandLine(t, []string{"hostname", "sh", "--cmd", "echo test"}))
	assert.Equal(t, "hostname", host, "host mismatch")
	assert.Equal(t, "sh --cmd echo test", command, "command mismatch")
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
			err := parseSSHCommandLine(t, tt.args)

			// Should return an error for invalid flags
			assert.Error(t, err, tt.description)

			// Should not have set host to the invalid flag
			assert.NotEqual(t, tt.args[0], host, "Invalid flag should not be interpreted as hostname")
		})
	}
}

func TestSSHCommand_DeprecatedLoginFlag(t *testing.T) {
	tests := []struct {
		name         string
		args         []string
		expectedUser string
		expectWarn   bool
	}{
		{
			name:         "login sets the username and warns",
			args:         []string{"--login", "alice", "hostname"},
			expectedUser: "alice",
			expectWarn:   true,
		},
		{
			name:         "user takes priority over login",
			args:         []string{"--user", "bob", "--login", "alice", "hostname"},
			expectedUser: "bob",
			expectWarn:   true,
		},
		{
			name:         "empty login still warns",
			args:         []string{"--login=", "hostname"},
			expectedUser: "",
			expectWarn:   true,
		},
		{
			name:         "user does not warn",
			args:         []string{"--user", "bob", "hostname"},
			expectedUser: "bob",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Cobra prints flag deprecations through the command output.
			var out bytes.Buffer
			sshCmd.SetOut(&out)
			t.Cleanup(func() { sshCmd.SetOut(nil) })

			require.NoError(t, parseSSHCommandLine(t, tt.args))

			// An empty --login falls back to the invoking user, which differs per host.
			if tt.expectedUser != "" {
				assert.Equal(t, tt.expectedUser, resolveSSHUsername(), "resolved username")
			}
			if tt.expectWarn {
				assert.Contains(t, out.String(), "Flag --login has been deprecated, use --user instead\n", "deprecation notice")
			} else {
				assert.Empty(t, out.String(), "no deprecation notice")
			}
		})
	}
}

func TestSSHCommand_RemoteCommandKeepsForwardingFlags(t *testing.T) {
	// -L and -R after the host belong to the remote command, not to port forwarding.
	require.NoError(t, parseSSHCommandLine(t, []string{"hostname", "grep", "-R", "pattern", "."}))

	assert.Equal(t, "hostname", host, "host mismatch")
	assert.Equal(t, "grep -R pattern .", command, "remote command should keep -R")
	assert.Empty(t, remoteForwards, "remote forwards should be empty")
	assert.Empty(t, localForwards, "local forwards should be empty")
}

func TestSSHCommand_ForwardValueAttachedToFlag(t *testing.T) {
	require.NoError(t, parseSSHCommandLine(t, []string{"-L8080:localhost:80", "-R9090:localhost:443", "hostname"}))

	assert.Equal(t, []string{"8080:localhost:80"}, localForwards, "local forwards")
	assert.Equal(t, []string{"9090:localhost:443"}, remoteForwards, "remote forwards")
}

func TestSSHCommand_IdentityFlag(t *testing.T) {
	for _, args := range [][]string{
		{"-i", "/tmp/id_ed25519", "hostname"},
		{"--identity", "/tmp/id_ed25519", "hostname"},
	} {
		require.NoError(t, parseSSHCommandLine(t, args))
		assert.Equal(t, "/tmp/id_ed25519", identityFile, "identity file from %v", args)
	}

	f := sshCmd.Flags().Lookup("identity")
	require.NotNil(t, f)
	assert.Empty(t, f.Deprecated, "identity is in use and must not be deprecated")
}

func TestSSHCommand_FlagsNotInheritedBySubcommands(t *testing.T) {
	for _, sub := range []string{"proxy", "detect", "sftp"} {
		c, _, err := sshCmd.Find([]string{sub})
		require.NoError(t, err)
		require.NotEqual(t, sshCmd, c, "subcommand %s should exist", sub)
		assert.Nil(t, c.InheritedFlags().Lookup("port"), "%s should not inherit --port", sub)
	}
}

func TestSSHCommand_UsernameAfterEnvVars(t *testing.T) {
	// The root PersistentPreRunE applies NB_* env vars after argument
	// validation, so the user must be resolved after it runs.
	tests := []struct {
		name         string
		env          map[string]string
		args         []string
		expectedUser string
	}{
		{
			name:         "NB_LOGIN is used when nothing else is set",
			env:          map[string]string{"NB_LOGIN": "alice"},
			args:         []string{"hostname"},
			expectedUser: "alice",
		},
		{
			name:         "NB_USER beats user@host",
			env:          map[string]string{"NB_USER": "bob"},
			args:         []string{"carol@hostname"},
			expectedUser: "bob",
		},
		{
			name:         "NB_USER beats NB_LOGIN",
			env:          map[string]string{"NB_USER": "bob", "NB_LOGIN": "alice"},
			args:         []string{"hostname"},
			expectedUser: "bob",
		},
		{
			name:         "NB_LOGIN beats user@host",
			env:          map[string]string{"NB_LOGIN": "alice"},
			args:         []string{"carol@hostname"},
			expectedUser: "alice",
		},
		{
			name:         "user@host without env vars",
			args:         []string{"carol@hostname"},
			expectedUser: "carol",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for _, key := range []string{"NB_USER", "WT_USER", "NB_LOGIN", "WT_LOGIN"} {
				t.Setenv(key, "")
				require.NoError(t, os.Unsetenv(key))
			}
			for key, value := range tt.env {
				t.Setenv(key, value)
			}

			runSSHPreRun(t, tt.args)

			assert.Equal(t, tt.expectedUser, username, "resolved SSH user")
			assert.Equal(t, "hostname", host, "host mismatch")
		})
	}
}

func TestSSHCommand_FlagsAfterHost(t *testing.T) {
	// OpenSSH parses options before the host and right after it. The remote
	// command starts at the first argument after the host that is not an option.
	tests := []struct {
		name          string
		args          []string
		expectedPort  int
		expectedTTY   bool
		expectedLocal []string
		expectedCmd   string
	}{
		{
			name:         "port after host",
			args:         []string{"hostname", "-p", "2222"},
			expectedPort: 2222,
		},
		{
			name:          "forward after host",
			args:          []string{"hostname", "-L", "8080:localhost:80"},
			expectedPort:  22,
			expectedLocal: []string{"8080:localhost:80"},
		},
		{
			name:          "flags after host then command",
			args:          []string{"hostname", "-t", "-L", "8080:localhost:80", "ls", "-la"},
			expectedPort:  22,
			expectedTTY:   true,
			expectedLocal: []string{"8080:localhost:80"},
			expectedCmd:   "ls -la",
		},
		{
			name:         "flag after command belongs to command",
			args:         []string{"hostname", "ls", "-p", "2222"},
			expectedPort: 22,
			expectedCmd:  "ls -p 2222",
		},
		{
			name:         "double dash before host stops flag parsing",
			args:         []string{"--", "hostname", "-p", "2222"},
			expectedPort: 22,
			expectedCmd:  "-p 2222",
		},
		{
			name:         "double dash after host passes flags to command",
			args:         []string{"hostname", "--", "-p", "2222"},
			expectedPort: 22,
			expectedCmd:  "-p 2222",
		},
		{
			name:         "flag after host overrides flag before host",
			args:         []string{"-p", "2200", "hostname", "-p", "2222"},
			expectedPort: 2222,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.NoError(t, parseSSHCommandLine(t, tt.args))

			assert.Equal(t, "hostname", host, "host mismatch")
			assert.Equal(t, tt.expectedPort, port, "port mismatch")
			assert.Equal(t, tt.expectedTTY, requestPTY, "tty mismatch")
			assert.Equal(t, len(tt.expectedLocal), len(localForwards), "local forward count")
			if len(tt.expectedLocal) > 0 {
				assert.Equal(t, tt.expectedLocal, localForwards, "local forwards")
			}
			assert.Equal(t, tt.expectedCmd, command, "command mismatch")
		})
	}
}

func TestSSHCommand_UserAfterHost(t *testing.T) {
	require.NoError(t, parseSSHCommandLine(t, []string{"hostname", "-u", "alice", "whoami"}))

	assert.Equal(t, "alice", resolveSSHUsername(), "username mismatch")
	assert.Equal(t, "whoami", command, "command mismatch")
}

func TestSSHCommand_LogLevelFlagAfterHost(t *testing.T) {
	// OpenSSH users write "-l user" after the host. In netbird -l is the log level,
	// which is only accepted before the host.
	err := parseSSHCommandLine(t, []string{"hostname", "-l", "alice"})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "-u or user@host", "error should point to -u")
}

func TestSSHCommand_HelpAfterHost(t *testing.T) {
	sshCmd.InitDefaultHelpFlag()

	err := parseSSHCommandLine(t, []string{"hostname", "-h"})

	assert.ErrorIs(t, err, pflag.ErrHelp, "-h after the host should request help")
}

func TestValidateKnownHostsFile(t *testing.T) {
	existing := filepath.Join(t.TempDir(), "known_hosts")
	require.NoError(t, os.WriteFile(existing, nil, 0o600))

	assert.NoError(t, validateKnownHostsFile(""), "unset path")
	assert.NoError(t, validateKnownHostsFile(existing), "existing file")

	err := validateKnownHostsFile(filepath.Join(t.TempDir(), "missing"))
	require.Error(t, err, "missing file")
	assert.NotContains(t, err.Error(), "OpenSSH option", "a plain path gets no -o hint")

	// An OpenSSH habit: "-o StrictHostKeyChecking=no" sets --known-hosts in netbird.
	err = validateKnownHostsFile("StrictHostKeyChecking=no")
	require.Error(t, err, "OpenSSH option as path")
	assert.Contains(t, err.Error(), "not an OpenSSH option", "error should explain -o")
}
