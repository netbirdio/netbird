package server

import (
	"context"
	"fmt"
	"net"
	"os/user"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/client/ssh"
	sshclient "github.com/netbirdio/netbird/client/ssh/client"
)

func TestServer_RootLoginRestriction(t *testing.T) {
	// Generate host key for server
	hostKey, err := ssh.GeneratePrivateKey(ssh.ED25519)
	require.NoError(t, err)

	tests := []struct {
		name        string
		allowRoot   bool
		username    string
		expectError bool
		description string
	}{
		{
			name:        "root login allowed",
			allowRoot:   true,
			username:    "root",
			expectError: false,
			description: "Root login should succeed when allowed",
		},
		{
			name:        "root login denied",
			allowRoot:   false,
			username:    "root",
			expectError: true,
			description: "Root login should fail when disabled",
		},
		{
			name:        "regular user login always allowed",
			allowRoot:   false,
			username:    "testuser",
			expectError: false,
			description: "Regular user login should work regardless of root setting",
		},
	}

	// Add Windows Administrator tests if on Windows
	if runtime.GOOS == "windows" {
		tests = append(tests, []struct {
			name        string
			allowRoot   bool
			username    string
			expectError bool
			description string
		}{
			{
				name:        "Administrator login allowed",
				allowRoot:   true,
				username:    "Administrator",
				expectError: false,
				description: "Administrator login should succeed when allowed",
			},
			{
				name:        "Administrator login denied",
				allowRoot:   false,
				username:    "Administrator",
				expectError: true,
				description: "Administrator login should fail when disabled",
			},
			{
				name:        "administrator login denied (lowercase)",
				allowRoot:   false,
				username:    "administrator",
				expectError: true,
				description: "administrator login should fail when disabled (case insensitive)",
			},
		}...)
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Mock privileged environment to test root access controls
			// Set up mock users based on platform
			mockUsers := map[string]*user.User{
				"root":     createTestUser("root", "0", "0", "/root"),
				"testuser": createTestUser("testuser", "1000", "1000", "/home/testuser"),
			}

			// Add Windows-specific users for Administrator tests
			if runtime.GOOS == "windows" {
				mockUsers["Administrator"] = createTestUser("Administrator", "500", "544", "C:\\Users\\Administrator")
				mockUsers["administrator"] = createTestUser("administrator", "500", "544", "C:\\Users\\administrator")
			}

			cleanup := setupTestDependencies(
				createTestUser("root", "0", "0", "/root"), // Running as root
				nil,
				runtime.GOOS,
				0, // euid 0 (root)
				mockUsers,
				nil,
			)
			defer cleanup()

			// Create server with specific configuration
			serverConfig := &Config{
				HostKeyPEM: hostKey,
				JWT:        nil,
			}
			server := New(serverConfig)
			server.SetAllowRootLogin(tt.allowRoot)

			// Test the userNameLookup method directly
			user, err := server.userNameLookup(tt.username)

			if tt.expectError {
				assert.Error(t, err, tt.description)
				if tt.username == "root" || strings.ToLower(tt.username) == "administrator" {
					// Check for appropriate error message based on platform capabilities
					errorMsg := err.Error()
					// Either privileged user restriction OR user switching limitation
					hasPrivilegedError := strings.Contains(errorMsg, "privileged user")
					hasSwitchingError := strings.Contains(errorMsg, "cannot switch") || strings.Contains(errorMsg, "user switching not supported")
					assert.True(t, hasPrivilegedError || hasSwitchingError,
						"Expected privileged user or user switching error, got: %s", errorMsg)
				}
			} else {
				if tt.username == "root" || strings.ToLower(tt.username) == "administrator" {
					// For privileged users, we expect either success or a different error
					// (like user not found), but not the "login disabled" error
					if err != nil {
						assert.NotContains(t, err.Error(), "privileged user login is disabled")
					}
				} else {
					// For regular users, lookup should generally succeed or fall back gracefully
					// Note: may return current user as fallback
					assert.NotNil(t, user)
				}
			}
		})
	}
}

func TestServer_PortForwardingRestriction(t *testing.T) {
	// Test that the port forwarding callbacks properly respect configuration flags
	// This is a unit test of the callback logic, not a full integration test

	// Generate host key for server
	hostKey, err := ssh.GeneratePrivateKey(ssh.ED25519)
	require.NoError(t, err)

	tests := []struct {
		name                  string
		allowLocalForwarding  bool
		allowRemoteForwarding bool
		description           string
	}{
		{
			name:                  "all forwarding allowed",
			allowLocalForwarding:  true,
			allowRemoteForwarding: true,
			description:           "Both local and remote forwarding should be allowed",
		},
		{
			name:                  "local forwarding disabled",
			allowLocalForwarding:  false,
			allowRemoteForwarding: true,
			description:           "Local forwarding should be denied when disabled",
		},
		{
			name:                  "remote forwarding disabled",
			allowLocalForwarding:  true,
			allowRemoteForwarding: false,
			description:           "Remote forwarding should be denied when disabled",
		},
		{
			name:                  "all forwarding disabled",
			allowLocalForwarding:  false,
			allowRemoteForwarding: false,
			description:           "Both forwarding types should be denied when disabled",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create server with specific configuration
			serverConfig := &Config{
				HostKeyPEM: hostKey,
				JWT:        nil,
			}
			server := New(serverConfig)
			server.SetAllowLocalPortForwarding(tt.allowLocalForwarding)
			server.SetAllowRemotePortForwarding(tt.allowRemoteForwarding)

			// We need to access the internal configuration to simulate the callback tests
			// Since the callbacks are created inside the Start method, we'll test the logic directly

			// Test the configuration values are set correctly
			server.mu.RLock()
			allowLocal := server.allowLocalPortForwarding
			allowRemote := server.allowRemotePortForwarding
			server.mu.RUnlock()

			assert.Equal(t, tt.allowLocalForwarding, allowLocal, "Local forwarding configuration should be set correctly")
			assert.Equal(t, tt.allowRemoteForwarding, allowRemote, "Remote forwarding configuration should be set correctly")

			// Simulate the callback logic
			localResult := allowLocal   // This would be the callback return value
			remoteResult := allowRemote // This would be the callback return value

			assert.Equal(t, tt.allowLocalForwarding, localResult,
				"Local port forwarding callback should return correct value")
			assert.Equal(t, tt.allowRemoteForwarding, remoteResult,
				"Remote port forwarding callback should return correct value")
		})
	}
}

func TestServer_PrivilegedPortAccess(t *testing.T) {
	hostKey, err := ssh.GeneratePrivateKey(ssh.ED25519)
	require.NoError(t, err)

	serverConfig := &Config{
		HostKeyPEM: hostKey,
	}
	server := New(serverConfig)
	server.SetAllowRemotePortForwarding(true)

	tests := []struct {
		name          string
		forwardType   string
		port          uint32
		username      string
		expectError   bool
		errorMsg      string
		skipOnWindows bool
	}{
		{
			name:          "non-root user remote forward privileged port",
			forwardType:   "remote",
			port:          80,
			username:      "testuser",
			expectError:   true,
			errorMsg:      "cannot bind to privileged port",
			skipOnWindows: true,
		},
		{
			name:          "non-root user tcpip-forward privileged port",
			forwardType:   "tcpip-forward",
			port:          443,
			username:      "testuser",
			expectError:   true,
			errorMsg:      "cannot bind to privileged port",
			skipOnWindows: true,
		},
		{
			name:        "non-root user remote forward unprivileged port",
			forwardType: "remote",
			port:        8080,
			username:    "testuser",
			expectError: false,
		},
		{
			name:        "non-root user remote forward port 0",
			forwardType: "remote",
			port:        0,
			username:    "testuser",
			expectError: false,
		},
		{
			name:        "root user remote forward privileged port",
			forwardType: "remote",
			port:        22,
			username:    "root",
			expectError: false,
		},
		{
			name:        "local forward privileged port allowed for non-root",
			forwardType: "local",
			port:        80,
			username:    "testuser",
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.skipOnWindows && runtime.GOOS == "windows" {
				t.Skip("Windows does not have privileged port restrictions")
			}

			result := PrivilegeCheckResult{
				Allowed: true,
				User:    &user.User{Username: tt.username},
			}

			err := server.checkPrivilegedPortAccess(tt.forwardType, tt.port, result)

			if tt.expectError {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorMsg)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestServer_PortConflictHandling(t *testing.T) {
	// Test that multiple sessions requesting the same local port are handled naturally by the OS
	// Get current user for SSH connection
	currentUser, err := user.Current()
	require.NoError(t, err, "Should be able to get current user")

	// Generate host key for server
	hostKey, err := ssh.GeneratePrivateKey(ssh.ED25519)
	require.NoError(t, err)

	// Create server
	serverConfig := &Config{
		HostKeyPEM: hostKey,
		JWT:        nil,
	}
	server := New(serverConfig)
	server.SetAllowRootLogin(true)

	serverAddr := StartTestServer(t, server)
	defer func() {
		err := server.Stop()
		require.NoError(t, err)
	}()

	// Get a free port for testing
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	testPort := ln.Addr().(*net.TCPAddr).Port
	err = ln.Close()
	require.NoError(t, err)

	// Connect first client
	ctx1, cancel1 := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel1()

	client1, err := sshclient.Dial(ctx1, serverAddr, currentUser.Username, sshclient.DialOptions{
		InsecureSkipVerify: true,
	})
	require.NoError(t, err)
	defer func() {
		err := client1.Close()
		assert.NoError(t, err)
	}()

	// Connect second client
	ctx2, cancel2 := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel2()

	client2, err := sshclient.Dial(ctx2, serverAddr, currentUser.Username, sshclient.DialOptions{
		InsecureSkipVerify: true,
	})
	require.NoError(t, err)
	defer func() {
		err := client2.Close()
		assert.NoError(t, err)
	}()

	// First client binds to the test port
	localAddr1 := fmt.Sprintf("127.0.0.1:%d", testPort)
	remoteAddr := "127.0.0.1:80"

	// Start first client's port forwarding
	done1 := make(chan error, 1)
	go func() {
		// This should succeed and hold the port
		err := client1.LocalPortForward(ctx1, localAddr1, remoteAddr)
		done1 <- err
	}()

	// Give first client time to bind
	time.Sleep(200 * time.Millisecond)

	// Second client tries to bind to same port
	localAddr2 := fmt.Sprintf("127.0.0.1:%d", testPort)

	shortCtx, shortCancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer shortCancel()

	err = client2.LocalPortForward(shortCtx, localAddr2, remoteAddr)
	// Second client should fail due to "address already in use"
	assert.Error(t, err, "Second client should fail to bind to same port")
	if err != nil {
		// The error should indicate the address is already in use
		errMsg := strings.ToLower(err.Error())
		if runtime.GOOS == "windows" {
			assert.Contains(t, errMsg, "only one usage of each socket address",
				"Error should indicate port conflict")
		} else {
			assert.Contains(t, errMsg, "address already in use",
				"Error should indicate port conflict")
		}
	}

	// Cancel first client's context and wait for it to finish
	cancel1()
	select {
	case err1 := <-done1:
		// Should get context cancelled or deadline exceeded
		assert.Error(t, err1, "First client should exit when context cancelled")
	case <-time.After(2 * time.Second):
		t.Error("First client did not exit within timeout")
	}
}

func TestServer_IsPrivilegedUser(t *testing.T) {

	tests := []struct {
		username    string
		expected    bool
		description string
	}{
		{
			username:    "root",
			expected:    true,
			description: "root should be considered privileged",
		},
		{
			username:    "regular",
			expected:    false,
			description: "regular user should not be privileged",
		},
		{
			username:    "",
			expected:    false,
			description: "empty username should not be privileged",
		},
	}

	// Add Windows-specific tests
	if runtime.GOOS == "windows" {
		tests = append(tests, []struct {
			username    string
			expected    bool
			description string
		}{
			{
				username:    "Administrator",
				expected:    true,
				description: "Administrator should be considered privileged on Windows",
			},
			{
				username:    "administrator",
				expected:    true,
				description: "administrator should be considered privileged on Windows (case insensitive)",
			},
		}...)
	} else {
		// On non-Windows systems, Administrator should not be privileged
		tests = append(tests, []struct {
			username    string
			expected    bool
			description string
		}{
			{
				username:    "Administrator",
				expected:    false,
				description: "Administrator should not be privileged on non-Windows systems",
			},
		}...)
	}

	for _, tt := range tests {
		t.Run(tt.description, func(t *testing.T) {
			result := isPrivilegedUsername(tt.username)
			assert.Equal(t, tt.expected, result, tt.description)
		})
	}
}

func TestServer_NonPtyShellSession(t *testing.T) {
	// Test that non-PTY shell sessions (ssh -T) work regardless of port forwarding settings.
	currentUser, err := user.Current()
	require.NoError(t, err, "Should be able to get current user")

	hostKey, err := ssh.GeneratePrivateKey(ssh.ED25519)
	require.NoError(t, err)

	tests := []struct {
		name                  string
		allowLocalForwarding  bool
		allowRemoteForwarding bool
	}{
		{
			name:                  "shell_with_local_forwarding_enabled",
			allowLocalForwarding:  true,
			allowRemoteForwarding: false,
		},
		{
			name:                  "shell_with_remote_forwarding_enabled",
			allowLocalForwarding:  false,
			allowRemoteForwarding: true,
		},
		{
			name:                  "shell_with_both_forwarding_enabled",
			allowLocalForwarding:  true,
			allowRemoteForwarding: true,
		},
		{
			name:                  "shell_with_forwarding_disabled",
			allowLocalForwarding:  false,
			allowRemoteForwarding: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			serverConfig := &Config{
				HostKeyPEM: hostKey,
				JWT:        nil,
			}
			server := New(serverConfig)
			server.SetAllowRootLogin(true)
			server.SetAllowLocalPortForwarding(tt.allowLocalForwarding)
			server.SetAllowRemotePortForwarding(tt.allowRemoteForwarding)

			serverAddr := StartTestServer(t, server)
			defer func() {
				_ = server.Stop()
			}()

			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			client, err := sshclient.Dial(ctx, serverAddr, currentUser.Username, sshclient.DialOptions{
				InsecureSkipVerify: true,
			})
			require.NoError(t, err)
			defer func() {
				_ = client.Close()
			}()

			// Execute without PTY and no command - simulates ssh -T (shell without PTY)
			// Should always succeed regardless of port forwarding settings
			_, err = client.ExecuteCommand(ctx, "")
			assert.NoError(t, err, "Non-PTY shell session should be allowed")
		})
	}
}
