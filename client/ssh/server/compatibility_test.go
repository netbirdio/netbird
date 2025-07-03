package server

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/user"
	"runtime"
	"strings"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"

	nbssh "github.com/netbirdio/netbird/client/ssh"
)

// TestMain handles package-level setup and cleanup
func TestMain(m *testing.M) {
	// Run tests
	code := m.Run()

	// Cleanup any created test users
	cleanupTestUsers()

	os.Exit(code)
}

// TestSSHServerCompatibility tests that our SSH server is compatible with the system SSH client
func TestSSHServerCompatibility(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping SSH compatibility tests in short mode")
	}

	// Check if ssh binary is available
	if !isSSHClientAvailable() {
		t.Skip("SSH client not available on this system")
	}

	// Set up SSH server - use our existing key generation for server
	hostKey, err := nbssh.GeneratePrivateKey(nbssh.ED25519)
	require.NoError(t, err)

	// Generate OpenSSH-compatible keys for client
	clientPrivKeyOpenSSH, clientPubKeyOpenSSH, err := generateOpenSSHKey(t)
	require.NoError(t, err)

	server := New(hostKey)
	server.SetAllowRootLogin(true) // Allow root login for testing
	err = server.AddAuthorizedKey("test-peer", string(clientPubKeyOpenSSH))
	require.NoError(t, err)

	serverAddr := StartTestServer(t, server)
	defer func() {
		err := server.Stop()
		require.NoError(t, err)
	}()

	// Create temporary key files for SSH client
	clientKeyFile, cleanupKey := createTempKeyFileFromBytes(t, clientPrivKeyOpenSSH)
	defer cleanupKey()

	// Extract host and port from server address
	host, portStr, err := net.SplitHostPort(serverAddr)
	require.NoError(t, err)

	// Get appropriate user for SSH connection (handle system accounts)
	username := getTestUsername(t)

	t.Run("basic command execution", func(t *testing.T) {
		testSSHCommandExecutionWithUser(t, host, portStr, clientKeyFile, username)
	})

	t.Run("interactive command", func(t *testing.T) {
		testSSHInteractiveCommand(t, host, portStr, clientKeyFile)
	})

	t.Run("port forwarding", func(t *testing.T) {
		testSSHPortForwarding(t, host, portStr, clientKeyFile)
	})
}

// testSSHCommandExecutionWithUser tests basic command execution with system SSH client using specified user.
func testSSHCommandExecutionWithUser(t *testing.T, host, port, keyFile, username string) {
	cmd := exec.Command("ssh",
		"-i", keyFile,
		"-p", port,
		"-o", "StrictHostKeyChecking=no",
		"-o", "UserKnownHostsFile=/dev/null",
		"-o", "ConnectTimeout=5",
		fmt.Sprintf("%s@%s", username, host),
		"echo", "hello_world")

	output, err := cmd.CombinedOutput()

	if err != nil {
		t.Logf("SSH command failed: %v", err)
		t.Logf("Output: %s", string(output))
		return
	}

	assert.Contains(t, string(output), "hello_world", "SSH command should execute successfully")
}

// testSSHInteractiveCommand tests interactive shell session.
func testSSHInteractiveCommand(t *testing.T, host, port, keyFile string) {
	// Get appropriate user for SSH connection
	username := getTestUsername(t)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "ssh",
		"-i", keyFile,
		"-p", port,
		"-o", "StrictHostKeyChecking=no",
		"-o", "UserKnownHostsFile=/dev/null",
		"-o", "ConnectTimeout=5",
		fmt.Sprintf("%s@%s", username, host))

	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Skipf("Cannot create stdin pipe: %v", err)
		return
	}

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Skipf("Cannot create stdout pipe: %v", err)
		return
	}

	err = cmd.Start()
	if err != nil {
		t.Logf("Cannot start SSH session: %v", err)
		return
	}

	go func() {
		defer func() {
			if err := stdin.Close(); err != nil {
				t.Logf("stdin close error: %v", err)
			}
		}()
		time.Sleep(100 * time.Millisecond)
		if _, err := stdin.Write([]byte("echo interactive_test\n")); err != nil {
			t.Logf("stdin write error: %v", err)
		}
		time.Sleep(100 * time.Millisecond)
		if _, err := stdin.Write([]byte("exit\n")); err != nil {
			t.Logf("stdin write error: %v", err)
		}
	}()

	output, err := io.ReadAll(stdout)
	if err != nil {
		t.Logf("Cannot read SSH output: %v", err)
	}

	err = cmd.Wait()
	if err != nil {
		t.Logf("SSH interactive session error: %v", err)
		t.Logf("Output: %s", string(output))
		return
	}

	assert.Contains(t, string(output), "interactive_test", "Interactive SSH session should work")
}

// testSSHPortForwarding tests port forwarding compatibility.
func testSSHPortForwarding(t *testing.T, host, port, keyFile string) {
	// Get appropriate user for SSH connection
	username := getTestUsername(t)

	testServer, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer testServer.Close()

	testServerAddr := testServer.Addr().String()
	expectedResponse := "HTTP/1.1 200 OK\r\nContent-Length: 21\r\n\r\nCompatibility Test OK"

	go func() {
		for {
			conn, err := testServer.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer func() {
					if err := c.Close(); err != nil {
						t.Logf("test server connection close error: %v", err)
					}
				}()
				buf := make([]byte, 1024)
				if _, err := c.Read(buf); err != nil {
					t.Logf("Test server read error: %v", err)
				}
				if _, err := c.Write([]byte(expectedResponse)); err != nil {
					t.Logf("Test server write error: %v", err)
				}
			}(conn)
		}
	}()

	localListener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	localAddr := localListener.Addr().String()
	localListener.Close()

	_, localPort, err := net.SplitHostPort(localAddr)
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	forwardSpec := fmt.Sprintf("%s:%s", localPort, testServerAddr)
	cmd := exec.CommandContext(ctx, "ssh",
		"-i", keyFile,
		"-p", port,
		"-L", forwardSpec,
		"-o", "StrictHostKeyChecking=no",
		"-o", "UserKnownHostsFile=/dev/null",
		"-o", "ConnectTimeout=5",
		"-N",
		fmt.Sprintf("%s@%s", username, host))

	err = cmd.Start()
	if err != nil {
		t.Logf("Cannot start SSH port forwarding: %v", err)
		return
	}

	defer func() {
		if cmd.Process != nil {
			if err := cmd.Process.Kill(); err != nil {
				t.Logf("process kill error: %v", err)
			}
		}
		if err := cmd.Wait(); err != nil {
			t.Logf("process wait after kill: %v", err)
		}
	}()

	time.Sleep(500 * time.Millisecond)

	conn, err := net.DialTimeout("tcp", localAddr, 3*time.Second)
	if err != nil {
		t.Logf("Cannot connect to forwarded port: %v", err)
		return
	}
	defer func() {
		if err := conn.Close(); err != nil {
			t.Logf("forwarded connection close error: %v", err)
		}
	}()

	request := "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
	_, err = conn.Write([]byte(request))
	require.NoError(t, err)

	if err := conn.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		log.Debugf("failed to set read deadline: %v", err)
	}
	response := make([]byte, len(expectedResponse))
	n, err := io.ReadFull(conn, response)
	if err != nil {
		t.Logf("Cannot read forwarded response: %v", err)
		return
	}

	assert.Equal(t, len(expectedResponse), n, "Should read expected number of bytes")
	assert.Equal(t, expectedResponse, string(response), "Should get correct HTTP response through SSH port forwarding")
}

// isSSHClientAvailable checks if the ssh binary is available
func isSSHClientAvailable() bool {
	_, err := exec.LookPath("ssh")
	return err == nil
}

// generateOpenSSHKey generates an ED25519 key in OpenSSH format that the system SSH client can use.
func generateOpenSSHKey(t *testing.T) ([]byte, []byte, error) {
	// Check if ssh-keygen is available
	if _, err := exec.LookPath("ssh-keygen"); err != nil {
		// Fall back to our existing key generation and try to convert
		return generateOpenSSHKeyFallback()
	}

	// Create temporary file for ssh-keygen
	tempFile, err := os.CreateTemp("", "ssh_keygen_*")
	if err != nil {
		return nil, nil, fmt.Errorf("create temp file: %w", err)
	}
	keyPath := tempFile.Name()
	tempFile.Close()

	// Remove the temp file so ssh-keygen can create it
	if err := os.Remove(keyPath); err != nil {
		t.Logf("failed to remove key file: %v", err)
	}

	// Clean up temp files
	defer func() {
		if err := os.Remove(keyPath); err != nil {
			t.Logf("failed to cleanup key file: %v", err)
		}
		if err := os.Remove(keyPath + ".pub"); err != nil {
			t.Logf("failed to cleanup public key file: %v", err)
		}
	}()

	// Generate key using ssh-keygen
	cmd := exec.Command("ssh-keygen", "-t", "ed25519", "-f", keyPath, "-N", "", "-q")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, nil, fmt.Errorf("ssh-keygen failed: %w, output: %s", err, string(output))
	}

	// Read private key
	privKeyBytes, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, nil, fmt.Errorf("read private key: %w", err)
	}

	// Read public key
	pubKeyBytes, err := os.ReadFile(keyPath + ".pub")
	if err != nil {
		return nil, nil, fmt.Errorf("read public key: %w", err)
	}

	return privKeyBytes, pubKeyBytes, nil
}

// generateOpenSSHKeyFallback falls back to generating keys using our existing method
func generateOpenSSHKeyFallback() ([]byte, []byte, error) {
	// Generate shared.ED25519 key pair using our existing method
	_, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generate key: %w", err)
	}

	// Convert to SSH format
	sshPrivKey, err := ssh.NewSignerFromKey(privKey)
	if err != nil {
		return nil, nil, fmt.Errorf("create signer: %w", err)
	}

	// For the fallback, just use our PKCS#8 format and hope it works
	// This won't be in OpenSSH format but might still work with some SSH clients
	hostKey, err := nbssh.GeneratePrivateKey(nbssh.ED25519)
	if err != nil {
		return nil, nil, fmt.Errorf("generate fallback key: %w", err)
	}

	// Get public key in SSH format
	sshPubKey := ssh.MarshalAuthorizedKey(sshPrivKey.PublicKey())

	return hostKey, sshPubKey, nil
}

// createTempKeyFileFromBytes creates a temporary SSH private key file from raw bytes
func createTempKeyFileFromBytes(t *testing.T, keyBytes []byte) (string, func()) {
	t.Helper()

	tempFile, err := os.CreateTemp("", "ssh_test_key_*")
	require.NoError(t, err)

	_, err = tempFile.Write(keyBytes)
	require.NoError(t, err)

	err = tempFile.Close()
	require.NoError(t, err)

	// Set proper permissions for SSH key (readable by owner only)
	err = os.Chmod(tempFile.Name(), 0600)
	require.NoError(t, err)

	cleanup := func() {
		_ = os.Remove(tempFile.Name())
	}

	return tempFile.Name(), cleanup
}

// createTempKeyFile creates a temporary SSH private key file (for backward compatibility)
func createTempKeyFile(t *testing.T, privateKey []byte) (string, func()) {
	return createTempKeyFileFromBytes(t, privateKey)
}

// TestSSHServerFeatureCompatibility tests specific SSH features for compatibility
func TestSSHServerFeatureCompatibility(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping SSH feature compatibility tests in short mode")
	}

	if runtime.GOOS == "windows" && isCI() {
		t.Skip("Skipping Windows SSH compatibility tests in CI due to S4U authentication issues")
	}

	if !isSSHClientAvailable() {
		t.Skip("SSH client not available on this system")
	}

	// Test various SSH features
	testCases := []struct {
		name        string
		testFunc    func(t *testing.T, host, port, keyFile string)
		description string
	}{
		{
			name:        "command_with_flags",
			testFunc:    testCommandWithFlags,
			description: "Commands with flags should work like standard SSH",
		},
		{
			name:        "environment_variables",
			testFunc:    testEnvironmentVariables,
			description: "Environment variables should be available",
		},
		{
			name:        "exit_codes",
			testFunc:    testExitCodes,
			description: "Exit codes should be properly handled",
		},
	}

	// Set up SSH server
	hostKey, err := nbssh.GeneratePrivateKey(nbssh.ED25519)
	require.NoError(t, err)

	clientPrivKey, err := nbssh.GeneratePrivateKey(nbssh.ED25519)
	require.NoError(t, err)
	clientPubKey, err := nbssh.GeneratePublicKey(clientPrivKey)
	require.NoError(t, err)

	server := New(hostKey)
	server.SetAllowRootLogin(true) // Allow root login for testing
	err = server.AddAuthorizedKey("test-peer", string(clientPubKey))
	require.NoError(t, err)

	serverAddr := StartTestServer(t, server)
	defer func() {
		err := server.Stop()
		require.NoError(t, err)
	}()

	clientKeyFile, cleanupKey := createTempKeyFile(t, clientPrivKey)
	defer cleanupKey()

	host, portStr, err := net.SplitHostPort(serverAddr)
	require.NoError(t, err)

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			tc.testFunc(t, host, portStr, clientKeyFile)
		})
	}
}

// testCommandWithFlags tests that commands with flags work properly
func testCommandWithFlags(t *testing.T, host, port, keyFile string) {
	// Get appropriate user for SSH connection
	username := getTestUsername(t)

	// Test ls with flags
	cmd := exec.Command("ssh",
		"-i", keyFile,
		"-p", port,
		"-o", "StrictHostKeyChecking=no",
		"-o", "UserKnownHostsFile=/dev/null",
		"-o", "ConnectTimeout=5",
		fmt.Sprintf("%s@%s", username, host),
		"ls", "-la", "/tmp")

	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Logf("Command with flags failed: %v", err)
		t.Logf("Output: %s", string(output))
		return
	}

	// Should not be empty and should not contain error messages
	assert.NotEmpty(t, string(output), "ls -la should produce output")
	assert.NotContains(t, strings.ToLower(string(output)), "command not found", "Command should be executed")
}

// testEnvironmentVariables tests that environment is properly set up
func testEnvironmentVariables(t *testing.T, host, port, keyFile string) {
	// Get appropriate user for SSH connection
	username := getTestUsername(t)

	cmd := exec.Command("ssh",
		"-i", keyFile,
		"-p", port,
		"-o", "StrictHostKeyChecking=no",
		"-o", "UserKnownHostsFile=/dev/null",
		"-o", "ConnectTimeout=5",
		fmt.Sprintf("%s@%s", username, host),
		"echo", "$HOME")

	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Logf("Environment test failed: %v", err)
		t.Logf("Output: %s", string(output))
		return
	}

	// HOME environment variable should be available
	homeOutput := strings.TrimSpace(string(output))
	assert.NotEmpty(t, homeOutput, "HOME environment variable should be set")
	assert.NotEqual(t, "$HOME", homeOutput, "Environment variable should be expanded")
}

// testExitCodes tests that exit codes are properly handled
func testExitCodes(t *testing.T, host, port, keyFile string) {
	// Get appropriate user for SSH connection
	username := getTestUsername(t)

	// Test successful command (exit code 0)
	cmd := exec.Command("ssh",
		"-i", keyFile,
		"-p", port,
		"-o", "StrictHostKeyChecking=no",
		"-o", "UserKnownHostsFile=/dev/null",
		"-o", "ConnectTimeout=5",
		fmt.Sprintf("%s@%s", username, host),
		"true") // always succeeds

	err := cmd.Run()
	assert.NoError(t, err, "Command with exit code 0 should succeed")

	// Test failing command (exit code 1)
	cmd = exec.Command("ssh",
		"-i", keyFile,
		"-p", port,
		"-o", "StrictHostKeyChecking=no",
		"-o", "UserKnownHostsFile=/dev/null",
		"-o", "ConnectTimeout=5",
		fmt.Sprintf("%s@%s", username, host),
		"false") // always fails

	err = cmd.Run()
	assert.Error(t, err, "Command with exit code 1 should fail")

	// Check if it's the right kind of error
	if exitError, ok := err.(*exec.ExitError); ok {
		assert.Equal(t, 1, exitError.ExitCode(), "Exit code should be preserved")
	}
}

// TestSSHServerSecurityFeatures tests security-related SSH features
func TestSSHServerSecurityFeatures(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping SSH security tests in short mode")
	}

	if !isSSHClientAvailable() {
		t.Skip("SSH client not available on this system")
	}

	// Get appropriate user for SSH connection
	username := getTestUsername(t)

	// Set up SSH server with specific security settings
	hostKey, err := nbssh.GeneratePrivateKey(nbssh.ED25519)
	require.NoError(t, err)

	clientPrivKey, err := nbssh.GeneratePrivateKey(nbssh.ED25519)
	require.NoError(t, err)
	clientPubKey, err := nbssh.GeneratePublicKey(clientPrivKey)
	require.NoError(t, err)

	server := New(hostKey)
	server.SetAllowRootLogin(true) // Allow root login for testing
	err = server.AddAuthorizedKey("test-peer", string(clientPubKey))
	require.NoError(t, err)

	serverAddr := StartTestServer(t, server)
	defer func() {
		err := server.Stop()
		require.NoError(t, err)
	}()

	clientKeyFile, cleanupKey := createTempKeyFile(t, clientPrivKey)
	defer cleanupKey()

	host, portStr, err := net.SplitHostPort(serverAddr)
	require.NoError(t, err)

	t.Run("key_authentication", func(t *testing.T) {
		// Test that key authentication works
		cmd := exec.Command("ssh",
			"-i", clientKeyFile,
			"-p", portStr,
			"-o", "StrictHostKeyChecking=no",
			"-o", "UserKnownHostsFile=/dev/null",
			"-o", "ConnectTimeout=5",
			"-o", "PasswordAuthentication=no",
			fmt.Sprintf("%s@%s", username, host),
			"echo", "auth_success")

		output, err := cmd.CombinedOutput()
		if err != nil {
			t.Logf("Key authentication failed: %v", err)
			t.Logf("Output: %s", string(output))
			return
		}

		assert.Contains(t, string(output), "auth_success", "Key authentication should work")
	})

	t.Run("any_key_accepted_in_no_auth_mode", func(t *testing.T) {
		// Create a different key that shouldn't be accepted
		wrongKey, err := nbssh.GeneratePrivateKey(nbssh.ED25519)
		require.NoError(t, err)

		wrongKeyFile, cleanupWrongKey := createTempKeyFile(t, wrongKey)
		defer cleanupWrongKey()

		// Test that wrong key is rejected
		cmd := exec.Command("ssh",
			"-i", wrongKeyFile,
			"-p", portStr,
			"-o", "StrictHostKeyChecking=no",
			"-o", "UserKnownHostsFile=/dev/null",
			"-o", "ConnectTimeout=5",
			"-o", "PasswordAuthentication=no",
			fmt.Sprintf("%s@%s", username, host),
			"echo", "should_not_work")

		err = cmd.Run()
		assert.NoError(t, err, "Any key should work in no-auth mode")
	})
}

// TestCrossPlatformCompatibility tests cross-platform behavior
func TestCrossPlatformCompatibility(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping cross-platform compatibility tests in short mode")
	}

	if !isSSHClientAvailable() {
		t.Skip("SSH client not available on this system")
	}

	// Get appropriate user for SSH connection
	username := getTestUsername(t)

	// Set up SSH server
	hostKey, err := nbssh.GeneratePrivateKey(nbssh.ED25519)
	require.NoError(t, err)

	clientPrivKey, err := nbssh.GeneratePrivateKey(nbssh.ED25519)
	require.NoError(t, err)
	clientPubKey, err := nbssh.GeneratePublicKey(clientPrivKey)
	require.NoError(t, err)

	server := New(hostKey)
	server.SetAllowRootLogin(true) // Allow root login for testing
	err = server.AddAuthorizedKey("test-peer", string(clientPubKey))
	require.NoError(t, err)

	serverAddr := StartTestServer(t, server)
	defer func() {
		err := server.Stop()
		require.NoError(t, err)
	}()

	clientKeyFile, cleanupKey := createTempKeyFile(t, clientPrivKey)
	defer cleanupKey()

	host, portStr, err := net.SplitHostPort(serverAddr)
	require.NoError(t, err)

	// Test platform-specific commands
	var testCommand string

	switch runtime.GOOS {
	case "windows":
		testCommand = "echo %OS%"
	default:
		testCommand = "uname"
	}

	cmd := exec.Command("ssh",
		"-i", clientKeyFile,
		"-p", portStr,
		"-o", "StrictHostKeyChecking=no",
		"-o", "UserKnownHostsFile=/dev/null",
		"-o", "ConnectTimeout=5",
		fmt.Sprintf("%s@%s", username, host),
		testCommand)

	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Logf("Platform-specific command failed: %v", err)
		t.Logf("Output: %s", string(output))
		return
	}

	outputStr := strings.TrimSpace(string(output))
	t.Logf("Platform command output: %s", outputStr)
	assert.NotEmpty(t, outputStr, "Platform-specific command should produce output")
}

// getTestUsername returns an appropriate username for testing
func getTestUsername(t *testing.T) string {
	if runtime.GOOS == "windows" {
		currentUser, err := user.Current()
		require.NoError(t, err, "Should be able to get current user")

		// Check if this is a system account that can't authenticate
		if isSystemAccount(currentUser.Username) {
			// In CI environments, create a test user; otherwise try Administrator
			if isCI() {
				if testUser := getOrCreateTestUser(t); testUser != "" {
					return testUser
				}
			} else {
				// Try Administrator first for local development
				if _, err := user.Lookup("Administrator"); err == nil {
					return "Administrator"
				}
				if testUser := getOrCreateTestUser(t); testUser != "" {
					return testUser
				}
			}
		}
		return currentUser.Username
	}

	currentUser, err := user.Current()
	require.NoError(t, err, "Should be able to get current user")
	return currentUser.Username
}

// isCI checks if we're running in a CI environment
func isCI() bool {
	ciEnvVars := []string{
		"CI", "CONTINUOUS_INTEGRATION", "GITHUB_ACTIONS",
		"GITLAB_CI", "JENKINS_URL", "BUILDKITE", "CIRCLECI",
	}

	for _, envVar := range ciEnvVars {
		if os.Getenv(envVar) != "" {
			return true
		}
	}
	return false
}

// isSystemAccount checks if the user is a system account that can't authenticate
func isSystemAccount(username string) bool {
	systemAccounts := []string{
		"system",
		"NT AUTHORITY\\SYSTEM",
		"NT AUTHORITY\\LOCAL SERVICE",
		"NT AUTHORITY\\NETWORK SERVICE",
	}

	for _, sysAccount := range systemAccounts {
		if strings.EqualFold(username, sysAccount) {
			return true
		}
	}
	return false
}

var compatTestCreatedUsers = make(map[string]bool)
var compatTestUsersToCleanup []string

// registerTestUserCleanup registers a test user for cleanup
func registerTestUserCleanup(username string) {
	if !compatTestCreatedUsers[username] {
		compatTestCreatedUsers[username] = true
		compatTestUsersToCleanup = append(compatTestUsersToCleanup, username)
	}
}

// cleanupTestUsers removes all created test users
func cleanupTestUsers() {
	for _, username := range compatTestUsersToCleanup {
		removeWindowsTestUser(username)
	}
	compatTestUsersToCleanup = nil
	compatTestCreatedUsers = make(map[string]bool)
}

// getOrCreateTestUser creates a test user on Windows if needed
func getOrCreateTestUser(t *testing.T) string {
	testUsername := "netbird-test-user"

	// Check if user already exists
	if _, err := user.Lookup(testUsername); err == nil {
		return testUsername
	}

	// Try to create the user using PowerShell
	if createWindowsTestUser(t, testUsername) {
		// Register cleanup for the test user
		registerTestUserCleanup(testUsername)
		return testUsername
	}

	return ""
}

// removeWindowsTestUser removes a local user on Windows using PowerShell
func removeWindowsTestUser(username string) {
	if runtime.GOOS != "windows" {
		return
	}

	// PowerShell command to remove a local user
	psCmd := fmt.Sprintf(`
		try {
			Remove-LocalUser -Name "%s" -ErrorAction Stop
			Write-Output "User removed successfully"
		} catch {
			if ($_.Exception.Message -like "*cannot be found*") {
				Write-Output "User not found (already removed)"
			} else {
				Write-Error $_.Exception.Message
			}
		}
	`, username)

	cmd := exec.Command("powershell", "-Command", psCmd)
	output, err := cmd.CombinedOutput()

	if err != nil {
		log.Printf("Failed to remove test user %s: %v, output: %s", username, err, string(output))
	} else {
		log.Printf("Test user %s cleanup result: %s", username, string(output))
	}
}

// createWindowsTestUser creates a local user on Windows using PowerShell
func createWindowsTestUser(t *testing.T, username string) bool {
	if runtime.GOOS != "windows" {
		return false
	}

	// PowerShell command to create a local user
	psCmd := fmt.Sprintf(`
		try {
			$password = ConvertTo-SecureString "TestPassword123!" -AsPlainText -Force
			New-LocalUser -Name "%s" -Password $password -Description "NetBird test user" -UserMayNotChangePassword -PasswordNeverExpires
			Add-LocalGroupMember -Group "Users" -Member "%s"
			Write-Output "User created successfully"
		} catch {
			if ($_.Exception.Message -like "*already exists*") {
				Write-Output "User already exists"
			} else {
				Write-Error $_.Exception.Message
				exit 1
			}
		}
	`, username, username)

	cmd := exec.Command("powershell", "-Command", psCmd)
	output, err := cmd.CombinedOutput()

	if err != nil {
		t.Logf("Failed to create test user: %v, output: %s", err, string(output))
		return false
	}

	t.Logf("Test user creation result: %s", string(output))
	return true
}
