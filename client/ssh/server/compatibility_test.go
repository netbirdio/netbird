package server

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"

	nbssh "github.com/netbirdio/netbird/client/ssh"
	"github.com/netbirdio/netbird/client/ssh/testutil"
)

func TestMain(m *testing.M) {
	// On platforms where su doesn't support --pty (macOS, FreeBSD, Windows), the SSH server
	// spawns an executor subprocess via os.Executable(). During tests, this invokes the test
	// binary with "ssh exec" args. We handle that here to properly execute commands and
	// propagate exit codes.
	if len(os.Args) > 2 && os.Args[1] == "ssh" && os.Args[2] == "exec" {
		runTestExecutor()
		return
	}

	code := m.Run()
	testutil.CleanupTestUsers()
	os.Exit(code)
}

// runTestExecutor emulates the netbird executor for tests.
// Parses --shell and --cmd args, runs the command, and exits with the correct code.
func runTestExecutor() {
	if os.Getenv("_NETBIRD_TEST_EXECUTOR") != "" {
		fmt.Fprintf(os.Stderr, "executor recursion detected\n")
		os.Exit(1)
	}
	os.Setenv("_NETBIRD_TEST_EXECUTOR", "1")

	shell := "/bin/sh"
	var command string
	for i := 3; i < len(os.Args); i++ {
		switch os.Args[i] {
		case "--shell":
			if i+1 < len(os.Args) {
				shell = os.Args[i+1]
				i++
			}
		case "--cmd":
			if i+1 < len(os.Args) {
				command = os.Args[i+1]
				i++
			}
		}
	}

	var cmd *exec.Cmd
	if command == "" {
		cmd = exec.Command(shell)
	} else {
		cmd = exec.Command(shell, "-c", command)
	}
	cmd.Args[0] = "-" + filepath.Base(shell)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			os.Exit(exitErr.ExitCode())
		}
		os.Exit(1)
	}
	os.Exit(0)
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
	clientPrivKeyOpenSSH, _, err := generateOpenSSHKey(t)
	require.NoError(t, err)

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

	// Create temporary key files for SSH client
	clientKeyFile, cleanupKey := createTempKeyFileFromBytes(t, clientPrivKeyOpenSSH)
	defer cleanupKey()

	// Extract host and port from server address
	host, portStr, err := net.SplitHostPort(serverAddr)
	require.NoError(t, err)

	// Get appropriate user for SSH connection (handle system accounts)
	username := testutil.GetTestUsername(t)

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
	username := testutil.GetTestUsername(t)

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
	username := testutil.GetTestUsername(t)

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

// TestSSHPtyModes tests different PTY allocation modes (-T, -t, -tt flags)
// This ensures our implementation matches OpenSSH behavior for:
// - ssh host command        (no PTY - default when no TTY)
// - ssh -T host command     (explicit no PTY)
// - ssh -t host command     (force PTY)
// - ssh -T host             (no PTY shell - our implementation)
func TestSSHPtyModes(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping SSH PTY mode tests in short mode")
	}

	if !isSSHClientAvailable() {
		t.Skip("SSH client not available on this system")
	}

	if runtime.GOOS == "windows" && testutil.IsCI() {
		t.Skip("Skipping Windows SSH PTY tests in CI due to S4U authentication issues")
	}

	hostKey, err := nbssh.GeneratePrivateKey(nbssh.ED25519)
	require.NoError(t, err)

	clientPrivKeyOpenSSH, _, err := generateOpenSSHKey(t)
	require.NoError(t, err)

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

	clientKeyFile, cleanupKey := createTempKeyFileFromBytes(t, clientPrivKeyOpenSSH)
	defer cleanupKey()

	host, portStr, err := net.SplitHostPort(serverAddr)
	require.NoError(t, err)

	username := testutil.GetTestUsername(t)

	baseArgs := []string{
		"-i", clientKeyFile,
		"-p", portStr,
		"-o", "StrictHostKeyChecking=no",
		"-o", "UserKnownHostsFile=/dev/null",
		"-o", "ConnectTimeout=5",
		"-o", "BatchMode=yes",
	}

	t.Run("command_default_no_pty", func(t *testing.T) {
		args := append(slices.Clone(baseArgs), fmt.Sprintf("%s@%s", username, host), "echo", "no_pty_default")
		cmd := exec.Command("ssh", args...)

		output, err := cmd.CombinedOutput()
		require.NoError(t, err, "Command (default no PTY) failed: %s", output)
		assert.Contains(t, string(output), "no_pty_default")
	})

	t.Run("command_explicit_no_pty", func(t *testing.T) {
		args := append(slices.Clone(baseArgs), "-T", fmt.Sprintf("%s@%s", username, host), "echo", "explicit_no_pty")
		cmd := exec.Command("ssh", args...)

		output, err := cmd.CombinedOutput()
		require.NoError(t, err, "Command (-T explicit no PTY) failed: %s", output)
		assert.Contains(t, string(output), "explicit_no_pty")
	})

	t.Run("command_force_pty", func(t *testing.T) {
		args := append(slices.Clone(baseArgs), "-tt", fmt.Sprintf("%s@%s", username, host), "echo", "force_pty")
		cmd := exec.Command("ssh", args...)

		output, err := cmd.CombinedOutput()
		require.NoError(t, err, "Command (-tt force PTY) failed: %s", output)
		assert.Contains(t, string(output), "force_pty")
	})

	t.Run("shell_explicit_no_pty", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		args := append(slices.Clone(baseArgs), "-T", fmt.Sprintf("%s@%s", username, host))
		cmd := exec.CommandContext(ctx, "ssh", args...)

		stdin, err := cmd.StdinPipe()
		require.NoError(t, err)

		stdout, err := cmd.StdoutPipe()
		require.NoError(t, err)

		require.NoError(t, cmd.Start(), "Shell (-T no PTY) start failed")

		go func() {
			defer stdin.Close()
			time.Sleep(100 * time.Millisecond)
			_, err := stdin.Write([]byte("echo shell_no_pty_test\n"))
			assert.NoError(t, err, "write echo command")
			time.Sleep(100 * time.Millisecond)
			_, err = stdin.Write([]byte("exit 0\n"))
			assert.NoError(t, err, "write exit command")
		}()

		output, _ := io.ReadAll(stdout)
		err = cmd.Wait()

		require.NoError(t, err, "Shell (-T no PTY) failed: %s", output)
		assert.Contains(t, string(output), "shell_no_pty_test")
	})

	t.Run("exit_code_preserved_no_pty", func(t *testing.T) {
		args := append(slices.Clone(baseArgs), "-T", fmt.Sprintf("%s@%s", username, host), "exit", "42")
		cmd := exec.Command("ssh", args...)

		err := cmd.Run()
		require.Error(t, err, "Command should exit with non-zero")

		var exitErr *exec.ExitError
		require.True(t, errors.As(err, &exitErr), "Should be an exit error: %v", err)
		assert.Equal(t, 42, exitErr.ExitCode(), "Exit code should be preserved with -T")
	})

	t.Run("exit_code_preserved_with_pty", func(t *testing.T) {
		args := append(slices.Clone(baseArgs), "-tt", fmt.Sprintf("%s@%s", username, host), "sh -c 'exit 43'")
		cmd := exec.Command("ssh", args...)

		err := cmd.Run()
		require.Error(t, err, "PTY command should exit with non-zero")

		var exitErr *exec.ExitError
		require.True(t, errors.As(err, &exitErr), "Should be an exit error: %v", err)
		assert.Equal(t, 43, exitErr.ExitCode(), "Exit code should be preserved with -tt")
	})

	t.Run("stderr_works_no_pty", func(t *testing.T) {
		args := append(slices.Clone(baseArgs), "-T", fmt.Sprintf("%s@%s", username, host),
			"sh -c 'echo stdout_msg; echo stderr_msg >&2'")
		cmd := exec.Command("ssh", args...)

		var stdout, stderr strings.Builder
		cmd.Stdout = &stdout
		cmd.Stderr = &stderr

		require.NoError(t, cmd.Run(), "stderr test failed")
		assert.Contains(t, stdout.String(), "stdout_msg", "stdout should have stdout_msg")
		assert.Contains(t, stderr.String(), "stderr_msg", "stderr should have stderr_msg")
		assert.NotContains(t, stdout.String(), "stderr_msg", "stdout should NOT have stderr_msg")
	})

	t.Run("stderr_merged_with_pty", func(t *testing.T) {
		args := append(slices.Clone(baseArgs), "-tt", fmt.Sprintf("%s@%s", username, host),
			"sh -c 'echo stdout_msg; echo stderr_msg >&2'")
		cmd := exec.Command("ssh", args...)

		output, err := cmd.CombinedOutput()
		require.NoError(t, err, "PTY stderr test failed: %s", output)
		assert.Contains(t, string(output), "stdout_msg")
		assert.Contains(t, string(output), "stderr_msg")
	})
}

// TestSSHServerFeatureCompatibility tests specific SSH features for compatibility
func TestSSHServerFeatureCompatibility(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping SSH feature compatibility tests in short mode")
	}

	if runtime.GOOS == "windows" && testutil.IsCI() {
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
	username := testutil.GetTestUsername(t)

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
	username := testutil.GetTestUsername(t)

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
	username := testutil.GetTestUsername(t)

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
	username := testutil.GetTestUsername(t)

	// Set up SSH server with specific security settings
	hostKey, err := nbssh.GeneratePrivateKey(nbssh.ED25519)
	require.NoError(t, err)

	clientPrivKey, err := nbssh.GeneratePrivateKey(nbssh.ED25519)
	require.NoError(t, err)

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
	username := testutil.GetTestUsername(t)

	// Set up SSH server
	hostKey, err := nbssh.GeneratePrivateKey(nbssh.ED25519)
	require.NoError(t, err)

	clientPrivKey, err := nbssh.GeneratePrivateKey(nbssh.ED25519)
	require.NoError(t, err)

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
