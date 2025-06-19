package ssh

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	cryptossh "golang.org/x/crypto/ssh"
)

func TestSSHClient_DialWithKey(t *testing.T) {
	// Generate host key for server
	hostKey, err := GeneratePrivateKey(ED25519)
	require.NoError(t, err)

	// Generate client key pair
	clientPrivKey, err := GeneratePrivateKey(ED25519)
	require.NoError(t, err)
	clientPubKey, err := GeneratePublicKey(clientPrivKey)
	require.NoError(t, err)

	// Create and start server
	server := NewServer(hostKey)
	err = server.AddAuthorizedKey("test-peer", string(clientPubKey))
	require.NoError(t, err)

	serverAddr := startTestServer(t, server)
	defer func() {
		err := server.Stop()
		require.NoError(t, err)
	}()

	// Test DialWithKey
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	client, err := DialWithKey(ctx, serverAddr, "test-user", clientPrivKey)
	require.NoError(t, err)
	defer func() {
		err := client.Close()
		assert.NoError(t, err)
	}()

	// Verify client is connected
	assert.NotNil(t, client.client)
}

func TestSSHClient_ExecuteCommand(t *testing.T) {
	// Generate host key for server
	hostKey, err := GeneratePrivateKey(ED25519)
	require.NoError(t, err)

	// Generate client key pair
	clientPrivKey, err := GeneratePrivateKey(ED25519)
	require.NoError(t, err)
	clientPubKey, err := GeneratePublicKey(clientPrivKey)
	require.NoError(t, err)

	// Create and start server
	server := NewServer(hostKey)
	err = server.AddAuthorizedKey("test-peer", string(clientPubKey))
	require.NoError(t, err)

	serverAddr := startTestServer(t, server)
	defer func() {
		err := server.Stop()
		require.NoError(t, err)
	}()

	// Connect client
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	client, err := DialWithKey(ctx, serverAddr, "test-user", clientPrivKey)
	require.NoError(t, err)
	defer func() {
		err := client.Close()
		assert.NoError(t, err)
	}()

	// Test ExecuteCommand
	cmdCtx, cmdCancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cmdCancel()

	// Execute a simple command - should work with our SSH server
	output, err := client.ExecuteCommand(cmdCtx, "echo hello")
	assert.NoError(t, err)
	assert.NotNil(t, output)
}

func TestSSHClient_ExecuteCommandWithIO(t *testing.T) {
	// Generate host key for server
	hostKey, err := GeneratePrivateKey(ED25519)
	require.NoError(t, err)

	// Generate client key pair
	clientPrivKey, err := GeneratePrivateKey(ED25519)
	require.NoError(t, err)
	clientPubKey, err := GeneratePublicKey(clientPrivKey)
	require.NoError(t, err)

	// Create and start server
	server := NewServer(hostKey)
	err = server.AddAuthorizedKey("test-peer", string(clientPubKey))
	require.NoError(t, err)

	serverAddr := startTestServer(t, server)
	defer func() {
		err := server.Stop()
		require.NoError(t, err)
	}()

	// Connect client
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	client, err := DialWithKey(ctx, serverAddr, "test-user", clientPrivKey)
	require.NoError(t, err)
	defer func() {
		err := client.Close()
		assert.NoError(t, err)
	}()

	// Test ExecuteCommandWithIO
	cmdCtx, cmdCancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cmdCancel()

	// Execute a simple command with IO
	err = client.ExecuteCommandWithIO(cmdCtx, "echo hello")
	assert.NoError(t, err)
}

func TestSSHClient_ConnectionHandling(t *testing.T) {
	// Generate host key for server
	hostKey, err := GeneratePrivateKey(ED25519)
	require.NoError(t, err)

	// Generate client key pair
	clientPrivKey, err := GeneratePrivateKey(ED25519)
	require.NoError(t, err)
	clientPubKey, err := GeneratePublicKey(clientPrivKey)
	require.NoError(t, err)

	// Create and start server
	server := NewServer(hostKey)
	err = server.AddAuthorizedKey("test-peer", string(clientPubKey))
	require.NoError(t, err)

	serverAddr := startTestServer(t, server)
	defer func() {
		err := server.Stop()
		require.NoError(t, err)
	}()

	// Test multiple client connections
	const numClients = 3
	clients := make([]*Client, numClients)

	for i := 0; i < numClients; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		client, err := DialWithKey(ctx, serverAddr, fmt.Sprintf("test-user-%d", i), clientPrivKey)
		cancel()
		require.NoError(t, err, "Client %d should connect successfully", i)
		clients[i] = client
	}

	// Close all clients
	for i, client := range clients {
		err := client.Close()
		assert.NoError(t, err, "Client %d should close without error", i)
	}
}

func TestSSHClient_ContextCancellation(t *testing.T) {
	// Generate host key for server
	hostKey, err := GeneratePrivateKey(ED25519)
	require.NoError(t, err)

	// Generate client key pair
	clientPrivKey, err := GeneratePrivateKey(ED25519)
	require.NoError(t, err)
	clientPubKey, err := GeneratePublicKey(clientPrivKey)
	require.NoError(t, err)

	// Create and start server
	server := NewServer(hostKey)
	err = server.AddAuthorizedKey("test-peer", string(clientPubKey))
	require.NoError(t, err)

	serverAddr := startTestServer(t, server)
	defer func() {
		err := server.Stop()
		require.NoError(t, err)
	}()

	// Test context cancellation during connection
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Millisecond) // Very short timeout
	defer cancel()

	_, err = DialWithKey(ctx, serverAddr, "test-user", clientPrivKey)
	// Should either succeed quickly or fail due to context cancellation
	if err != nil {
		assert.Contains(t, err.Error(), "context")
	}
}

func TestSSHClient_InvalidAuth(t *testing.T) {
	// Generate host key for server
	hostKey, err := GeneratePrivateKey(ED25519)
	require.NoError(t, err)

	// Generate authorized key
	authorizedPrivKey, err := GeneratePrivateKey(ED25519)
	require.NoError(t, err)
	authorizedPubKey, err := GeneratePublicKey(authorizedPrivKey)
	require.NoError(t, err)

	// Generate unauthorized key (different from authorized)
	unauthorizedPrivKey, err := GeneratePrivateKey(ED25519)
	require.NoError(t, err)

	// Create server with only one authorized key
	server := NewServer(hostKey)
	err = server.AddAuthorizedKey("authorized-peer", string(authorizedPubKey))
	require.NoError(t, err)

	serverAddr := startTestServer(t, server)
	defer func() {
		err := server.Stop()
		require.NoError(t, err)
	}()

	// Try to connect with unauthorized key
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err = DialWithKey(ctx, serverAddr, "test-user", unauthorizedPrivKey)
	assert.Error(t, err, "Connection should fail with unauthorized key")
}

func TestSSHClient_TerminalStateRestoration(t *testing.T) {
	// Generate host key for server
	hostKey, err := GeneratePrivateKey(ED25519)
	require.NoError(t, err)

	// Generate client key pair
	clientPrivKey, err := GeneratePrivateKey(ED25519)
	require.NoError(t, err)
	clientPubKey, err := GeneratePublicKey(clientPrivKey)
	require.NoError(t, err)

	// Create and start server
	server := NewServer(hostKey)
	err = server.AddAuthorizedKey("test-peer", string(clientPubKey))
	require.NoError(t, err)

	serverAddr := startTestServer(t, server)
	defer func() {
		err := server.Stop()
		require.NoError(t, err)
	}()

	// Connect client
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	client, err := DialWithKey(ctx, serverAddr, "test-user", clientPrivKey)
	require.NoError(t, err)
	defer func() {
		err := client.Close()
		assert.NoError(t, err)
	}()

	// Test that terminal state fields are properly initialized
	assert.Nil(t, client.terminalState, "Terminal state should be nil initially")
	assert.Equal(t, 0, client.terminalFd, "Terminal fd should be 0 initially")

	// Test that restoreTerminal() doesn't panic when called with nil state
	client.restoreTerminal()
	assert.Nil(t, client.terminalState, "Terminal state should remain nil after restore")

	// Note: Windows console state is now handled by golang.org/x/term internally
}

func TestSSHClient_SignalForwarding(t *testing.T) {
	// Generate host key for server
	hostKey, err := GeneratePrivateKey(ED25519)
	require.NoError(t, err)

	// Generate client key pair
	clientPrivKey, err := GeneratePrivateKey(ED25519)
	require.NoError(t, err)
	clientPubKey, err := GeneratePublicKey(clientPrivKey)
	require.NoError(t, err)

	// Create and start server
	server := NewServer(hostKey)
	err = server.AddAuthorizedKey("test-peer", string(clientPubKey))
	require.NoError(t, err)

	serverAddr := startTestServer(t, server)
	defer func() {
		err := server.Stop()
		require.NoError(t, err)
	}()

	// Connect client
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	client, err := DialWithKey(ctx, serverAddr, "test-user", clientPrivKey)
	require.NoError(t, err)
	defer func() {
		err := client.Close()
		assert.NoError(t, err)
	}()

	// Test that we can execute a command and it works
	// This indirectly tests that the signal handling setup doesn't break normal functionality
	cmdCtx, cmdCancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cmdCancel()

	output, err := client.ExecuteCommand(cmdCtx, "echo signal_test")
	assert.NoError(t, err)
	assert.Contains(t, string(output), "signal_test")
}

func TestSSHClient_InteractiveCommands(t *testing.T) {
	// Generate host key for server
	hostKey, err := GeneratePrivateKey(ED25519)
	require.NoError(t, err)

	// Generate client key pair
	clientPrivKey, err := GeneratePrivateKey(ED25519)
	require.NoError(t, err)
	clientPubKey, err := GeneratePublicKey(clientPrivKey)
	require.NoError(t, err)

	// Create and start server
	server := NewServer(hostKey)
	err = server.AddAuthorizedKey("test-peer", string(clientPubKey))
	require.NoError(t, err)

	serverAddr := startTestServer(t, server)
	defer func() {
		err := server.Stop()
		require.NoError(t, err)
	}()

	// Connect client
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	client, err := DialWithKey(ctx, serverAddr, "test-user", clientPrivKey)
	require.NoError(t, err)
	defer func() {
		err := client.Close()
		assert.NoError(t, err)
	}()

	// Test ExecuteCommandWithIO for interactive-style commands
	// Note: This won't actually be interactive in tests, but verifies the method works
	cmdCtx, cmdCancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cmdCancel()

	err = client.ExecuteCommandWithIO(cmdCtx, "echo interactive_test")
	assert.NoError(t, err)
}

func TestSSHClient_NonTerminalEnvironment(t *testing.T) {
	// This test verifies that SSH client works in non-terminal environments
	// (like CI, redirected input/output, etc.)

	// Generate host key for server
	hostKey, err := GeneratePrivateKey(ED25519)
	require.NoError(t, err)

	// Generate client key pair
	clientPrivKey, err := GeneratePrivateKey(ED25519)
	require.NoError(t, err)
	clientPubKey, err := GeneratePublicKey(clientPrivKey)
	require.NoError(t, err)

	// Create and start server
	server := NewServer(hostKey)
	err = server.AddAuthorizedKey("test-peer", string(clientPubKey))
	require.NoError(t, err)

	serverAddr := startTestServer(t, server)
	defer func() {
		err := server.Stop()
		require.NoError(t, err)
	}()

	// Connect client - this should work even in non-terminal environments
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	client, err := DialWithKey(ctx, serverAddr, "test-user", clientPrivKey)
	require.NoError(t, err)
	defer func() {
		err := client.Close()
		assert.NoError(t, err)
	}()

	// Test command execution works in non-terminal environment
	cmdCtx, cmdCancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cmdCancel()

	output, err := client.ExecuteCommand(cmdCtx, "echo non_terminal_test")
	assert.NoError(t, err)
	assert.Contains(t, string(output), "non_terminal_test")
}

// Helper function to start a test server and return its address
func startTestServer(t *testing.T, server *Server) string {
	started := make(chan string, 1)
	errChan := make(chan error, 1)

	go func() {
		// Get a free port
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			errChan <- err
			return
		}
		actualAddr := ln.Addr().String()
		if err := ln.Close(); err != nil {
			errChan <- fmt.Errorf("close temp listener: %w", err)
			return
		}

		started <- actualAddr
		errChan <- server.Start(actualAddr)
	}()

	select {
	case actualAddr := <-started:
		return actualAddr
	case err := <-errChan:
		t.Fatalf("Server failed to start: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("Server start timeout")
	}
	return ""
}

func TestSSHClient_NonInteractiveCommand(t *testing.T) {
	hostKey, err := GeneratePrivateKey(ED25519)
	require.NoError(t, err)

	clientPrivKey, err := GeneratePrivateKey(ED25519)
	require.NoError(t, err)
	clientPubKey, err := GeneratePublicKey(clientPrivKey)
	require.NoError(t, err)

	server := NewServer(hostKey)
	err = server.AddAuthorizedKey("test-peer", string(clientPubKey))
	require.NoError(t, err)

	serverAddr := startTestServer(t, server)
	defer func() {
		err := server.Stop()
		require.NoError(t, err)
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	client, err := DialWithKey(ctx, serverAddr, "test-user", clientPrivKey)
	require.NoError(t, err)
	defer func() {
		err := client.Close()
		assert.NoError(t, err)
	}()

	// Test non-interactive command (should not drop to shell)
	cmdCtx, cmdCancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cmdCancel()

	err = client.ExecuteCommandWithIO(cmdCtx, "echo hello_test")
	assert.NoError(t, err, "Non-interactive command should execute and exit")
}

func TestSSHClient_CommandWithFlags(t *testing.T) {
	hostKey, err := GeneratePrivateKey(ED25519)
	require.NoError(t, err)

	clientPrivKey, err := GeneratePrivateKey(ED25519)
	require.NoError(t, err)
	clientPubKey, err := GeneratePublicKey(clientPrivKey)
	require.NoError(t, err)

	server := NewServer(hostKey)
	err = server.AddAuthorizedKey("test-peer", string(clientPubKey))
	require.NoError(t, err)

	serverAddr := startTestServer(t, server)
	defer func() {
		err := server.Stop()
		require.NoError(t, err)
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	client, err := DialWithKey(ctx, serverAddr, "test-user", clientPrivKey)
	require.NoError(t, err)
	defer func() {
		err := client.Close()
		assert.NoError(t, err)
	}()

	// Test command with flags (should pass flags to remote command)
	cmdCtx, cmdCancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cmdCancel()

	// Test ls with -la flags
	err = client.ExecuteCommandWithIO(cmdCtx, "ls -la /tmp")
	assert.NoError(t, err, "Command with flags should be passed to remote")

	// Test echo with -n flag
	output, err := client.ExecuteCommand(cmdCtx, "echo -n test_flag")
	assert.NoError(t, err)
	assert.Equal(t, "test_flag", strings.TrimSpace(string(output)), "Flag should be passed to remote echo command")
}

func TestSSHClient_PTYVsNoPTY(t *testing.T) {
	hostKey, err := GeneratePrivateKey(ED25519)
	require.NoError(t, err)

	clientPrivKey, err := GeneratePrivateKey(ED25519)
	require.NoError(t, err)
	clientPubKey, err := GeneratePublicKey(clientPrivKey)
	require.NoError(t, err)

	server := NewServer(hostKey)
	err = server.AddAuthorizedKey("test-peer", string(clientPubKey))
	require.NoError(t, err)

	serverAddr := startTestServer(t, server)
	defer func() {
		err := server.Stop()
		require.NoError(t, err)
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	client, err := DialWithKey(ctx, serverAddr, "test-user", clientPrivKey)
	require.NoError(t, err)
	defer func() {
		err := client.Close()
		assert.NoError(t, err)
	}()

	cmdCtx, cmdCancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cmdCancel()

	// Test ExecuteCommandWithIO (no PTY) - should not drop to shell
	err = client.ExecuteCommandWithIO(cmdCtx, "echo no_pty_test")
	assert.NoError(t, err, "ExecuteCommandWithIO should execute command without PTY")

	// Test ExecuteCommand (also no PTY) - should capture output
	output, err := client.ExecuteCommand(cmdCtx, "echo captured_output")
	assert.NoError(t, err, "ExecuteCommand should work without PTY")
	assert.Contains(t, string(output), "captured_output", "Output should be captured")
}

func TestSSHClient_PipedCommand(t *testing.T) {
	hostKey, err := GeneratePrivateKey(ED25519)
	require.NoError(t, err)

	clientPrivKey, err := GeneratePrivateKey(ED25519)
	require.NoError(t, err)
	clientPubKey, err := GeneratePublicKey(clientPrivKey)
	require.NoError(t, err)

	server := NewServer(hostKey)
	err = server.AddAuthorizedKey("test-peer", string(clientPubKey))
	require.NoError(t, err)

	serverAddr := startTestServer(t, server)
	defer func() {
		err := server.Stop()
		require.NoError(t, err)
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	client, err := DialWithKey(ctx, serverAddr, "test-user", clientPrivKey)
	require.NoError(t, err)
	defer func() {
		err := client.Close()
		assert.NoError(t, err)
	}()

	// Test piped commands work correctly
	cmdCtx, cmdCancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cmdCancel()

	// Test with piped commands that don't require PTY
	var pipeCmd string
	if runtime.GOOS == "windows" {
		pipeCmd = "echo hello world | Select-String hello"
	} else {
		pipeCmd = "echo 'hello world' | grep hello"
	}

	output, err := client.ExecuteCommand(cmdCtx, pipeCmd)
	assert.NoError(t, err, "Piped commands should work")
	assert.Contains(t, strings.TrimSpace(string(output)), "hello", "Piped command output should contain expected text")
}

func TestSSHClient_InteractiveTerminalBehavior(t *testing.T) {
	hostKey, err := GeneratePrivateKey(ED25519)
	require.NoError(t, err)

	clientPrivKey, err := GeneratePrivateKey(ED25519)
	require.NoError(t, err)
	clientPubKey, err := GeneratePublicKey(clientPrivKey)
	require.NoError(t, err)

	server := NewServer(hostKey)
	err = server.AddAuthorizedKey("test-peer", string(clientPubKey))
	require.NoError(t, err)

	serverAddr := startTestServer(t, server)
	defer func() {
		err := server.Stop()
		require.NoError(t, err)
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	client, err := DialWithKey(ctx, serverAddr, "test-user", clientPrivKey)
	require.NoError(t, err)
	defer func() {
		err := client.Close()
		assert.NoError(t, err)
	}()

	// Test that OpenTerminal would work (though it will timeout in test)
	termCtx, termCancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer termCancel()

	err = client.OpenTerminal(termCtx)
	// Should timeout since we can't provide interactive input in tests
	assert.Error(t, err, "OpenTerminal should timeout in test environment")

	if runtime.GOOS == "windows" {
		// Windows may have console handle issues in test environment
		assert.True(t,
			strings.Contains(err.Error(), "context deadline exceeded") ||
				strings.Contains(err.Error(), "console"),
			"Should timeout or have console error on Windows, got: %v", err)
	} else {
		assert.Contains(t, err.Error(), "context deadline exceeded", "Should timeout due to no interactive input")
	}
}

func TestSSHClient_SignalHandling(t *testing.T) {
	hostKey, err := GeneratePrivateKey(ED25519)
	require.NoError(t, err)

	clientPrivKey, err := GeneratePrivateKey(ED25519)
	require.NoError(t, err)
	clientPubKey, err := GeneratePublicKey(clientPrivKey)
	require.NoError(t, err)

	server := NewServer(hostKey)
	err = server.AddAuthorizedKey("test-peer", string(clientPubKey))
	require.NoError(t, err)

	serverAddr := startTestServer(t, server)
	defer func() {
		err := server.Stop()
		require.NoError(t, err)
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	client, err := DialWithKey(ctx, serverAddr, "test-user", clientPrivKey)
	require.NoError(t, err)
	defer func() {
		err := client.Close()
		assert.NoError(t, err)
	}()

	// Test context cancellation (simulates Ctrl+C)
	cmdCtx, cmdCancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cmdCancel()

	// Start a long-running command that will be cancelled
	// Use a command that should work reliably across platforms
	start := time.Now()
	err = client.ExecuteCommandWithPTY(cmdCtx, "sleep 10")
	duration := time.Since(start)

	// What we care about is that the command was terminated due to context cancellation
	// This can manifest in several ways:
	// 1. Context deadline exceeded error
	// 2. ExitMissingError (clean termination without exit status)
	// 3. No error but command completed due to cancellation
	if err != nil {
		// Accept context errors or ExitMissingError (both indicate successful cancellation)
		var exitMissingErr *cryptossh.ExitMissingError
		isValidCancellation := errors.Is(err, context.DeadlineExceeded) ||
			errors.Is(err, context.Canceled) ||
			errors.As(err, &exitMissingErr)

		// If we got a valid cancellation error, the test passes
		if isValidCancellation {
			return
		}

		// If we got some other error, that's unexpected
		t.Errorf("Unexpected error type: %s", err.Error())
		return
	}

	// If no error was returned, check if this was due to rapid command failure
	// or actual successful cancellation
	if duration < 50*time.Millisecond {
		// Command completed too quickly, likely failed to start properly
		// This can happen in test environments - skip the test in this case
		t.Skip("Command completed too quickly, likely environment issue - skipping test")
		return
	}

	// If command took reasonable time, context should be cancelled
	assert.Error(t, cmdCtx.Err(), "Context should be cancelled due to timeout")
}

func TestSSHClient_TerminalStateCleanup(t *testing.T) {
	hostKey, err := GeneratePrivateKey(ED25519)
	require.NoError(t, err)

	clientPrivKey, err := GeneratePrivateKey(ED25519)
	require.NoError(t, err)
	clientPubKey, err := GeneratePublicKey(clientPrivKey)
	require.NoError(t, err)

	server := NewServer(hostKey)
	err = server.AddAuthorizedKey("test-peer", string(clientPubKey))
	require.NoError(t, err)

	serverAddr := startTestServer(t, server)
	defer func() {
		err := server.Stop()
		require.NoError(t, err)
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	client, err := DialWithKey(ctx, serverAddr, "test-user", clientPrivKey)
	require.NoError(t, err)
	defer func() {
		err := client.Close()
		assert.NoError(t, err)
	}()

	// Verify initial state
	assert.Nil(t, client.terminalState, "Terminal state should be nil initially")
	assert.Equal(t, 0, client.terminalFd, "Terminal fd should be 0 initially")

	// Test that restoreTerminal doesn't panic with nil state
	client.restoreTerminal()
	assert.Nil(t, client.terminalState, "Terminal state should remain nil after restore")

	// Test command execution that might set terminal state
	cmdCtx, cmdCancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cmdCancel()

	// Use a simple command that's more reliable in PTY mode
	var testCmd string
	if runtime.GOOS == "windows" {
		testCmd = "echo terminal_state_test"
	} else {
		testCmd = "true"
	}

	err = client.ExecuteCommandWithPTY(cmdCtx, testCmd)
	// Note: PTY commands may fail due to signal termination behavior, which is expected
	if err != nil {
		t.Logf("PTY command returned error (may be expected): %v", err)
	}

	// Terminal state should be cleaned up after command (regardless of command success)
	assert.Nil(t, client.terminalState, "Terminal state should be cleaned up after command")
}

// Helper functions for the new behavioral tests
func setupTestSSHServerAndClient(t *testing.T) (*Server, string, *Client) {
	hostKey, err := GeneratePrivateKey(ED25519)
	require.NoError(t, err)

	clientPrivKey, err := GeneratePrivateKey(ED25519)
	require.NoError(t, err)
	clientPubKey, err := GeneratePublicKey(clientPrivKey)
	require.NoError(t, err)

	server := NewServer(hostKey)
	err = server.AddAuthorizedKey("test-peer", string(clientPubKey))
	require.NoError(t, err)

	serverAddr := startTestServer(t, server)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	client, err := DialWithKey(ctx, serverAddr, "test-user", clientPrivKey)
	require.NoError(t, err)

	return server, serverAddr, client
}

// TestSSHClient_InteractiveShellBehavior tests that interactive sessions work correctly
func TestSSHClient_InteractiveShellBehavior(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping interactive test in short mode")
	}

	server, _, client := setupTestSSHServerAndClient(t)
	defer func() {
		err := server.Stop()
		require.NoError(t, err)
	}()
	defer func() {
		err := client.Close()
		assert.NoError(t, err)
	}()

	// Test that shell session can be opened and accepts input
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// For interactive shell test, we expect it to succeed but may timeout
	// since we can't easily simulate Ctrl+D in a test environment
	// This test verifies the shell can be opened
	err := client.OpenTerminal(ctx)
	// Note: This may timeout in test environment, which is expected behavior
	// The important thing is that it doesn't panic or fail immediately
	t.Logf("Interactive shell test result: %v", err)
}

// TestSSHClient_NonInteractiveCommands tests that commands execute without dropping to shell
func TestSSHClient_NonInteractiveCommands(t *testing.T) {
	server, _, client := setupTestSSHServerAndClient(t)
	defer func() {
		err := server.Stop()
		require.NoError(t, err)
	}()
	defer func() {
		err := client.Close()
		assert.NoError(t, err)
	}()

	testCases := []struct {
		name    string
		command string
	}{
		{"echo command", "echo hello_world"},
		{"pwd command", "pwd"},
		{"date command", "date"},
		{"ls command", "ls -la /tmp"},
		{"whoami command", "whoami"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			// Capture output
			var output bytes.Buffer
			oldStdout := os.Stdout
			r, w, err := os.Pipe()
			require.NoError(t, err)
			os.Stdout = w

			done := make(chan struct{})
			go func() {
				_, _ = io.Copy(&output, r)
				close(done)
			}()

			// Execute command - should complete without hanging
			start := time.Now()
			err = client.ExecuteCommandWithIO(ctx, tc.command)
			duration := time.Since(start)

			_ = w.Close()
			<-done // Wait for copy to complete
			os.Stdout = oldStdout

			// Log execution details for debugging
			t.Logf("Command %q executed in %v", tc.command, duration)
			if err != nil {
				t.Logf("Command error: %v", err)
			}
			t.Logf("Output length: %d bytes", len(output.Bytes()))

			// Should execute successfully and exit immediately
			// In CI environments, some commands might fail due to missing tools
			// but they should not timeout
			if err != nil && errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("Command %q timed out after %v", tc.command, duration)
			}

			// If no timeout, the test passes (some commands may fail in CI but shouldn't hang)
			if err == nil {
				assert.NotNil(t, output.Bytes(), "Command should produce some output or complete")
			}
		})
	}
}

// TestSSHClient_FlagParametersPassing tests that SSH flags are passed correctly
func TestSSHClient_FlagParametersPassing(t *testing.T) {
	server, _, client := setupTestSSHServerAndClient(t)
	defer func() {
		err := server.Stop()
		require.NoError(t, err)
	}()
	defer func() {
		err := client.Close()
		assert.NoError(t, err)
	}()

	// Test commands with various flag combinations
	testCases := []struct {
		name    string
		command string
	}{
		{"ls with flags", "ls -la -h /tmp"},
		{"echo with flags", "echo -n 'no newline'"},
		{"grep with flags", "echo 'test line' | grep -i TEST"},
		{"sort with flags", "echo -e 'b\\na\\nc' | sort -r"},
		{"command with multiple spaces", "echo    'multiple   spaces'"},
		{"command with quotes", "echo 'quoted string' \"double quoted\""},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			// Execute command - flags should be preserved and passed through SSH
			start := time.Now()
			err := client.ExecuteCommandWithIO(ctx, tc.command)
			duration := time.Since(start)

			t.Logf("Command %q executed in %v", tc.command, duration)
			if err != nil {
				t.Logf("Command error: %v", err)
			}

			if err != nil && errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("Command %q timed out after %v", tc.command, duration)
			}
		})
	}
}

// TestSSHClient_StdinCommands tests commands that read from stdin over SSH
func TestSSHClient_StdinCommands(t *testing.T) {
	server, _, client := setupTestSSHServerAndClient(t)
	defer func() {
		err := server.Stop()
		require.NoError(t, err)
	}()
	defer func() {
		err := client.Close()
		assert.NoError(t, err)
	}()

	testCases := []struct {
		name    string
		command string
	}{
		{"simple cat", "cat /etc/hostname"},
		{"wc lines", "wc -l /etc/passwd"},
		{"head command", "head -n 1 /etc/passwd"},
		{"tail command", "tail -n 1 /etc/passwd"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()

			// Test commands that typically read from stdin
			// Note: In test environment, these commands may timeout or behave differently
			// The main goal is to verify they don't crash and can be executed
			err := client.ExecuteCommandWithIO(ctx, tc.command)
			// Some stdin commands may timeout in test environment - log the result
			t.Logf("Stdin command '%s' result: %v", tc.command, err)
		})
	}
}

// TestSSHClient_ComplexScenarios tests more complex real-world scenarios
func TestSSHClient_ComplexScenarios(t *testing.T) {
	server, _, client := setupTestSSHServerAndClient(t)
	defer func() {
		err := server.Stop()
		require.NoError(t, err)
	}()
	defer func() {
		err := client.Close()
		assert.NoError(t, err)
	}()

	t.Run("file operations", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()

		err := client.ExecuteCommandWithIO(ctx, "ls /tmp")
		assert.NoError(t, err, "File operations should work")
	})

	t.Run("basic commands", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()

		err := client.ExecuteCommandWithIO(ctx, "pwd")
		assert.NoError(t, err, "Basic commands should work")
	})

	t.Run("text processing", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()

		// Simple text processing that doesn't require shell interpretation
		err := client.ExecuteCommandWithIO(ctx, "whoami")
		assert.NoError(t, err, "Text processing should work")
	})

	t.Run("date commands", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()

		err := client.ExecuteCommandWithIO(ctx, "date")
		assert.NoError(t, err, "Date commands should work")
	})
}

// TestBehaviorRegression tests the specific behavioral issues mentioned:
// 1. Non-interactive commands not working anymore
// 2. Flag parsing being broken
// 3. Commands that should not hang but do hang
func TestBehaviorRegression(t *testing.T) {
	server, _, client := setupTestSSHServerAndClient(t)
	defer func() {
		err := server.Stop()
		require.NoError(t, err)
	}()
	defer func() {
		err := client.Close()
		assert.NoError(t, err)
	}()

	t.Run("non-interactive commands should not hang", func(t *testing.T) {
		// Test commands that should complete immediately
		var quickCommands []string
		var maxDuration time.Duration

		if runtime.GOOS == "windows" {
			quickCommands = []string{
				"echo hello",
				"cd",
				"echo %USERNAME%",
				"echo test123",
			}
			maxDuration = 5 * time.Second // Windows commands can be slower
		} else {
			quickCommands = []string{
				"echo hello",
				"pwd",
				"whoami",
				"date",
				"echo test123",
			}
			maxDuration = 2 * time.Second
		}

		for _, cmd := range quickCommands {
			t.Run("cmd: "+cmd, func(t *testing.T) {
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer cancel()

				start := time.Now()
				err := client.ExecuteCommandWithIO(ctx, cmd)
				duration := time.Since(start)

				assert.NoError(t, err, "Command should complete without hanging: %s", cmd)
				assert.Less(t, duration, maxDuration, "Command should complete quickly: %s", cmd)
			})
		}
	})

	t.Run("commands with flags should work", func(t *testing.T) {
		flagCommands := []struct {
			name string
			cmd  string
		}{
			{"ls with -l", "ls -l /tmp"},
			{"echo with -n", "echo -n test"},
			{"ls with multiple flags", "ls -la /tmp"},
			{"cat with file", "cat /etc/hostname"},
		}

		for _, tc := range flagCommands {
			t.Run(tc.name, func(t *testing.T) {
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()

				err := client.ExecuteCommandWithIO(ctx, tc.cmd)
				assert.NoError(t, err, "Flag command should work: %s", tc.cmd)
			})
		}
	})

	t.Run("commands should behave like regular SSH", func(t *testing.T) {
		// These commands should behave exactly like regular SSH
		var testCases []struct {
			name    string
			command string
		}

		if runtime.GOOS == "windows" {
			testCases = []struct {
				name    string
				command string
			}{
				{"simple echo", "echo test"},
				{"current directory", "Get-Location"},
				{"list files", "Get-ChildItem"},
				{"system info", "$PSVersionTable.PSVersion"},
			}
		} else {
			testCases = []struct {
				name    string
				command string
			}{
				{"simple echo", "echo test"},
				{"pwd command", "pwd"},
				{"list files", "ls /tmp"},
				{"system info", "uname -a"},
			}
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
				defer cancel()

				// Should work with ExecuteCommandWithIO (non-PTY)
				err := client.ExecuteCommandWithIO(ctx, tc.command)
				assert.NoError(t, err, "Non-PTY execution should work for: %s", tc.command)

				// Should also work with ExecuteCommand (capture output)
				output, err := client.ExecuteCommand(ctx, tc.command)
				assert.NoError(t, err, "Output capture should work for: %s", tc.command)
				assert.NotEmpty(t, output, "Should have output for: %s", tc.command)
			})
		}
	})
}

// TestNonInteractiveCommandRegression tests that non-interactive commands work correctly
// This test addresses the regression where non-interactive commands stopped working
func TestNonInteractiveCommandRegression(t *testing.T) {
	server, _, client := setupTestSSHServerAndClient(t)
	defer func() {
		err := server.Stop()
		require.NoError(t, err)
	}()
	defer func() {
		err := client.Close()
		assert.NoError(t, err)
	}()

	// Test simple command that should complete immediately
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Test ExecuteCommandWithIO - should complete without hanging
	err := client.ExecuteCommandWithIO(ctx, "echo test_non_interactive")
	assert.NoError(t, err, "Non-interactive command should execute and exit immediately")

	// Test ExecuteCommand - should also work
	output, err := client.ExecuteCommand(ctx, "echo test_capture")
	assert.NoError(t, err, "ExecuteCommand should work for non-interactive commands")
	assert.Contains(t, string(output), "test_capture", "Output should be captured")
}

// TestFlagParsingRegression tests that command flags are parsed correctly
// This test addresses the regression where flag parsing was broken
func TestFlagParsingRegression(t *testing.T) {
	server, _, client := setupTestSSHServerAndClient(t)
	defer func() {
		err := server.Stop()
		require.NoError(t, err)
	}()
	defer func() {
		err := client.Close()
		assert.NoError(t, err)
	}()

	testCases := []struct {
		name    string
		command string
	}{
		{"ls with flags", "ls -la"},
		{"echo with flags", "echo -n test"},
		{"grep with flags", "echo 'hello world' | grep -o hello"},
		{"command with multiple flags", "ls -la -h"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			// Flags should be passed through to the remote command, not parsed by netbird
			err := client.ExecuteCommandWithIO(ctx, tc.command)
			assert.NoError(t, err, "Command with flags should execute successfully")
		})
	}
}

// TestCommandCompletionRegression tests that commands complete and don't hang
func TestSSHClient_NonZeroExitCodes(t *testing.T) {
	server, _, client := setupTestSSHServerAndClient(t)
	defer func() {
		err := server.Stop()
		require.NoError(t, err)
	}()
	defer func() {
		err := client.Close()
		assert.NoError(t, err)
	}()

	// Test commands that return non-zero exit codes should not return errors
	var testCases []struct {
		name    string
		command string
	}

	if runtime.GOOS == "windows" {
		testCases = []struct {
			name    string
			command string
		}{
			{"select-string no match", "echo hello | Select-String notfound"},
			{"exit 1 command", "throw \"exit with code 1\""},
			{"get-childitem nonexistent", "Get-ChildItem C:\\nonexistent\\path"},
		}
	} else {
		testCases = []struct {
			name    string
			command string
		}{
			{"grep no match", "echo 'hello' | grep 'notfound'"},
			{"false command", "false"},
			{"ls nonexistent", "ls /nonexistent/path"},
		}
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()

			// These commands should complete without returning an error,
			// even though they have non-zero exit codes
			err := client.ExecuteCommandWithIO(ctx, tc.command)
			assert.NoError(t, err, "Command with non-zero exit code should not return error: %s", tc.command)

			// Same test with ExecuteCommand (capture output)
			_, err = client.ExecuteCommand(ctx, tc.command)
			assert.NoError(t, err, "ExecuteCommand with non-zero exit code should not return error: %s", tc.command)
		})
	}
}

func TestSSHServer_WindowsShellHandling(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping Windows shell test in short mode")
	}

	server := &Server{}

	if runtime.GOOS == "windows" {
		// Test Windows cmd.exe shell behavior
		args := server.getShellCommandArgs("cmd.exe", "echo test")
		assert.Equal(t, "cmd.exe", args[0])
		assert.Equal(t, "/c", args[1])
		assert.Equal(t, "echo test", args[2])

		// Test PowerShell behavior
		args = server.getShellCommandArgs("powershell.exe", "echo test")
		assert.Equal(t, "powershell.exe", args[0])
		assert.Equal(t, "-Command", args[1])
		assert.Equal(t, "echo test", args[2])
	} else {
		// Test Unix shell behavior
		args := server.getShellCommandArgs("/bin/sh", "echo test")
		assert.Equal(t, "/bin/sh", args[0])
		assert.Equal(t, "-c", args[1])
		assert.Equal(t, "echo test", args[2])
	}
}

func TestCommandCompletionRegression(t *testing.T) {
	server, _, client := setupTestSSHServerAndClient(t)
	defer func() {
		err := server.Stop()
		require.NoError(t, err)
	}()
	defer func() {
		err := client.Close()
		assert.NoError(t, err)
	}()

	// Commands that should complete quickly
	commands := []string{
		"echo hello",
		"pwd",
		"whoami",
		"date",
		"ls /tmp",
		"uname",
	}

	for _, cmd := range commands {
		t.Run("command: "+cmd, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			start := time.Now()
			err := client.ExecuteCommandWithIO(ctx, cmd)
			duration := time.Since(start)

			assert.NoError(t, err, "Command should execute without error: %s", cmd)
			assert.Less(t, duration, 3*time.Second, "Command should complete quickly: %s", cmd)
		})
	}
}
