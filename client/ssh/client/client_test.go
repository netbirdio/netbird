package client

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/user"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	cryptossh "golang.org/x/crypto/ssh"

	"github.com/netbirdio/netbird/client/ssh"
	sshserver "github.com/netbirdio/netbird/client/ssh/server"
)

func TestSSHClient_DialWithKey(t *testing.T) {
	// Generate host key for server
	hostKey, err := ssh.GeneratePrivateKey(ssh.ED25519)
	require.NoError(t, err)

	// Generate client key pair
	clientPrivKey, err := ssh.GeneratePrivateKey(ssh.ED25519)
	require.NoError(t, err)
	clientPubKey, err := ssh.GeneratePublicKey(clientPrivKey)
	require.NoError(t, err)

	// Create and start server
	server := sshserver.New(hostKey)
	server.SetAllowRootLogin(true) // Allow root/admin login for tests

	err = server.AddAuthorizedKey("test-peer", string(clientPubKey))
	require.NoError(t, err)

	serverAddr := sshserver.StartTestServer(t, server)
	defer func() {
		err := server.Stop()
		require.NoError(t, err)
	}()

	// Test Dial
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	currentUser := getCurrentUsername()
	client, err := DialInsecure(ctx, serverAddr, currentUser)
	require.NoError(t, err)
	defer func() {
		err := client.Close()
		assert.NoError(t, err)
	}()

	// Verify client is connected
	assert.NotNil(t, client.client)
}

func TestSSHClient_CommandExecution(t *testing.T) {
	server, _, client := setupTestSSHServerAndClient(t)
	defer func() {
		err := server.Stop()
		require.NoError(t, err)
	}()
	defer func() {
		err := client.Close()
		assert.NoError(t, err)
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	t.Run("ExecuteCommand captures output", func(t *testing.T) {
		output, err := client.ExecuteCommand(ctx, "echo hello")
		assert.NoError(t, err)
		assert.Contains(t, string(output), "hello")
	})

	t.Run("ExecuteCommandWithIO streams output", func(t *testing.T) {
		err := client.ExecuteCommandWithIO(ctx, "echo world")
		assert.NoError(t, err)
	})

	t.Run("commands with flags work", func(t *testing.T) {
		output, err := client.ExecuteCommand(ctx, "echo -n test_flag")
		assert.NoError(t, err)
		assert.Equal(t, "test_flag", strings.TrimSpace(string(output)))
	})

	t.Run("non-zero exit codes don't return errors", func(t *testing.T) {
		var testCmd string
		if runtime.GOOS == "windows" {
			testCmd = "echo hello | Select-String notfound"
		} else {
			testCmd = "echo 'hello' | grep 'notfound'"
		}
		_, err := client.ExecuteCommand(ctx, testCmd)
		assert.NoError(t, err)
	})
}

func TestSSHClient_ConnectionHandling(t *testing.T) {
	server, serverAddr, _ := setupTestSSHServerAndClient(t)
	defer func() {
		err := server.Stop()
		require.NoError(t, err)
	}()

	// Generate client key for multiple connections
	clientPrivKey, err := ssh.GeneratePrivateKey(ssh.ED25519)
	require.NoError(t, err)
	clientPubKey, err := ssh.GeneratePublicKey(clientPrivKey)
	require.NoError(t, err)
	err = server.AddAuthorizedKey("multi-peer", string(clientPubKey))
	require.NoError(t, err)

	const numClients = 3
	clients := make([]*Client, numClients)

	for i := 0; i < numClients; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		currentUser := getCurrentUsername()
		client, err := DialInsecure(ctx, serverAddr, fmt.Sprintf("%s-%d", currentUser, i))
		cancel()
		require.NoError(t, err, "Client %d should connect successfully", i)
		clients[i] = client
	}

	for i, client := range clients {
		err := client.Close()
		assert.NoError(t, err, "Client %d should close without error", i)
	}
}

func TestSSHClient_ContextCancellation(t *testing.T) {
	server, serverAddr, _ := setupTestSSHServerAndClient(t)
	defer func() {
		err := server.Stop()
		require.NoError(t, err)
	}()

	clientPrivKey, err := ssh.GeneratePrivateKey(ssh.ED25519)
	require.NoError(t, err)
	clientPubKey, err := ssh.GeneratePublicKey(clientPrivKey)
	require.NoError(t, err)
	err = server.AddAuthorizedKey("cancel-peer", string(clientPubKey))
	require.NoError(t, err)

	t.Run("connection with short timeout", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 1*time.Millisecond)
		defer cancel()

		currentUser := getCurrentUsername()
		_, err = DialInsecure(ctx, serverAddr, currentUser)
		if err != nil {
			assert.Contains(t, err.Error(), "context")
		}
	})

	t.Run("command execution cancellation", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		currentUser := getCurrentUsername()
		client, err := DialInsecure(ctx, serverAddr, currentUser)
		require.NoError(t, err)
		defer func() {
			if err := client.Close(); err != nil {
				t.Logf("client close error: %v", err)
			}
		}()

		cmdCtx, cmdCancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		defer cmdCancel()

		err = client.ExecuteCommandWithPTY(cmdCtx, "sleep 10")
		if err != nil {
			var exitMissingErr *cryptossh.ExitMissingError
			isValidCancellation := errors.Is(err, context.DeadlineExceeded) ||
				errors.Is(err, context.Canceled) ||
				errors.As(err, &exitMissingErr)
			assert.True(t, isValidCancellation, "Should handle command cancellation properly")
		}
	})
}

func TestSSHClient_NoAuthMode(t *testing.T) {
	hostKey, err := ssh.GeneratePrivateKey(ssh.ED25519)
	require.NoError(t, err)

	server := sshserver.New(hostKey)
	server.SetAllowRootLogin(true) // Allow root/admin login for tests

	serverAddr := sshserver.StartTestServer(t, server)
	defer func() {
		err := server.Stop()
		require.NoError(t, err)
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	currentUser := getCurrentUsername()

	t.Run("any key succeeds in no-auth mode", func(t *testing.T) {
		client, err := DialInsecure(ctx, serverAddr, currentUser)
		assert.NoError(t, err)
		if client != nil {
			require.NoError(t, client.Close(), "Client should close without error")
		}
	})
}

func TestSSHClient_TerminalState(t *testing.T) {
	server, _, client := setupTestSSHServerAndClient(t)
	defer func() {
		err := server.Stop()
		require.NoError(t, err)
	}()
	defer func() {
		err := client.Close()
		assert.NoError(t, err)
	}()

	assert.Nil(t, client.terminalState)
	assert.Equal(t, 0, client.terminalFd)

	client.restoreTerminal()
	assert.Nil(t, client.terminalState)

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	err := client.OpenTerminal(ctx)
	// In test environment without a real terminal, this may complete quickly or timeout
	// Both behaviors are acceptable for testing terminal state management
	if err != nil {
		if runtime.GOOS == "windows" {
			assert.True(t,
				strings.Contains(err.Error(), "context deadline exceeded") ||
					strings.Contains(err.Error(), "console"),
				"Should timeout or have console error on Windows")
		} else {
			// On Unix systems in test environment, we may get various errors
			// including timeouts or terminal-related errors
			assert.True(t,
				strings.Contains(err.Error(), "context deadline exceeded") ||
					strings.Contains(err.Error(), "terminal") ||
					strings.Contains(err.Error(), "pty"),
				"Expected timeout or terminal-related error, got: %v", err)
		}
	}
}

func setupTestSSHServerAndClient(t *testing.T) (*sshserver.Server, string, *Client) {
	hostKey, err := ssh.GeneratePrivateKey(ssh.ED25519)
	require.NoError(t, err)

	clientPrivKey, err := ssh.GeneratePrivateKey(ssh.ED25519)
	require.NoError(t, err)
	clientPubKey, err := ssh.GeneratePublicKey(clientPrivKey)
	require.NoError(t, err)

	server := sshserver.New(hostKey)
	server.SetAllowRootLogin(true) // Allow root/admin login for tests

	err = server.AddAuthorizedKey("test-peer", string(clientPubKey))
	require.NoError(t, err)

	serverAddr := sshserver.StartTestServer(t, server)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	currentUser := getCurrentUsername()
	client, err := DialInsecure(ctx, serverAddr, currentUser)
	require.NoError(t, err)

	return server, serverAddr, client
}

func TestSSHClient_PortForwarding(t *testing.T) {
	server, _, client := setupTestSSHServerAndClient(t)
	defer func() {
		err := server.Stop()
		require.NoError(t, err)
	}()
	defer func() {
		err := client.Close()
		assert.NoError(t, err)
	}()

	t.Run("local forwarding times out gracefully", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		defer cancel()

		err := client.LocalPortForward(ctx, "127.0.0.1:0", "127.0.0.1:8080")
		assert.Error(t, err)
		assert.True(t,
			errors.Is(err, context.DeadlineExceeded) ||
				errors.Is(err, context.Canceled) ||
				strings.Contains(err.Error(), "connection"),
			"Expected context or connection error")
	})

	t.Run("remote forwarding denied", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
		defer cancel()

		err := client.RemotePortForward(ctx, "127.0.0.1:0", "127.0.0.1:8080")
		assert.Error(t, err)
		assert.True(t,
			strings.Contains(err.Error(), "denied") ||
				strings.Contains(err.Error(), "disabled"),
			"Should be denied by default")
	})

	t.Run("invalid addresses fail", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
		defer cancel()

		err := client.LocalPortForward(ctx, "invalid:address", "127.0.0.1:8080")
		assert.Error(t, err)

		err = client.LocalPortForward(ctx, "127.0.0.1:0", "invalid:address")
		assert.Error(t, err)
	})
}

func TestSSHClient_PortForwardingDataTransfer(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping data transfer test in short mode")
	}

	hostKey, err := ssh.GeneratePrivateKey(ssh.ED25519)
	require.NoError(t, err)

	clientPrivKey, err := ssh.GeneratePrivateKey(ssh.ED25519)
	require.NoError(t, err)
	clientPubKey, err := ssh.GeneratePublicKey(clientPrivKey)
	require.NoError(t, err)

	server := sshserver.New(hostKey)
	server.SetAllowLocalPortForwarding(true)
	server.SetAllowRootLogin(true) // Allow root/admin login for tests

	err = server.AddAuthorizedKey("test-peer", string(clientPubKey))
	require.NoError(t, err)

	serverAddr := sshserver.StartTestServer(t, server)
	defer func() {
		err := server.Stop()
		require.NoError(t, err)
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	currentUser := getCurrentUsername()
	client, err := DialInsecure(ctx, serverAddr, currentUser)
	require.NoError(t, err)
	defer func() {
		if err := client.Close(); err != nil {
			t.Logf("client close error: %v", err)
		}
	}()

	testServer, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() {
		if err := testServer.Close(); err != nil {
			t.Logf("test server close error: %v", err)
		}
	}()

	testServerAddr := testServer.Addr().String()
	expectedResponse := "Hello, World!"

	go func() {
		for {
			conn, err := testServer.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer func() {
					if err := c.Close(); err != nil {
						t.Logf("connection close error: %v", err)
					}
				}()
				buf := make([]byte, 1024)
				if _, err := c.Read(buf); err != nil {
					t.Logf("connection read error: %v", err)
					return
				}
				if _, err := c.Write([]byte(expectedResponse)); err != nil {
					t.Logf("connection write error: %v", err)
				}
			}(conn)
		}
	}()

	localListener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	localAddr := localListener.Addr().String()
	if err := localListener.Close(); err != nil {
		t.Logf("local listener close error: %v", err)
	}

	ctx, cancel = context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	go func() {
		err := client.LocalPortForward(ctx, localAddr, testServerAddr)
		if err != nil && !errors.Is(err, context.Canceled) {
			t.Logf("Port forward error: %v", err)
		}
	}()

	time.Sleep(100 * time.Millisecond)

	conn, err := net.DialTimeout("tcp", localAddr, 2*time.Second)
	require.NoError(t, err)
	defer func() {
		if err := conn.Close(); err != nil {
			t.Logf("connection close error: %v", err)
		}
	}()

	_, err = conn.Write([]byte("test"))
	require.NoError(t, err)

	if err := conn.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Logf("set read deadline error: %v", err)
	}
	response := make([]byte, len(expectedResponse))
	n, err := io.ReadFull(conn, response)
	require.NoError(t, err)
	assert.Equal(t, len(expectedResponse), n)
	assert.Equal(t, expectedResponse, string(response))
}

// getCurrentUsername returns the current username for SSH connections
func getCurrentUsername() string {
	if runtime.GOOS == "windows" {
		if currentUser, err := user.Current(); err == nil {
			// On Windows, return the full domain\username for proper authentication
			return currentUser.Username
		}
	}

	if username := os.Getenv("USER"); username != "" {
		return username
	}

	if currentUser, err := user.Current(); err == nil {
		return currentUser.Username
	}

	return "test-user"
}
