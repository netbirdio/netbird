package server

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"os/user"
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	cryptossh "golang.org/x/crypto/ssh"

	nbssh "github.com/netbirdio/netbird/client/ssh"
)

func TestServer_StartStop(t *testing.T) {
	key, err := nbssh.GeneratePrivateKey(nbssh.ED25519)
	require.NoError(t, err)

	serverConfig := &Config{
		HostKeyPEM: key,
		JWT:        nil,
	}
	server := New(serverConfig)

	err = server.Stop()
	assert.NoError(t, err)
}

func TestSSHServerIntegration(t *testing.T) {
	// Generate host key for server
	hostKey, err := nbssh.GeneratePrivateKey(nbssh.ED25519)
	require.NoError(t, err)

	// Generate client key pair
	clientPrivKey, err := nbssh.GeneratePrivateKey(nbssh.ED25519)
	require.NoError(t, err)

	// Create server with random port
	serverConfig := &Config{
		HostKeyPEM: hostKey,
		JWT:        nil,
	}
	server := New(serverConfig)

	// Start server in background
	serverAddr := "127.0.0.1:0"
	started := make(chan string, 1)
	errChan := make(chan error, 1)

	go func() {
		// Get a free port
		ln, err := net.Listen("tcp", serverAddr)
		if err != nil {
			errChan <- err
			return
		}
		actualAddr := ln.Addr().String()
		if err := ln.Close(); err != nil {
			errChan <- fmt.Errorf("close temp listener: %w", err)
			return
		}

		addrPort, _ := netip.ParseAddrPort(actualAddr)
		if err := server.Start(context.Background(), addrPort); err != nil {
			errChan <- err
			return
		}
		started <- actualAddr
	}()

	select {
	case actualAddr := <-started:
		serverAddr = actualAddr
	case err := <-errChan:
		t.Fatalf("Server failed to start: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("Server start timeout")
	}

	defer func() {
		err := server.Stop()
		require.NoError(t, err)
	}()

	// Parse client private key
	signer, err := cryptossh.ParsePrivateKey(clientPrivKey)
	require.NoError(t, err)

	// Parse server host key for verification
	hostPrivParsed, err := cryptossh.ParsePrivateKey(hostKey)
	require.NoError(t, err)
	hostPubKey := hostPrivParsed.PublicKey()

	// Get current user for SSH connection
	currentUser, err := user.Current()
	require.NoError(t, err, "Should be able to get current user for test")

	// Create SSH client config
	config := &cryptossh.ClientConfig{
		User: currentUser.Username,
		Auth: []cryptossh.AuthMethod{
			cryptossh.PublicKeys(signer),
		},
		HostKeyCallback: cryptossh.FixedHostKey(hostPubKey),
		Timeout:         3 * time.Second,
	}

	// Connect to SSH server
	client, err := cryptossh.Dial("tcp", serverAddr, config)
	require.NoError(t, err)
	defer func() {
		if err := client.Close(); err != nil {
			t.Logf("close client: %v", err)
		}
	}()

	// Test creating a session
	session, err := client.NewSession()
	require.NoError(t, err)
	defer func() {
		if err := session.Close(); err != nil {
			t.Logf("close session: %v", err)
		}
	}()

	// Note: Since we don't have a real shell environment in tests,
	// we can't test actual command execution, but we can verify
	// the connection and authentication work
	t.Log("SSH connection and authentication successful")
}

func TestSSHServerMultipleConnections(t *testing.T) {
	// Generate host key for server
	hostKey, err := nbssh.GeneratePrivateKey(nbssh.ED25519)
	require.NoError(t, err)

	// Generate client key pair
	clientPrivKey, err := nbssh.GeneratePrivateKey(nbssh.ED25519)
	require.NoError(t, err)

	// Create server
	serverConfig := &Config{
		HostKeyPEM: hostKey,
		JWT:        nil,
	}
	server := New(serverConfig)

	// Start server
	serverAddr := "127.0.0.1:0"
	started := make(chan string, 1)
	errChan := make(chan error, 1)

	go func() {
		ln, err := net.Listen("tcp", serverAddr)
		if err != nil {
			errChan <- err
			return
		}
		actualAddr := ln.Addr().String()
		if err := ln.Close(); err != nil {
			errChan <- fmt.Errorf("close temp listener: %w", err)
			return
		}

		addrPort, _ := netip.ParseAddrPort(actualAddr)
		if err := server.Start(context.Background(), addrPort); err != nil {
			errChan <- err
			return
		}
		started <- actualAddr
	}()

	select {
	case actualAddr := <-started:
		serverAddr = actualAddr
	case err := <-errChan:
		t.Fatalf("Server failed to start: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("Server start timeout")
	}

	defer func() {
		err := server.Stop()
		require.NoError(t, err)
	}()

	// Parse client private key
	signer, err := cryptossh.ParsePrivateKey(clientPrivKey)
	require.NoError(t, err)

	// Parse server host key
	hostPrivParsed, err := cryptossh.ParsePrivateKey(hostKey)
	require.NoError(t, err)
	hostPubKey := hostPrivParsed.PublicKey()

	// Get current user for SSH connection
	currentUser, err := user.Current()
	require.NoError(t, err, "Should be able to get current user for test")

	config := &cryptossh.ClientConfig{
		User: currentUser.Username,
		Auth: []cryptossh.AuthMethod{
			cryptossh.PublicKeys(signer),
		},
		HostKeyCallback: cryptossh.FixedHostKey(hostPubKey),
		Timeout:         3 * time.Second,
	}

	// Test multiple concurrent connections
	const numConnections = 5
	results := make(chan error, numConnections)

	for i := 0; i < numConnections; i++ {
		go func(id int) {
			client, err := cryptossh.Dial("tcp", serverAddr, config)
			if err != nil {
				results <- fmt.Errorf("connection %d failed: %w", id, err)
				return
			}
			defer func() {
				_ = client.Close() // Ignore error in test goroutine
			}()

			session, err := client.NewSession()
			if err != nil {
				results <- fmt.Errorf("session %d failed: %w", id, err)
				return
			}
			defer func() {
				_ = session.Close() // Ignore error in test goroutine
			}()

			results <- nil
		}(i)
	}

	// Wait for all connections to complete
	for i := 0; i < numConnections; i++ {
		select {
		case err := <-results:
			assert.NoError(t, err)
		case <-time.After(10 * time.Second):
			t.Fatalf("Connection %d timed out", i)
		}
	}
}

func TestSSHServerNoAuthMode(t *testing.T) {
	// Generate host key for server
	hostKey, err := nbssh.GeneratePrivateKey(nbssh.ED25519)
	require.NoError(t, err)

	// Create server
	serverConfig := &Config{
		HostKeyPEM: hostKey,
		JWT:        nil,
	}
	server := New(serverConfig)

	// Start server
	serverAddr := "127.0.0.1:0"
	started := make(chan string, 1)
	errChan := make(chan error, 1)

	go func() {
		ln, err := net.Listen("tcp", serverAddr)
		if err != nil {
			errChan <- err
			return
		}
		actualAddr := ln.Addr().String()
		if err := ln.Close(); err != nil {
			errChan <- fmt.Errorf("close temp listener: %w", err)
			return
		}

		addrPort, _ := netip.ParseAddrPort(actualAddr)
		if err := server.Start(context.Background(), addrPort); err != nil {
			errChan <- err
			return
		}
		started <- actualAddr
	}()

	select {
	case actualAddr := <-started:
		serverAddr = actualAddr
	case err := <-errChan:
		t.Fatalf("Server failed to start: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("Server start timeout")
	}

	defer func() {
		err := server.Stop()
		require.NoError(t, err)
	}()

	// Generate a client private key for SSH protocol (server doesn't check it)
	clientPrivKey, err := nbssh.GeneratePrivateKey(nbssh.ED25519)
	require.NoError(t, err)
	clientSigner, err := cryptossh.ParsePrivateKey(clientPrivKey)
	require.NoError(t, err)

	// Parse server host key
	hostPrivParsed, err := cryptossh.ParsePrivateKey(hostKey)
	require.NoError(t, err)
	hostPubKey := hostPrivParsed.PublicKey()

	// Get current user for SSH connection
	currentUser, err := user.Current()
	require.NoError(t, err, "Should be able to get current user for test")

	// Try to connect with client key
	config := &cryptossh.ClientConfig{
		User: currentUser.Username,
		Auth: []cryptossh.AuthMethod{
			cryptossh.PublicKeys(clientSigner),
		},
		HostKeyCallback: cryptossh.FixedHostKey(hostPubKey),
		Timeout:         3 * time.Second,
	}

	// This should succeed in no-auth mode (server doesn't verify keys)
	conn, err := cryptossh.Dial("tcp", serverAddr, config)
	assert.NoError(t, err, "Connection should succeed in no-auth mode")
	if conn != nil {
		assert.NoError(t, conn.Close())
	}
}

func TestSSHServerStartStopCycle(t *testing.T) {
	hostKey, err := nbssh.GeneratePrivateKey(nbssh.ED25519)
	require.NoError(t, err)

	serverConfig := &Config{
		HostKeyPEM: hostKey,
		JWT:        nil,
	}
	server := New(serverConfig)
	serverAddr := "127.0.0.1:0"

	// Test multiple start/stop cycles
	for i := 0; i < 3; i++ {
		t.Logf("Start/stop cycle %d", i+1)

		started := make(chan string, 1)
		errChan := make(chan error, 1)

		go func() {
			ln, err := net.Listen("tcp", serverAddr)
			if err != nil {
				errChan <- err
				return
			}
			actualAddr := ln.Addr().String()
			if err := ln.Close(); err != nil {
				errChan <- fmt.Errorf("close temp listener: %w", err)
				return
			}

			addrPort, _ := netip.ParseAddrPort(actualAddr)
			if err := server.Start(context.Background(), addrPort); err != nil {
				errChan <- err
				return
			}
			started <- actualAddr
		}()

		select {
		case <-started:
		case err := <-errChan:
			t.Fatalf("Cycle %d: Server failed to start: %v", i+1, err)
		case <-time.After(5 * time.Second):
			t.Fatalf("Cycle %d: Server start timeout", i+1)
		}

		err = server.Stop()
		require.NoError(t, err, "Cycle %d: Stop should succeed", i+1)
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
		assert.Equal(t, "-Command", args[1])
		assert.Equal(t, "echo test", args[2])

		// Test PowerShell behavior
		args = server.getShellCommandArgs("powershell.exe", "echo test")
		assert.Equal(t, "powershell.exe", args[0])
		assert.Equal(t, "-Command", args[1])
		assert.Equal(t, "echo test", args[2])
	} else {
		args := server.getShellCommandArgs("/bin/sh", "echo test")
		assert.Equal(t, "/bin/sh", args[0])
		assert.Equal(t, "-c", args[1])
		assert.Equal(t, "echo test", args[2])

		args = server.getShellCommandArgs("/bin/sh", "")
		assert.Equal(t, "/bin/sh", args[0])
		assert.Len(t, args, 1)
	}
}

func TestSSHServer_PortForwardingConfiguration(t *testing.T) {
	hostKey, err := nbssh.GeneratePrivateKey(nbssh.ED25519)
	require.NoError(t, err)

	serverConfig1 := &Config{
		HostKeyPEM: hostKey,
		JWT:        nil,
	}
	server1 := New(serverConfig1)

	serverConfig2 := &Config{
		HostKeyPEM: hostKey,
		JWT:        nil,
	}
	server2 := New(serverConfig2)

	assert.False(t, server1.allowLocalPortForwarding, "Local port forwarding should be disabled by default for security")
	assert.False(t, server1.allowRemotePortForwarding, "Remote port forwarding should be disabled by default for security")

	server2.SetAllowLocalPortForwarding(true)
	server2.SetAllowRemotePortForwarding(true)

	assert.True(t, server2.allowLocalPortForwarding, "Local port forwarding should be enabled when explicitly set")
	assert.True(t, server2.allowRemotePortForwarding, "Remote port forwarding should be enabled when explicitly set")
}
