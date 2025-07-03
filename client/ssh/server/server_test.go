package server

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"os/user"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/gliderlabs/ssh"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	cryptossh "golang.org/x/crypto/ssh"

	nbssh "github.com/netbirdio/netbird/client/ssh"
)

func TestServer_AddAuthorizedKey(t *testing.T) {
	key, err := nbssh.GeneratePrivateKey(nbssh.ED25519)
	require.NoError(t, err)
	server := New(key)

	keys := map[string][]byte{}
	for i := 0; i < 10; i++ {
		peer := fmt.Sprintf("%s-%d", "remotePeer", i)
		remotePrivKey, err := nbssh.GeneratePrivateKey(nbssh.ED25519)
		require.NoError(t, err)
		remotePubKey, err := nbssh.GeneratePublicKey(remotePrivKey)
		require.NoError(t, err)

		err = server.AddAuthorizedKey(peer, string(remotePubKey))
		require.NoError(t, err)
		keys[peer] = remotePubKey
	}

	for peer, remotePubKey := range keys {
		k, ok := server.authorizedKeys[peer]
		assert.True(t, ok, "expecting remotePeer key to be found in authorizedKeys")
		assert.Equal(t, string(remotePubKey), strings.TrimSpace(string(cryptossh.MarshalAuthorizedKey(k))))
	}
}

func TestServer_RemoveAuthorizedKey(t *testing.T) {
	key, err := nbssh.GeneratePrivateKey(nbssh.ED25519)
	require.NoError(t, err)
	server := New(key)

	remotePrivKey, err := nbssh.GeneratePrivateKey(nbssh.ED25519)
	require.NoError(t, err)
	remotePubKey, err := nbssh.GeneratePublicKey(remotePrivKey)
	require.NoError(t, err)

	err = server.AddAuthorizedKey("remotePeer", string(remotePubKey))
	require.NoError(t, err)

	server.RemoveAuthorizedKey("remotePeer")

	_, ok := server.authorizedKeys["remotePeer"]
	assert.False(t, ok, "expecting remotePeer's SSH key to be removed")
}

func TestServer_PubKeyHandler(t *testing.T) {
	key, err := nbssh.GeneratePrivateKey(nbssh.ED25519)
	require.NoError(t, err)
	server := New(key)

	var keys []ssh.PublicKey
	for i := 0; i < 10; i++ {
		peer := fmt.Sprintf("%s-%d", "remotePeer", i)
		remotePrivKey, err := nbssh.GeneratePrivateKey(nbssh.ED25519)
		require.NoError(t, err)
		remotePubKey, err := nbssh.GeneratePublicKey(remotePrivKey)
		require.NoError(t, err)

		remoteParsedPubKey, _, _, _, err := ssh.ParseAuthorizedKey(remotePubKey)
		require.NoError(t, err)

		err = server.AddAuthorizedKey(peer, string(remotePubKey))
		require.NoError(t, err)
		keys = append(keys, remoteParsedPubKey)
	}

	for _, key := range keys {
		accepted := server.publicKeyHandler(nil, key)
		assert.True(t, accepted, "SSH key should be accepted")
	}
}

func TestServer_StartStop(t *testing.T) {
	key, err := nbssh.GeneratePrivateKey(nbssh.ED25519)
	require.NoError(t, err)

	server := New(key)

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
	clientPubKey, err := nbssh.GeneratePublicKey(clientPrivKey)
	require.NoError(t, err)

	// Create server with random port
	server := New(hostKey)

	// Add client's public key as authorized
	err = server.AddAuthorizedKey("test-peer", string(clientPubKey))
	require.NoError(t, err)

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

		started <- actualAddr
		addrPort, _ := netip.ParseAddrPort(actualAddr)
		errChan <- server.Start(context.Background(), addrPort)
	}()

	select {
	case actualAddr := <-started:
		serverAddr = actualAddr
	case err := <-errChan:
		t.Fatalf("Server failed to start: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("Server start timeout")
	}

	// Server is ready when we get the started signal

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
	clientPubKey, err := nbssh.GeneratePublicKey(clientPrivKey)
	require.NoError(t, err)

	// Create server
	server := New(hostKey)
	err = server.AddAuthorizedKey("test-peer", string(clientPubKey))
	require.NoError(t, err)

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

		started <- actualAddr
		addrPort, _ := netip.ParseAddrPort(actualAddr)
		errChan <- server.Start(context.Background(), addrPort)
	}()

	select {
	case actualAddr := <-started:
		serverAddr = actualAddr
	case err := <-errChan:
		t.Fatalf("Server failed to start: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("Server start timeout")
	}

	// Server is ready when we get the started signal

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

	// Generate authorized key
	authorizedPrivKey, err := nbssh.GeneratePrivateKey(nbssh.ED25519)
	require.NoError(t, err)
	authorizedPubKey, err := nbssh.GeneratePublicKey(authorizedPrivKey)
	require.NoError(t, err)

	// Generate unauthorized key (different from authorized)
	unauthorizedPrivKey, err := nbssh.GeneratePrivateKey(nbssh.ED25519)
	require.NoError(t, err)

	// Create server with only one authorized key
	server := New(hostKey)
	err = server.AddAuthorizedKey("authorized-peer", string(authorizedPubKey))
	require.NoError(t, err)

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

		started <- actualAddr
		addrPort, _ := netip.ParseAddrPort(actualAddr)
		errChan <- server.Start(context.Background(), addrPort)
	}()

	select {
	case actualAddr := <-started:
		serverAddr = actualAddr
	case err := <-errChan:
		t.Fatalf("Server failed to start: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("Server start timeout")
	}

	// Server is ready when we get the started signal

	defer func() {
		err := server.Stop()
		require.NoError(t, err)
	}()

	// Parse unauthorized private key
	unauthorizedSigner, err := cryptossh.ParsePrivateKey(unauthorizedPrivKey)
	require.NoError(t, err)

	// Parse server host key
	hostPrivParsed, err := cryptossh.ParsePrivateKey(hostKey)
	require.NoError(t, err)
	hostPubKey := hostPrivParsed.PublicKey()

	// Get current user for SSH connection
	currentUser, err := user.Current()
	require.NoError(t, err, "Should be able to get current user for test")

	// Try to connect with unauthorized key
	config := &cryptossh.ClientConfig{
		User: currentUser.Username,
		Auth: []cryptossh.AuthMethod{
			cryptossh.PublicKeys(unauthorizedSigner),
		},
		HostKeyCallback: cryptossh.FixedHostKey(hostPubKey),
		Timeout:         3 * time.Second,
	}

	// This should succeed in no-auth mode
	conn, err := cryptossh.Dial("tcp", serverAddr, config)
	assert.NoError(t, err, "Connection should succeed in no-auth mode")
	if conn != nil {
		assert.NoError(t, conn.Close())
	}
}

func TestSSHServerStartStopCycle(t *testing.T) {
	hostKey, err := nbssh.GeneratePrivateKey(nbssh.ED25519)
	require.NoError(t, err)

	server := New(hostKey)
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

			started <- actualAddr
			addrPort, _ := netip.ParseAddrPort(actualAddr)
			errChan <- server.Start(context.Background(), addrPort)
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
		assert.Equal(t, "-l", args[1])
		assert.Equal(t, "-c", args[2])
		assert.Equal(t, "echo test", args[3])
	}
}

func TestSSHServer_PortForwardingConfiguration(t *testing.T) {
	hostKey, err := nbssh.GeneratePrivateKey(nbssh.ED25519)
	require.NoError(t, err)

	server1 := New(hostKey)
	server2 := New(hostKey)

	assert.False(t, server1.allowLocalPortForwarding, "Local port forwarding should be disabled by default for security")
	assert.False(t, server1.allowRemotePortForwarding, "Remote port forwarding should be disabled by default for security")

	server2.SetAllowLocalPortForwarding(true)
	server2.SetAllowRemotePortForwarding(true)

	assert.True(t, server2.allowLocalPortForwarding, "Local port forwarding should be enabled when explicitly set")
	assert.True(t, server2.allowRemotePortForwarding, "Remote port forwarding should be enabled when explicitly set")
}
