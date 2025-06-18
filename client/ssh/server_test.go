package ssh

import (
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

func TestServer_AddAuthorizedKey(t *testing.T) {
	key, err := GeneratePrivateKey(ED25519)
	if err != nil {
		t.Fatal(err)
	}
	server := NewServer(key)

	// add multiple keys
	keys := map[string][]byte{}
	for i := 0; i < 10; i++ {
		peer := fmt.Sprintf("%s-%d", "remotePeer", i)
		remotePrivKey, err := GeneratePrivateKey(ED25519)
		if err != nil {
			t.Fatal(err)
		}
		remotePubKey, err := GeneratePublicKey(remotePrivKey)
		if err != nil {
			t.Fatal(err)
		}

		err = server.AddAuthorizedKey(peer, string(remotePubKey))
		if err != nil {
			t.Error(err)
		}
		keys[peer] = remotePubKey
	}

	// make sure that all keys have been added
	for peer, remotePubKey := range keys {
		k, ok := server.authorizedKeys[peer]
		assert.True(t, ok, "expecting remotePeer key to be found in authorizedKeys")

		assert.Equal(t, string(remotePubKey), strings.TrimSpace(string(ssh.MarshalAuthorizedKey(k))))
	}

}

func TestServer_RemoveAuthorizedKey(t *testing.T) {
	key, err := GeneratePrivateKey(ED25519)
	if err != nil {
		t.Fatal(err)
	}
	server := NewServer(key)

	remotePrivKey, err := GeneratePrivateKey(ED25519)
	if err != nil {
		t.Fatal(err)
	}
	remotePubKey, err := GeneratePublicKey(remotePrivKey)
	if err != nil {
		t.Fatal(err)
	}

	err = server.AddAuthorizedKey("remotePeer", string(remotePubKey))
	if err != nil {
		t.Error(err)
	}

	server.RemoveAuthorizedKey("remotePeer")

	_, ok := server.authorizedKeys["remotePeer"]
	assert.False(t, ok, "expecting remotePeer's SSH key to be removed")
}

func TestServer_PubKeyHandler(t *testing.T) {
	key, err := GeneratePrivateKey(ED25519)
	if err != nil {
		t.Fatal(err)
	}
	server := NewServer(key)

	var keys []ssh.PublicKey
	for i := 0; i < 10; i++ {
		peer := fmt.Sprintf("%s-%d", "remotePeer", i)
		remotePrivKey, err := GeneratePrivateKey(ED25519)
		if err != nil {
			t.Fatal(err)
		}
		remotePubKey, err := GeneratePublicKey(remotePrivKey)
		if err != nil {
			t.Fatal(err)
		}

		remoteParsedPubKey, _, _, _, err := ssh.ParseAuthorizedKey(remotePubKey)
		if err != nil {
			t.Fatal(err)
		}

		err = server.AddAuthorizedKey(peer, string(remotePubKey))
		if err != nil {
			t.Error(err)
		}
		keys = append(keys, remoteParsedPubKey)
	}

	for _, key := range keys {
		accepted := server.publicKeyHandler(nil, key)

		assert.True(t, accepted, "SSH key should be accepted")
	}
}

func TestServer_StartStop(t *testing.T) {
	key, err := GeneratePrivateKey(ED25519)
	if err != nil {
		t.Fatal(err)
	}

	server := NewServer(key)

	// Test stopping when not started
	err = server.Stop()
	assert.NoError(t, err)
}

func TestSSHServerIntegration(t *testing.T) {
	// Generate host key for server
	hostKey, err := GeneratePrivateKey(ED25519)
	require.NoError(t, err)

	// Generate client key pair
	clientPrivKey, err := GeneratePrivateKey(ED25519)
	require.NoError(t, err)
	clientPubKey, err := GeneratePublicKey(clientPrivKey)
	require.NoError(t, err)

	// Create server with random port
	server := NewServer(hostKey)

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
		errChan <- server.Start(actualAddr)
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
	signer, err := ssh.ParsePrivateKey(clientPrivKey)
	require.NoError(t, err)

	// Parse server host key for verification
	hostPrivParsed, err := ssh.ParsePrivateKey(hostKey)
	require.NoError(t, err)
	hostPubKey := hostPrivParsed.PublicKey()

	// Create SSH client config
	config := &ssh.ClientConfig{
		User: "test-user",
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(signer),
		},
		HostKeyCallback: ssh.FixedHostKey(hostPubKey),
		Timeout:         3 * time.Second,
	}

	// Connect to SSH server
	client, err := ssh.Dial("tcp", serverAddr, config)
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
	hostKey, err := GeneratePrivateKey(ED25519)
	require.NoError(t, err)

	// Generate client key pair
	clientPrivKey, err := GeneratePrivateKey(ED25519)
	require.NoError(t, err)
	clientPubKey, err := GeneratePublicKey(clientPrivKey)
	require.NoError(t, err)

	// Create server
	server := NewServer(hostKey)
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
		errChan <- server.Start(actualAddr)
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
	signer, err := ssh.ParsePrivateKey(clientPrivKey)
	require.NoError(t, err)

	// Parse server host key
	hostPrivParsed, err := ssh.ParsePrivateKey(hostKey)
	require.NoError(t, err)
	hostPubKey := hostPrivParsed.PublicKey()

	config := &ssh.ClientConfig{
		User: "test-user",
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(signer),
		},
		HostKeyCallback: ssh.FixedHostKey(hostPubKey),
		Timeout:         3 * time.Second,
	}

	// Test multiple concurrent connections
	const numConnections = 5
	results := make(chan error, numConnections)

	for i := 0; i < numConnections; i++ {
		go func(id int) {
			client, err := ssh.Dial("tcp", serverAddr, config)
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

func TestSSHServerAuthenticationFailure(t *testing.T) {
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
		errChan <- server.Start(actualAddr)
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
	unauthorizedSigner, err := ssh.ParsePrivateKey(unauthorizedPrivKey)
	require.NoError(t, err)

	// Parse server host key
	hostPrivParsed, err := ssh.ParsePrivateKey(hostKey)
	require.NoError(t, err)
	hostPubKey := hostPrivParsed.PublicKey()

	// Try to connect with unauthorized key
	config := &ssh.ClientConfig{
		User: "test-user",
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(unauthorizedSigner),
		},
		HostKeyCallback: ssh.FixedHostKey(hostPubKey),
		Timeout:         3 * time.Second,
	}

	// This should fail
	_, err = ssh.Dial("tcp", serverAddr, config)
	assert.Error(t, err, "Connection should fail with unauthorized key")
	assert.Contains(t, err.Error(), "unable to authenticate")
}

func TestSSHServerStartStopCycle(t *testing.T) {
	hostKey, err := GeneratePrivateKey(ED25519)
	require.NoError(t, err)

	server := NewServer(hostKey)
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
			errChan <- server.Start(actualAddr)
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
