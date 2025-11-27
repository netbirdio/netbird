package server

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/user"
	"testing"
	"time"

	"github.com/pkg/sftp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	cryptossh "golang.org/x/crypto/ssh"

	"github.com/netbirdio/netbird/client/ssh"
)

func TestSSHServer_SFTPSubsystem(t *testing.T) {
	// Skip SFTP test when running as root due to protocol issues in some environments
	if os.Geteuid() == 0 {
		t.Skip("Skipping SFTP test when running as root - may have protocol compatibility issues")
	}

	// Get current user for SSH connection
	currentUser, err := user.Current()
	require.NoError(t, err, "Should be able to get current user")

	// Generate host key for server
	hostKey, err := ssh.GeneratePrivateKey(ssh.ED25519)
	require.NoError(t, err)

	// Generate client key pair
	clientPrivKey, err := ssh.GeneratePrivateKey(ssh.ED25519)
	require.NoError(t, err)

	// Create server with SFTP enabled
	serverConfig := &Config{
		HostKeyPEM: hostKey,
		JWT:        nil,
	}
	server := New(serverConfig)
	server.SetAllowSFTP(true)
	server.SetAllowRootLogin(true)

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

	// (currentUser already obtained at function start)

	// Create SSH client connection
	clientConfig := &cryptossh.ClientConfig{
		User: currentUser.Username,
		Auth: []cryptossh.AuthMethod{
			cryptossh.PublicKeys(signer),
		},
		HostKeyCallback: cryptossh.FixedHostKey(hostPubKey),
		Timeout:         5 * time.Second,
	}

	conn, err := cryptossh.Dial("tcp", serverAddr, clientConfig)
	require.NoError(t, err, "SSH connection should succeed")
	defer func() {
		if err := conn.Close(); err != nil {
			t.Logf("connection close error: %v", err)
		}
	}()

	// Create SFTP client
	sftpClient, err := sftp.NewClient(conn)
	require.NoError(t, err, "SFTP client creation should succeed")
	defer func() {
		if err := sftpClient.Close(); err != nil {
			t.Logf("SFTP client close error: %v", err)
		}
	}()

	// Test basic SFTP operations
	workingDir, err := sftpClient.Getwd()
	assert.NoError(t, err, "Should be able to get working directory")
	assert.NotEmpty(t, workingDir, "Working directory should not be empty")

	// Test directory listing
	files, err := sftpClient.ReadDir(".")
	assert.NoError(t, err, "Should be able to list current directory")
	assert.NotNil(t, files, "File list should not be nil")
}

func TestSSHServer_SFTPDisabled(t *testing.T) {
	// Get current user for SSH connection
	currentUser, err := user.Current()
	require.NoError(t, err, "Should be able to get current user")

	// Generate host key for server
	hostKey, err := ssh.GeneratePrivateKey(ssh.ED25519)
	require.NoError(t, err)

	// Generate client key pair
	clientPrivKey, err := ssh.GeneratePrivateKey(ssh.ED25519)
	require.NoError(t, err)

	// Create server with SFTP disabled
	serverConfig := &Config{
		HostKeyPEM: hostKey,
		JWT:        nil,
	}
	server := New(serverConfig)
	server.SetAllowSFTP(false)

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

	// (currentUser already obtained at function start)

	// Create SSH client connection
	clientConfig := &cryptossh.ClientConfig{
		User: currentUser.Username,
		Auth: []cryptossh.AuthMethod{
			cryptossh.PublicKeys(signer),
		},
		HostKeyCallback: cryptossh.FixedHostKey(hostPubKey),
		Timeout:         5 * time.Second,
	}

	conn, err := cryptossh.Dial("tcp", serverAddr, clientConfig)
	require.NoError(t, err, "SSH connection should succeed")
	defer func() {
		if err := conn.Close(); err != nil {
			t.Logf("connection close error: %v", err)
		}
	}()

	// Try to create SFTP client - should fail when SFTP is disabled
	_, err = sftp.NewClient(conn)
	assert.Error(t, err, "SFTP client creation should fail when SFTP is disabled")
}
