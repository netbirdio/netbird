package server

import (
	"context"
	"fmt"
	"net/netip"
	"strings"
	"testing"
	"time"

	cryptossh "golang.org/x/crypto/ssh"
)

// waitForServerReady waits for the SSH server to be ready to accept SSH connections.
// It attempts a real SSH handshake (which will fail auth) to ensure the server is fully operational.
func waitForServerReady(addr string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	var lastErr error

	// SSH client config that will fail authentication but succeed in handshake
	config := &cryptossh.ClientConfig{
		User:            "probe",
		Auth:            []cryptossh.AuthMethod{}, // No auth - will fail after handshake
		HostKeyCallback: cryptossh.InsecureIgnoreHostKey(),
		Timeout:         1 * time.Second,
	}

	for time.Now().Before(deadline) {
		// Try a real SSH connection - this verifies the server is actually ready
		conn, err := cryptossh.Dial("tcp", addr, config)
		if conn != nil {
			_ = conn.Close()
		}

		// We expect auth to fail, but the dial should succeed (TCP + SSH handshake)
		// The server is ready when we get an SSH-level error (handshake completed but auth failed)
		// The server is NOT ready when we get a network-level error (connection refused, timeout, etc.)
		if err == nil {
			// Unexpected success - server is definitely ready
			// Give the server time to process the closed connection
			time.Sleep(200 * time.Millisecond)
			return nil
		}

		errStr := err.Error()
		// The server is ready if we got an SSH handshake error (means we connected and spoke SSH)
		// SSH errors contain "ssh:" in the message
		if strings.Contains(errStr, "ssh:") {
			// Server responded with SSH protocol - it's ready
			// Give it time to reset after our probe
			time.Sleep(200 * time.Millisecond)
			return nil
		}

		lastErr = err
		time.Sleep(50 * time.Millisecond)
	}
	return fmt.Errorf("server did not become ready within %v (last error: %v)", timeout, lastErr)
}

func StartTestServer(t *testing.T, server *Server) string {
	// Use port 0 to let the OS assign a free port
	addrPort := netip.MustParseAddrPort("127.0.0.1:0")
	if err := server.Start(context.Background(), addrPort); err != nil {
		t.Fatalf("Server failed to start: %v", err)
	}

	// Get the actual listening address from the server
	actualAddr := server.Addr()
	if actualAddr == nil {
		t.Fatalf("Server started but no listener address available")
	}

	addr := actualAddr.String()

	// Wait for the server to be ready to accept connections.
	// Use a generous timeout as CI runners can be slow.
	if err := waitForServerReady(addr, 10*time.Second); err != nil {
		t.Fatalf("Server not ready: %v", err)
	}
	return addr
}
