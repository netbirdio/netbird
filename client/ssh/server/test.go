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
		// If we get "connection refused", the server isn't ready yet
		// If we get "ssh: handshake failed: EOF" or auth errors, the server IS ready
		if err == nil {
			// Unexpected success - server is definitely ready
			return nil
		}

		errStr := err.Error()
		// These errors indicate the SSH server is up and responding:
		// - "ssh: handshake failed: ssh: no auth methods available" (server working, no auth)
		// - "ssh: handshake failed: EOF" (server closed after banner)
		// - Any error that isn't "connection refused" or network-related
		if !isConnectionRefusedError(errStr) {
			return nil
		}

		lastErr = err
		time.Sleep(50 * time.Millisecond)
	}
	return fmt.Errorf("server did not become ready within %v (last error: %v)", timeout, lastErr)
}

// isConnectionRefusedError checks if the error indicates the server isn't listening yet
func isConnectionRefusedError(errStr string) bool {
	// Check for common connection refused patterns across platforms
	return strings.Contains(errStr, "connection refused") ||
		strings.Contains(errStr, "connectex: No connection could be made") ||
		strings.Contains(errStr, "connect: connection refused") ||
		(strings.Contains(errStr, "dial tcp") && strings.Contains(errStr, "refused"))
}

func StartTestServer(t *testing.T, server *Server) string {
	started := make(chan string, 1)
	errChan := make(chan error, 1)

	go func() {
		// Use port 0 to let the OS assign a free port
		addrPort := netip.MustParseAddrPort("127.0.0.1:0")
		if err := server.Start(context.Background(), addrPort); err != nil {
			errChan <- err
			return
		}

		// Get the actual listening address from the server
		actualAddr := server.Addr()
		if actualAddr == nil {
			errChan <- fmt.Errorf("server started but no listener address available")
			return
		}

		started <- actualAddr.String()
	}()

	select {
	case actualAddr := <-started:
		// Wait for the server to be ready to accept connections.
		// Use a generous timeout as Windows CI runners can be slow.
		if err := waitForServerReady(actualAddr, 10*time.Second); err != nil {
			t.Fatalf("Server not ready: %v", err)
		}
		return actualAddr
	case err := <-errChan:
		t.Fatalf("Server failed to start: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("Server start timeout")
	}
	return ""
}
