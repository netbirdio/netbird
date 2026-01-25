package server

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"testing"
	"time"
)

// waitForServerReady waits for the SSH server to be ready to accept connections.
// Uses aggressive polling with short intervals to minimize test latency while
// ensuring we catch server readiness even on slow CI runners (especially Windows).
func waitForServerReady(addr string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	var lastErr error
	attempt := 0
	for time.Now().Before(deadline) {
		attempt++
		conn, err := net.DialTimeout("tcp", addr, 500*time.Millisecond)
		if err == nil {
			conn.Close()
			return nil
		}
		lastErr = err
		// Exponential backoff: 10ms, 20ms, 40ms, 80ms, then cap at 100ms
		backoff := time.Duration(10<<min(attempt, 4)) * time.Millisecond
		if backoff > 100*time.Millisecond {
			backoff = 100 * time.Millisecond
		}
		time.Sleep(backoff)
	}
	return fmt.Errorf("server did not become ready within %v (last error: %v)", timeout, lastErr)
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
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
