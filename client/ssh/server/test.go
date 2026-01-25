package server

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"
)

// waitForServerReady waits for the SSH server to be ready to accept SSH connections.
// It uses a lightweight TCP banner check (reading SSH-2.0 banner) to verify the server
// is accepting connections and responding properly.
func waitForServerReady(addr string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	var lastErr error

	// checkSSHBanner does a lightweight TCP connection that just reads the SSH banner.
	// This verifies the server's Accept loop is running and handling connections.
	checkSSHBanner := func() error {
		dialer := &net.Dialer{Timeout: 2 * time.Second}
		conn, err := dialer.Dial("tcp", addr)
		if err != nil {
			return err
		}
		defer conn.Close()

		if err := conn.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
			return err
		}

		reader := bufio.NewReader(conn)
		banner, err := reader.ReadString('\n')
		if err != nil {
			return fmt.Errorf("read banner: %w", err)
		}

		if !strings.HasPrefix(banner, "SSH-") {
			return fmt.Errorf("invalid SSH banner: %s", banner)
		}

		return nil
	}

	for time.Now().Before(deadline) {
		if err := checkSSHBanner(); err == nil {
			return nil
		} else {
			lastErr = err
		}
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
