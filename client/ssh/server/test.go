package server

import (
	"context"
	"fmt"
	"net/netip"
	"testing"
	"time"
)

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
		return actualAddr
	case err := <-errChan:
		t.Fatalf("Server failed to start: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("Server start timeout")
	}
	return ""
}
