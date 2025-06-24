package server

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"testing"
	"time"
)

func StartTestServer(t *testing.T, server *Server) string {
	started := make(chan string, 1)
	errChan := make(chan error, 1)

	go func() {
		// Get a free port
		ln, err := net.Listen("tcp", "127.0.0.1:0")
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
		addrPort := netip.MustParseAddrPort(actualAddr)
		errChan <- server.Start(context.Background(), addrPort)
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
