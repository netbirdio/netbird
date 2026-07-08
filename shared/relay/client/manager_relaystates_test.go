package client

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// stallingRelayListener accepts TCP connections and holds them open without ever
// responding, so a relay handshake dialed against it blocks until its context is
// cancelled. It returns the "rel://host:port" URL to dial.
func stallingRelayListener(t *testing.T) string {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	var mu sync.Mutex
	var conns []net.Conn
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			conns = append(conns, c)
			mu.Unlock()
		}
	}()
	t.Cleanup(func() {
		_ = ln.Close()
		mu.Lock()
		for _, c := range conns {
			_ = c.Close()
		}
		mu.Unlock()
	})

	return "rel://" + ln.Addr().String()
}

// TestRelayStates_DoesNotBlockOnRealHangingDial is a regression test for
// status calls hanging behind an in-progress relay dial.
//
// While a relay is being dialed, its RelayTrack write-lock is held for the whole
// dial (up to serverResponseTimeout per transport attempt, times the transport
// fallback chain, times however many relays are being dialed at once) in openConnVia.
func TestRelayStates_DoesNotBlockOnRealHangingDial(t *testing.T) {
	serverAddr := stallingRelayListener(t)

	mCtx, mCancel := context.WithCancel(context.Background())
	t.Cleanup(mCancel)

	m := NewManager(mCtx, nil, "alice", 1280)

	dialDone := make(chan struct{})
	go func() {
		defer close(dialDone)
		_, _ = m.openConnVia(mCtx, serverAddr, "peerKey", netip.Addr{})
	}()

	require.Eventually(t, func() bool {
		m.relayClientsMutex.RLock()
		defer m.relayClientsMutex.RUnlock()
		_, ok := m.relayClients[serverAddr]
		return ok
	}, 5*time.Second, 5*time.Millisecond, "relay dial did not start")

	done := make(chan []RelayConnState, 1)
	go func() {
		done <- m.RelayStates()
	}()

	select {
	case states := <-done:
		require.Empty(t, states, "a relay still being dialed carries no state and must be omitted")
	case <-time.After(2 * time.Second):
		t.Fatal("RelayStates blocked on a foreign relay whose Connect() is in progress")
	}

	// Release the hanging dial so the goroutine can exit cleanly.
	mCancel()
	select {
	case <-dialDone:
	case <-time.After(5 * time.Second):
		t.Fatal("openConnVia did not return after context cancellation")
	}
}
