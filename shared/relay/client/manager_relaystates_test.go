package client

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// stallingRelayListener accepts TCP connections and holds them open without ever
// responding, so a relay handshake dialed against it blocks until its context is
// cancelled. accepted is signalled once per incoming connection so a caller can
// wait until a dial has actually reached the listener. It returns the
// "rel://host:port" URL to dial.
func stallingRelayListener(t *testing.T) (string, <-chan struct{}) {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	accepted := make(chan struct{}, 1)
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
			select {
			case accepted <- struct{}{}:
			default:
			}
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

	return "rel://" + ln.Addr().String(), accepted
}

// TestRelayStates_DoesNotBlockOnRealHangingDial is a regression test for
// RelayStates() called by a "status -d command" hanging behind an in-progress
// foreign relay dial.
func TestRelayStates_DoesNotBlockOnRealHangingDial(t *testing.T) {
	serverAddr, accepted := stallingRelayListener(t)

	mCtx, mCancel := context.WithCancel(context.Background())
	t.Cleanup(mCancel)

	m := NewManager(mCtx, nil, "alice", 1280)

	dialDone := make(chan struct{})
	go func() {
		defer close(dialDone)
		_, _ = m.foreign.OpenConn(mCtx, "peerKey", RelayServer{Addr: serverAddr})
	}()

	select {
	case <-accepted:
	case <-time.After(5 * time.Second):
		t.Fatal("relay dial did not reach the listener")
	}

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
		t.Fatal("foreign OpenConn did not return after context cancellation")
	}
}
