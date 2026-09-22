package server

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/relay/server/listener/ws"
	"github.com/netbirdio/netbird/shared/relay/auth/allow"
)

func TestServer_ShutdownBeforeListen(t *testing.T) {
	addr := freeAddress(t)
	srv := newTestServer(t, addr)
	require.NoError(t, srv.Shutdown(context.Background()))

	errChan := make(chan error, 1)
	go func() {
		errChan <- srv.Listen(ListenerConfig{Address: addr})
	}()

	assert.NoError(t, waitForListenToReturn(t, errChan))
	assert.Empty(t, srv.ListenerProtocols(), "a shut down server must not register listeners")
	requireAddressFree(t, addr)
}

func TestServer_ShutdownStopsListen(t *testing.T) {
	addr := freeAddress(t)
	srv := newTestServer(t, addr)

	errChan := make(chan error, 1)
	go func() {
		errChan <- srv.Listen(ListenerConfig{Address: addr})
	}()

	waitForListeners(t, srv, errChan)

	require.NoError(t, srv.Shutdown(context.Background()))
	assert.NoError(t, waitForListenToReturn(t, errChan))
	requireAddressFree(t, addr)
}

func TestServer_ListenReturnsBindError(t *testing.T) {
	blocker, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = blocker.Close() })
	addr := blocker.Addr().String()
	srv := newTestServer(t, addr)

	errChan := make(chan error, 1)
	go func() {
		errChan <- srv.Listen(ListenerConfig{Address: addr})
	}()

	assert.Error(t, waitForListenToReturn(t, errChan), "Listen must return the bind error instead of serving")
	assert.Empty(t, srv.ListenerProtocols(), "a failed Listen must not register listeners")

	require.NoError(t, blocker.Close())
	requireAddressFree(t, addr)
}

func TestBindListeners_RollsBackOnError(t *testing.T) {
	addr := freeAddress(t)
	listeners := []Listener{
		&ws.Listener{Address: addr},
		&ws.Listener{Address: addr},
	}

	bound, err := bindListeners(listeners)
	require.Error(t, err, "binding the same address twice must fail")
	assert.Nil(t, bound, "no listener may be reported as bound after a failure")
	requireAddressFree(t, addr)
}

func newTestServer(t *testing.T, addr string) *Server {
	t.Helper()
	srv, err := NewServer(Config{
		ExposedAddress: "rel://" + addr,
		AuthValidator:  &allow.Auth{},
	})
	require.NoError(t, err)
	t.Cleanup(func() {
		assert.NoError(t, srv.Shutdown(context.Background()))
	})
	return srv
}

// The server binds TCP and UDP on the same port, so a port is only picked when
// both are free. The probes are closed before Listen binds, which leaves a small
// window for another process to take the port; waitForListeners then reports the
// bind error instead of a timeout.
func freeAddress(t *testing.T) string {
	t.Helper()
	for attempt := 0; attempt < 10; attempt++ {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		require.NoError(t, err)
		addr := ln.Addr().String()
		require.NoError(t, ln.Close())

		conn, err := net.ListenPacket("udp", addr)
		if err != nil {
			continue
		}
		require.NoError(t, conn.Close())
		return addr
	}
	t.Fatal("no address with both tcp and udp ports free")
	return ""
}

// Listen registers its listeners under the same lock that starts serving, so a
// non-empty ListenerProtocols means the sockets are bound. A Listen that returns
// before that has failed to bind, and its error is reported instead of a timeout.
func waitForListeners(t *testing.T, srv *Server, errChan <-chan error) {
	t.Helper()
	deadline := time.After(5 * time.Second)
	for len(srv.ListenerProtocols()) == 0 {
		select {
		case err := <-errChan:
			t.Fatalf("Listen returned before binding: %v", err)
		case <-deadline:
			t.Fatal("listeners were not bound")
		case <-time.After(10 * time.Millisecond):
		}
	}
}

func waitForListenToReturn(t *testing.T, errChan <-chan error) error {
	t.Helper()
	select {
	case err := <-errChan:
		return err
	case <-time.After(5 * time.Second):
		t.Fatal("Listen did not return")
		return nil
	}
}

// The QUIC listener releases its UDP socket from the read loop after Close returns,
// so both sockets are polled instead of checked once.
func requireAddressFree(t *testing.T, addr string) {
	t.Helper()
	require.Eventually(t, func() bool {
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			return false
		}
		_ = ln.Close()

		conn, err := net.ListenPacket("udp", addr)
		if err != nil {
			return false
		}
		_ = conn.Close()
		return true
	}, 5*time.Second, 10*time.Millisecond, "address %s must be released", addr)
}
