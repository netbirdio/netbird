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
	addr := freeTCPAddress(t)
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
	addr := freeTCPAddress(t)
	srv := newTestServer(t, addr)

	errChan := make(chan error, 1)
	go func() {
		errChan <- srv.Listen(ListenerConfig{Address: addr})
	}()

	// ListenerProtocols is populated under the same lock that starts serving, so a
	// non-empty result means Listen has bound its listeners.
	require.Eventually(t, func() bool {
		return len(srv.ListenerProtocols()) > 0
	}, 5*time.Second, 10*time.Millisecond, "listeners were not bound")

	require.NoError(t, srv.Shutdown(context.Background()))
	assert.NoError(t, waitForListenToReturn(t, errChan))
	requireAddressFree(t, addr)
}

func TestBindListeners_RollsBackOnError(t *testing.T) {
	addr := freeTCPAddress(t)
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
	return srv
}

func freeTCPAddress(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := ln.Addr().String()
	require.NoError(t, ln.Close())
	return addr
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
