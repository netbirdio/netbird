//go:build linux

package quic

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	relaylistener "github.com/netbirdio/netbird/relay/server/listener"
)

func TestListener_SocketsShareThePort(t *testing.T) {
	t.Setenv(envSockets, "4")

	l := &Listener{Address: "127.0.0.1:0", TLSConfig: testTLSConfig(t)}
	require.NoError(t, l.Bind())
	t.Cleanup(func() { _ = l.Shutdown(context.Background()) })

	require.Len(t, l.sockets, 4, "one socket per requested count")
	port := l.sockets[0].LocalAddr.(*net.UDPAddr).Port
	for i, s := range l.sockets {
		assert.Equal(t, port, s.LocalAddr.(*net.UDPAddr).Port, "socket %d must share the port", i)
	}
}

func TestListener_AcceptsOnSharedPort(t *testing.T) {
	t.Setenv(envSockets, "4")

	l := &Listener{Address: "127.0.0.1:0", TLSConfig: testTLSConfig(t)}
	require.NoError(t, l.Bind())
	addr := l.sockets[0].LocalAddr.String()

	// The kernel picks the socket from the client's source port, so several clients
	// are needed to land on more than one socket.
	const clients = 16
	accepted := make(chan relaylistener.Conn, clients)
	errChan := make(chan error, 1)
	go func() {
		errChan <- l.Serve(func(conn relaylistener.Conn) { accepted <- conn })
	}()

	conns := make([]relaylistener.Conn, 0, clients)
	for range clients {
		dialTestSession(t, addr)
		select {
		case conn := <-accepted:
			conns = append(conns, conn)
		case <-time.After(5 * time.Second):
			t.Fatal("listener did not accept the test session")
		}
	}

	require.NoError(t, l.Shutdown(context.Background()))
	assert.NoError(t, waitForServeToReturn(t, errChan))

	for _, conn := range conns {
		require.NoError(t, conn.Close())
	}
	requireUDPAddressFree(t, addr)
}
