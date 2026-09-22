package server

import (
	"context"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/shared/relay/auth/allow"
)

type closeRecorderConn struct {
	reads  int
	closed bool
}

func (c *closeRecorderConn) Read(context.Context, []byte) (int, error) {
	c.reads++
	return 0, net.ErrClosed
}

func (c *closeRecorderConn) Write(context.Context, []byte) (int, error) {
	return 0, net.ErrClosed
}

func (c *closeRecorderConn) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1}
}

func (c *closeRecorderConn) Close() error {
	c.closed = true
	return nil
}

func (c *closeRecorderConn) Protocol() string {
	return "test"
}

func TestRelay_AcceptAfterShutdownClosesConn(t *testing.T) {
	relay, err := NewRelay(Config{
		ExposedAddress: "rel://127.0.0.1:1234",
		AuthValidator:  &allow.Auth{},
	})
	require.NoError(t, err)
	relay.Shutdown(context.Background())

	conn := &closeRecorderConn{}
	relay.Accept(conn)
	assert.True(t, conn.closed, "a connection accepted after shutdown must be closed")
	// The handshake error path closes the connection too, so only an untouched Read
	// proves the closed guard rejected it before any handshake.
	assert.Zero(t, conn.reads, "a connection accepted after shutdown must not be read")
}
