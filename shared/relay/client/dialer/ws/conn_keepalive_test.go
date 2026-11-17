package ws

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/shared/alignedhb/keepalive"
)

// The relay client tunes the TCP keepalive once v2 is confirmed, so the
// WebSocket conn must lead to the socket below it.
func TestConnLeadsToTCPSocket(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer ln.Close()
	raw, err := net.Dial("tcp", ln.Addr().String())
	require.NoError(t, err)
	defer raw.Close()

	tc, ok := keepalive.TCPConn(NewConn(nil, "rels://relay.example:443", raw))
	assert.True(t, ok, "socket below the WebSocket must be found")
	assert.Same(t, raw, net.Conn(tc))

	_, ok = keepalive.TCPConn(NewConn(nil, "rels://relay.example:443", nil))
	assert.False(t, ok, "no socket when the dial did not record one")
}
