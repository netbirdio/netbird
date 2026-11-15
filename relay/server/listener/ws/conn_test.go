package ws

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	relaylistener "github.com/netbirdio/netbird/relay/server/listener"
)

// acceptOne serves l and returns the first relay connection it accepts.
func acceptOne(t *testing.T, l *Listener) *Conn {
	t.Helper()
	accepted := make(chan *Conn, 1)
	go func() {
		_ = l.Serve(func(c relaylistener.Conn) {
			accepted <- c.(*Conn)
		})
	}()
	t.Cleanup(func() { _ = l.Shutdown(context.Background()) })

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	client, resp, err := websocket.Dial(ctx, "ws://"+l.listener.Addr().String()+URLPath, nil)
	if resp != nil && resp.Body != nil {
		_ = resp.Body.Close()
	}
	require.NoError(t, err)
	t.Cleanup(func() { _ = client.CloseNow() })

	select {
	case c := <-accepted:
		t.Cleanup(func() { _ = c.Close() })
		return c
	case <-time.After(5 * time.Second):
		t.Fatal("no connection accepted")
		return nil
	}
}

func TestConn_KeepsAcceptedSocket(t *testing.T) {
	l := &Listener{Address: "127.0.0.1:0"}
	require.NoError(t, l.Bind())
	c := acceptOne(t, l)

	require.NotNil(t, c.netConn, "the accepted socket must reach the relay connection")
	_, isTCP := c.netConn.(*net.TCPConn)
	assert.True(t, isTCP, "socket type %T", c.netConn)
	assert.NoError(t, c.UseAlignedHeartbeat(time.Minute), "tuning the accepted socket")
}

func TestConn_UseAlignedHeartbeatWithoutSocket(t *testing.T) {
	c := &Conn{}
	assert.Error(t, c.UseAlignedHeartbeat(time.Minute), "a connection without a socket cannot be tuned")
}
