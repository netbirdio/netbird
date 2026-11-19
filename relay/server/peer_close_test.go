package server

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/shared/relay/auth/allow"
	"github.com/netbirdio/netbird/shared/relay/messages"
)

// stalledWriteConn blocks every transport write until the connection is closed and
// ignores the write context, like a QUIC connection whose datagram queue is full.
type stalledWriteConn struct {
	*scriptedConn
	entered     chan struct{}
	enteredOnce sync.Once
}

func newStalledWriteConn() *stalledWriteConn {
	return &stalledWriteConn{
		scriptedConn: newScriptedConn(),
		entered:      make(chan struct{}),
	}
}

func (c *stalledWriteConn) Write(ctx context.Context, b []byte) (int, error) {
	if b[1] != byte(messages.MsgTypeTransport) {
		return c.scriptedConn.Write(ctx, b)
	}

	c.enteredOnce.Do(func() { close(c.entered) })
	<-c.closed
	return 0, net.ErrClosed
}

func TestPeer_CloseDoesNotWaitForStalledWrite(t *testing.T) {
	relay := newTestRelay(t, &allow.Auth{})
	conn := newStalledWriteConn()
	t.Cleanup(func() { _ = conn.Close() })
	peerID := messages.HashID("stalled")
	peer := NewPeer(relay.metrics, peerID, messages.CurrentProtocolVersion, conn, relay.store, relay.notifier)

	transport, err := messages.MarshalTransportMsg(peerID, []byte("payload"))
	require.NoError(t, err)
	writeErr := make(chan error, 1)
	go func() {
		_, err := peer.Write(context.Background(), transport)
		writeErr <- err
	}()
	require.True(t, signaled(conn.entered), "the write must reach the connection")

	closed := make(chan struct{})
	go func() {
		defer close(closed)
		peer.Close()
	}()
	require.True(t, signaled(closed), "closing a peer must not wait for a stalled write")

	select {
	case err := <-writeErr:
		assert.Error(t, err, "the stalled write must be aborted by the close")
	case <-time.After(testWaitTimeout):
		assert.Fail(t, "the stalled write must return after the close")
	}
}

func TestRelay_ReconnectDoesNotStallOnOldConnectionWrite(t *testing.T) {
	relay := newTestRelay(t, &allow.Auth{})
	targetID := messages.HashID("target")

	oldConn := newStalledWriteConn()
	t.Cleanup(func() { _ = oldConn.Close() })
	oldConn.deliver(t, authFrame(t, "target"))
	relay.Accept(oldConn)
	oldConn.waitFrames(t, 1)

	sender, _ := acceptPeer(t, relay, "sender")
	transport, err := messages.MarshalTransportMsg(targetID, []byte("payload"))
	require.NoError(t, err)
	sender.deliver(t, transport)
	require.True(t, signaled(oldConn.entered), "the forwarded frame must stall on the old connection")

	newConn := newScriptedConn()
	newConn.deliver(t, authFrame(t, "target"))
	reconnected := make(chan struct{})
	go func() {
		defer close(reconnected)
		relay.Accept(newConn)
	}()

	bystanderConn := newScriptedConn()
	bystanderConn.deliver(t, authFrame(t, "bystander"))
	bystanderConnected := make(chan struct{})
	go func() {
		defer close(bystanderConnected)
		relay.Accept(bystanderConn)
	}()

	assert.True(t, signaled(reconnected), "a reconnect must not wait for a write stalled on the old connection")
	assert.True(t, signaled(bystanderConnected), "an unrelated peer must be able to connect during the reconnect")
	// A reconnect that is still stuck holds the store lock, so the lookups below would hang.
	if t.Failed() {
		return
	}

	assert.True(t, oldConn.isClosed(), "the replaced connection must be closed")
	assert.False(t, newConn.isClosed(), "the new connection must stay open")
	stored, ok := relay.store.Peer(targetID)
	require.True(t, ok, "the reconnected peer must be in the store")
	assert.Same(t, newConn, stored.(*Peer).conn, "the store must hold the new connection")
}

func authFrame(t *testing.T, name string) []byte {
	t.Helper()
	auth, err := messages.MarshalAuthMsg(messages.HashID(name), []byte("token"))
	require.NoError(t, err)
	return auth
}

func signaled(signal <-chan struct{}) bool {
	select {
	case <-signal:
		return true
	case <-time.After(testWaitTimeout):
		return false
	}
}
