package server

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel"
	"google.golang.org/grpc/metadata"

	"github.com/netbirdio/netbird/shared/alignedhb"
	"github.com/netbirdio/netbird/shared/alignedhb/keepalive"
	"github.com/netbirdio/netbird/shared/signal/proto"
)

// acceptedConn returns the server end of a loopback TCP connection.
func acceptedConn(t *testing.T) net.Conn {
	t.Helper()
	if _, err := keepalive.Idle(nil); errors.Is(err, errors.ErrUnsupported) {
		t.Skip(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })
	client, err := net.Dial("tcp", ln.Addr().String())
	require.NoError(t, err)
	t.Cleanup(func() { _ = client.Close() })
	srv, err := ln.Accept()
	require.NoError(t, err)
	t.Cleanup(func() { _ = srv.Close() })
	return srv
}

func idleOf(t *testing.T, c net.Conn) time.Duration {
	t.Helper()
	idle, err := keepalive.Idle(c)
	require.NoError(t, err)
	return idle
}

// connectOnConn opens a stream as if it came in on conn. It returns the
// stream and the func that ends it and waits for ConnectStream to return.
func connectOnConn(t *testing.T, s *Server, conn net.Conn, peerKey string, pairs ...string) (*hbStream, func()) {
	t.Helper()
	md := metadata.Pairs(append([]string{proto.HeaderId, peerKey}, pairs...)...)
	ctx := keepalive.ConnContext(metadata.NewIncomingContext(context.Background(), md), conn)
	ctx, cancel := context.WithCancel(ctx)
	stream := &hbStream{ctx: ctx, in: make(chan *proto.EncryptedMessage, 8)}
	done := make(chan error, 1)
	go func() { done <- s.ConnectStream(stream) }()
	var once sync.Once
	end := func() {
		once.Do(func() {
			cancel()
			if err := <-done; err != nil {
				assert.True(t, errors.Is(err, context.Canceled) || errors.Is(err, ErrPeerRegisteredAgain), "stream ended with %v", err)
			}
		})
	}
	t.Cleanup(end)
	require.Eventually(t, func() bool { return s.registry.IsPeerRegistered(peerKey) }, time.Second, 10*time.Millisecond)
	return stream, end
}

// An aligned stream moves the keepalive of its connection past the period, so
// the server sends no probe between two heartbeats, and restores it at the end.
func TestConnectStreamAlignedKeepAlive(t *testing.T) {
	s := newAlignedTestServer(t)
	conn := acceptedConn(t)
	stock := idleOf(t, conn)

	const peerKey = "Zm9vYmFyZm9vYmFyZm9vYmFyZm9vYmFyZm9vYmFyMjA="
	req := signedRequest(t, testPhaseSecret, peerKey, 2*time.Second)
	_, end := connectOnConn(t, s, conn, peerKey, alignedhb.MetadataKey, req.Value())

	assert.Eventually(t, func() bool { return idleOf(t, conn) == 4*time.Second }, 2*time.Second, 10*time.Millisecond,
		"aligned stream: idle twice the period")
	end()
	assert.Eventually(t, func() bool { return idleOf(t, conn) == stock }, 2*time.Second, 10*time.Millisecond,
		"the ended stream restores the stock keepalive")
}

// A stream that opened stock switches its connection once the signed phase
// arrives on the stream.
func TestConnectStreamKeepAliveAfterSignedPhase(t *testing.T) {
	s := newAlignedTestServer(t)
	conn := acceptedConn(t)
	stock := idleOf(t, conn)

	const peerKey = "Zm9vYmFyZm9vYmFyZm9vYmFyZm9vYmFyZm9vYmFyMjE="
	req := signedRequest(t, testPhaseSecret, peerKey, 2*time.Second)
	stream, _ := connectOnConn(t, s, conn, peerKey, alignedhb.MetadataKey, alignedhb.StreamRequest{Period: 2 * time.Second}.Value())
	require.Eventually(t, func() bool { return len(stream.answer()) == 1 }, time.Second, 10*time.Millisecond)
	time.Sleep(100 * time.Millisecond)
	assert.Equal(t, stock, idleOf(t, conn), "a stream without a signed phase keeps the stock keepalive")

	stream.write(t, &proto.EncryptedMessage{Key: peerKey, RemoteKey: peerKey, PhaseRequest: &proto.PhaseRequest{
		PhaseMillis:    uint32(req.Signed.Phase.Milliseconds()),
		PhaseDay:       req.Signed.Day,
		PhaseSignature: req.Signed.Signature,
		PeriodSeconds:  2,
	}})
	assert.Eventually(t, func() bool { return idleOf(t, conn) == 4*time.Second }, 2*time.Second, 10*time.Millisecond,
		"the signed phase switches the connection")
}

// Old clients and desktops send no request: their connection keeps the stock
// keepalive.
func TestConnectStreamStockKeepAlive(t *testing.T) {
	s, err := NewServer(context.Background(), otel.Meter(""))
	require.NoError(t, err)
	conn := acceptedConn(t)
	stock := idleOf(t, conn)

	connectOnConn(t, s, conn, "Zm9vYmFyZm9vYmFyZm9vYmFyZm9vYmFyZm9vYmFyMjI=")
	time.Sleep(200 * time.Millisecond)
	assert.Equal(t, stock, idleOf(t, conn), "stock stream must not touch the keepalive")
}

// A stream that ends because the peer registered again restores the keepalive
// of its own connection while that connection stays open.
func TestConnectStreamRegisteredAgainRestoresKeepAlive(t *testing.T) {
	s := newAlignedTestServer(t)
	oldConn := acceptedConn(t)
	stock := idleOf(t, oldConn)

	const peerKey = "Zm9vYmFyZm9vYmFyZm9vYmFyZm9vYmFyZm9vYmFyMjM="
	req := signedRequest(t, testPhaseSecret, peerKey, 2*time.Second)
	connectOnConn(t, s, oldConn, peerKey, alignedhb.MetadataKey, req.Value())
	require.Eventually(t, func() bool { return idleOf(t, oldConn) == 4*time.Second }, 2*time.Second, 10*time.Millisecond,
		"aligned stream: idle twice the period")

	connectOnConn(t, s, acceptedConn(t), peerKey)
	assert.Eventually(t, func() bool { return idleOf(t, oldConn) == stock }, 2*time.Second, 10*time.Millisecond,
		"the replaced stream restores the stock keepalive")
}
