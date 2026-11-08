package server

import (
	"context"
	"io"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/netbirdio/netbird/shared/signal/proto"
)

func peerCtx(t *testing.T, key string) (context.Context, context.CancelFunc) {
	t.Helper()
	ctx, cancel := context.WithCancel(metadata.NewIncomingContext(context.Background(),
		metadata.Pairs(proto.HeaderId, key)))
	t.Cleanup(cancel)
	return ctx, cancel
}

func (s *hbStream) byKey(key string) []*proto.EncryptedMessage {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []*proto.EncryptedMessage
	for _, m := range s.msgs {
		if m.Key == key {
			out = append(out, m)
		}
	}
	return out
}

func TestGoingAwayNotifiesPeersAndRefusesNewStreams(t *testing.T) {
	s, err := NewServer(context.Background(), otel.Meter(""))
	require.NoError(t, err)

	const peerKey = "Z29pbmdhd2F5Z29pbmdhd2F5Z29pbmdhd2F5Z29pbmc="
	ctx, cancel := peerCtx(t, peerKey)
	stream := &hbStream{ctx: ctx}
	done := make(chan error, 1)
	go func() { done <- s.ConnectStream(stream) }()
	// A heartbeat proves the stream is past registration and fully connected.
	require.Eventually(t, func() bool { return len(stream.heartbeats()) > 0 }, 3*time.Second, 10*time.Millisecond)

	s.GoingAway()

	msgs := stream.byKey(TestGoingAwayKey)
	require.Len(t, msgs, 1, "the connected peer must get exactly one going-away message")
	assert.Equal(t, peerKey, msgs[0].RemoteKey, "going-away must be addressed to the peer")
	assert.Nil(t, msgs[0].Body, "going-away carries no body")

	// A reconnect that lands on the draining server must be refused.
	ctx2, _ := peerCtx(t, peerKey)
	err = s.ConnectStream(&hbStream{ctx: ctx2})
	assert.Equal(t, codes.Unavailable, status.Code(err), "new stream must get Unavailable while draining")
	assert.True(t, s.registry.IsPeerRegistered(peerKey), "a refused stream must not replace the old registration")

	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("ConnectStream did not return after stream closed")
	}
}

// recvStream yields n client messages on Recv, then blocks until the stream ends.
type recvStream struct {
	hbStream
	left atomic.Int32
	read atomic.Int32
}

func (s *recvStream) Recv() (*proto.EncryptedMessage, error) {
	if s.left.Add(-1) >= 0 {
		s.read.Add(1)
		return &proto.EncryptedMessage{Key: TestHeartbeatKey}, nil
	}
	<-s.ctx.Done()
	return nil, io.EOF
}

func TestConnectStreamDrainsClientWrites(t *testing.T) {
	s, err := NewServer(context.Background(), otel.Meter(""))
	require.NoError(t, err)

	const peerKey = "ZHJhaW5kcmFpbmRyYWluZHJhaW5kcmFpbmRyYWluMDA="
	ctx, cancel := peerCtx(t, peerKey)
	stream := &recvStream{hbStream: hbStream{ctx: ctx}}
	stream.left.Store(50)
	done := make(chan error, 1)
	go func() { done <- s.ConnectStream(stream) }()

	require.Eventually(t, func() bool { return stream.read.Load() == 50 }, time.Second, 10*time.Millisecond,
		"server must read every message the client writes on its stream")

	cancel()
	select {
	case err := <-done:
		assert.NoError(t, err)
	case <-time.After(2 * time.Second):
		t.Fatal("ConnectStream did not return after stream closed")
	}
}
