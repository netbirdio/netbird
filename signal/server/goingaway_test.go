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

	"github.com/netbirdio/netbird/shared/alignedhb"
	"github.com/netbirdio/netbird/shared/signal/proto"
)

func peerCtx(t *testing.T, key string) (context.Context, context.CancelFunc) {
	t.Helper()
	ctx, cancel := context.WithCancel(metadata.NewIncomingContext(context.Background(),
		metadata.Pairs(proto.HeaderId, key)))
	t.Cleanup(cancel)
	return ctx, cancel
}

// goingAway returns the going-away messages the stream got.
func (s *hbStream) goingAway() []*proto.EncryptedMessage {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []*proto.EncryptedMessage
	for _, m := range s.msgs {
		if m.GetServerHeartbeat().GetGoingAway() {
			out = append(out, m)
		}
	}
	return out
}

// waitAlignedMark waits until the stream of peerKey got the aligned heartbeat
// answer and was marked for it.
func waitAlignedMark(t *testing.T, s *Server, peerKey string) {
	t.Helper()
	require.Eventually(t, func() bool {
		p, ok := s.registry.Get(peerKey)
		return ok && p.AlignedHeartbeat()
	}, 3*time.Second, 10*time.Millisecond, "stream of %s must be marked aligned", peerKey)
}

func TestGoingAwayNotifiesPeersAndRefusesNewStreams(t *testing.T) {
	s := newAlignedTestServer(t)

	const (
		alignedKey = "Z29pbmdhd2F5Z29pbmdhd2F5Z29pbmdhd2F5Z29pbmc="
		pendingKey = "Z29pbmdhd2F5cGVuZGluZ3BlbmRpbmdwZW5kaW5nMDA="
		stockKey   = "Z29pbmdhd2F5c3RvY2tzdG9ja3N0b2Nrc3RvY2swMDA="
	)
	// A stream with a signed phase, one that asked but has no signed phase yet,
	// and a stock stream that never asked.
	aligned := connectTestPeer(t, s, alignedKey, alignedhb.MetadataKey, signedRequest(t, testPhaseSecret, alignedKey, time.Minute).Value())
	pending := connectTestPeer(t, s, pendingKey, alignedhb.MetadataKey, alignedhb.StreamRequest{Period: time.Minute}.Value())
	stock := connectTestPeer(t, s, stockKey)
	waitAlignedMark(t, s, alignedKey)
	waitAlignedMark(t, s, pendingKey)
	require.Eventually(t, stock.registered, 3*time.Second, 10*time.Millisecond)

	s.GoingAway()

	for key, stream := range map[string]*hbStream{alignedKey: aligned, pendingKey: pending} {
		msgs := stream.goingAway()
		require.Len(t, msgs, 1, "peer %s that got the answer must get exactly one going-away message", key)
		assert.Equal(t, key, msgs[0].RemoteKey, "going-away must be addressed to the peer")
		assert.Empty(t, msgs[0].Key, "going-away has no sender key, so the client gate accepts it")
		assert.Nil(t, msgs[0].Body, "going-away carries no body")
	}
	stock.mu.Lock()
	assert.Empty(t, stock.msgs, "a stock peer must get no message, it would try to decrypt it")
	stock.mu.Unlock()
	p, ok := s.registry.Get(stockKey)
	require.True(t, ok, "stock peer must stay registered")
	assert.False(t, p.AlignedHeartbeat(), "a stock stream must not be marked aligned")

	// A reconnect that lands on the draining server must be refused.
	ctx2, _ := peerCtx(t, alignedKey)
	err := s.ConnectStream(&hbStream{ctx: ctx2})
	assert.Equal(t, codes.Unavailable, status.Code(err), "new stream must get Unavailable while draining")
	assert.True(t, s.registry.IsPeerRegistered(alignedKey), "a refused stream must not replace the old registration")
}

func TestGoingAwaySkipsStockServer(t *testing.T) {
	// Without a phase verifier no stream gets an answer, so a server that never
	// turned the aligned heartbeat on sends no going-away message at all.
	s, err := NewServer(context.Background(), otel.Meter(""))
	require.NoError(t, err)

	const peerKey = "Z29pbmdhd2F5bm92ZXJpZmllcm5vdmVyaWZpZXJub3Y="
	stream := connectTestPeer(t, s, peerKey, alignedhb.MetadataKey, alignedhb.StreamRequest{Period: time.Minute}.Value())
	require.Eventually(t, stream.registered, 3*time.Second, 10*time.Millisecond)

	s.GoingAway()

	assert.Empty(t, stream.answer(), "no answer without a phase verifier")
	assert.Empty(t, stream.goingAway(), "a stream without the answer must get no going-away message")
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
		return &proto.EncryptedMessage{Key: "peer", RemoteKey: "peer"}, nil
	}
	<-s.ctx.Done()
	return nil, io.EOF
}

// A client writes on its stream only after an aligned heartbeat answer, and the
// server reads all of it so unread frames never fill the stream window.
func TestConnectStreamDrainsClientWrites(t *testing.T) {
	s := newAlignedTestServer(t)

	const peerKey = "ZHJhaW5kcmFpbmRyYWluZHJhaW5kcmFpbmRyYWluMDA="
	ctx, cancel := context.WithCancel(metadata.NewIncomingContext(context.Background(), metadata.Pairs(
		proto.HeaderId, peerKey, alignedhb.MetadataKey, alignedhb.StreamRequest{Period: 2 * time.Second}.Value())))
	t.Cleanup(cancel)
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
