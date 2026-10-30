package server

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"

	"github.com/netbirdio/netbird/shared/signal/proto"
)

// recordingStream is a minimal ConnectStream mock that records every message
// sent on it and that Recv blocks until the context is done, mirroring how a
// real peer holds its stream open.
type recordingStream struct {
	grpc.ServerStream
	ctx context.Context

	mu   sync.Mutex
	sent []*proto.EncryptedMessage
}

func (s *recordingStream) Context() context.Context     { return s.ctx }
func (s *recordingStream) SendHeader(metadata.MD) error { return nil }
func (s *recordingStream) Recv() (*proto.EncryptedMessage, error) {
	<-s.ctx.Done()
	return nil, s.ctx.Err()
}

func (s *recordingStream) Send(msg *proto.EncryptedMessage) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sent = append(s.sent, msg)
	return nil
}

func (s *recordingStream) sentMessages() []*proto.EncryptedMessage {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]*proto.EncryptedMessage(nil), s.sent...)
}

func registeredStreamCtx(peerID string) (context.Context, context.CancelFunc) {
	md := metadata.Pairs(proto.HeaderId, peerID)
	return context.WithCancel(metadata.NewIncomingContext(context.Background(), md))
}

func TestConnectStream_FlushAfterRegister_Enabled(t *testing.T) {
	s, err := NewServer(context.Background(), otel.Meter(""))
	require.NoError(t, err)
	s.flushAfterRegister = true

	ctx, cancel := registeredStreamCtx("peer-flush-on")
	stream := &recordingStream{ctx: ctx}

	done := make(chan error, 1)
	go func() { done <- s.ConnectStream(stream) }()

	require.Eventually(t, func() bool {
		return len(stream.sentMessages()) == 1
	}, time.Second, time.Millisecond, "expected exactly one placeholder message after the registration header")

	msg := stream.sentMessages()[0]
	require.Equal(t, "signal-server-flush", msg.Key)
	require.Equal(t, "peer-flush-on", msg.RemoteKey)

	cancel()
	require.NoError(t, <-done)
}

func TestConnectStream_FlushAfterRegister_DisabledByDefault(t *testing.T) {
	// Isolate from whatever the test process's environment happens to have,
	// so this reliably exercises the default rather than an inherited value.
	t.Setenv(EnvFlushAfterRegister, "")

	s, err := NewServer(context.Background(), otel.Meter(""))
	require.NoError(t, err)
	require.False(t, s.flushAfterRegister, "flag must default to disabled")

	ctx, cancel := registeredStreamCtx("peer-flush-off")
	stream := &recordingStream{ctx: ctx}

	done := make(chan error, 1)
	go func() { done <- s.ConnectStream(stream) }()

	time.Sleep(50 * time.Millisecond)
	require.Empty(t, stream.sentMessages(), "no message should be sent when the flag is disabled")

	cancel()
	require.NoError(t, <-done)
}

// blockingFirstSendStream wraps concurrencyCheckStream and pauses its very
// first Send call until released, signaling once it has entered. This lets a
// test start concurrent senders while that first call is in flight, so it
// reliably overlaps with them instead of depending on scheduling luck.
type blockingFirstSendStream struct {
	*concurrencyCheckStream
	once    sync.Once
	entered chan struct{}
	release chan struct{}
}

func newBlockingFirstSendStream(ctx context.Context) *blockingFirstSendStream {
	return &blockingFirstSendStream{
		concurrencyCheckStream: &concurrencyCheckStream{ctx: ctx},
		entered:                make(chan struct{}),
		release:                make(chan struct{}),
	}
}

func (s *blockingFirstSendStream) Send(msg *proto.EncryptedMessage) error {
	s.once.Do(func() {
		close(s.entered)
		<-s.release
	})
	return s.concurrencyCheckStream.Send(msg)
}

// TestConnectStream_FlushNeverRacesForwardedMessages guards against
// regressing the flush back to calling stream.Send directly: the flush must
// go through Peer.Send (which holds sendMu) so it can never run concurrently
// with a message forwardMessageToPeer relays to the same peer, which would
// violate gRPC's single-writer contract for a ServerStream. The first Send
// (the flush) is held open until all 50 forwards are queued up behind
// Peer.Send's mutex, guaranteeing real overlap instead of relying on the
// flush and the forwards happening to race by scheduling luck.
func TestConnectStream_FlushNeverRacesForwardedMessages(t *testing.T) {
	s, err := NewServer(context.Background(), otel.Meter(""))
	require.NoError(t, err)
	s.flushAfterRegister = true

	const peerID = "peer-flush-race"
	ctx, cancel := registeredStreamCtx(peerID)
	stream := newBlockingFirstSendStream(ctx)

	done := make(chan error, 1)
	go func() { done <- s.ConnectStream(stream) }()

	select {
	case <-stream.entered:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for the registration flush to start")
	}

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.forwardMessageToPeer(context.Background(), &proto.EncryptedMessage{Key: "sender", RemoteKey: peerID})
		}()
	}

	// Give the forwards time to actually reach Peer.Send and queue up behind
	// its mutex - held by the flush's in-progress Send - before releasing it.
	time.Sleep(50 * time.Millisecond)
	close(stream.release)

	wg.Wait()
	cancel()
	require.NoError(t, <-done)

	require.Equal(t, int32(1), stream.maxSeen.Load(), "Stream.Send must never run concurrently on the same peer stream")
	require.Equal(t, int32(51), stream.total.Load(), "expected the placeholder plus all 50 forwarded messages")
}
