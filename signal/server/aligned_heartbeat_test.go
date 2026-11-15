package server

import (
	"context"
	"errors"
	"io"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel"
	"google.golang.org/grpc/metadata"

	"github.com/netbirdio/netbird/shared/alignedhb"
	"github.com/netbirdio/netbird/shared/signal/proto"
)

type hbStream struct {
	proto.SignalExchange_ConnectStreamServer
	ctx      context.Context
	inflight atomic.Int32
	maxSeen  atomic.Int32
	mu       sync.Mutex
	msgs     []*proto.EncryptedMessage
	header   metadata.MD
	hbs      []time.Time
	// in carries what the client writes on the stream, nil for a client that
	// never writes.
	in chan *proto.EncryptedMessage
	// recvs counts Recv calls, so a test can tell whether the server reads.
	recvs atomic.Int32
}

func (s *hbStream) Context() context.Context { return s.ctx }

func (s *hbStream) SendHeader(md metadata.MD) error {
	s.mu.Lock()
	s.header = md.Copy()
	s.mu.Unlock()
	return nil
}

// Recv returns what the client writes and blocks until the stream ends once
// the client writes nothing more.
func (s *hbStream) Recv() (*proto.EncryptedMessage, error) {
	s.recvs.Add(1)
	select {
	case m := <-s.in:
		return m, nil
	case <-s.ctx.Done():
		return nil, io.EOF
	}
}

// write sends m on the stream as the client.
func (s *hbStream) write(t *testing.T, m *proto.EncryptedMessage) {
	t.Helper()
	select {
	case s.in <- m:
	case <-time.After(time.Second):
		t.Fatal("stream input is full")
	}
}

func (s *hbStream) Send(m *proto.EncryptedMessage) error {
	n := s.inflight.Add(1)
	for {
		old := s.maxSeen.Load()
		if n <= old || s.maxSeen.CompareAndSwap(old, n) {
			break
		}
	}
	time.Sleep(time.Millisecond)
	s.mu.Lock()
	s.msgs = append(s.msgs, m)
	if m.GetServerHeartbeat() != nil {
		s.hbs = append(s.hbs, time.Now())
	}
	s.mu.Unlock()
	s.inflight.Add(-1)
	return nil
}

func (s *hbStream) heartbeats() []*proto.EncryptedMessage {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []*proto.EncryptedMessage
	for _, m := range s.msgs {
		if m.GetServerHeartbeat() != nil {
			out = append(out, m)
		}
	}
	return out
}

func (s *hbStream) times() []time.Time {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]time.Time(nil), s.hbs...)
}

func (s *hbStream) answer() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.header.Get(alignedhb.MetadataKey)
}

func (s *hbStream) registered() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.header.Get(proto.HeaderRegistered)) > 0
}

func connectTestPeer(t *testing.T, s *Server, peerKey string, pairs ...string) *hbStream {
	t.Helper()
	md := metadata.Pairs(append([]string{proto.HeaderId, peerKey}, pairs...)...)
	ctx, cancel := context.WithCancel(metadata.NewIncomingContext(context.Background(), md))
	stream := &hbStream{ctx: ctx, in: make(chan *proto.EncryptedMessage, 8)}
	done := make(chan error, 1)
	go func() { done <- s.ConnectStream(stream) }()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			assert.True(t, errors.Is(err, context.Canceled) || errors.Is(err, ErrPeerRegisteredAgain), "stream ended with %v", err)
		}
	})
	require.Eventually(t, func() bool { return s.registry.IsPeerRegistered(peerKey) }, time.Second, 10*time.Millisecond)
	return stream
}

func TestConnectStreamAlignedHeartbeat(t *testing.T) {
	s := newAlignedTestServer(t)

	const peerKey = "Zm9vYmFyZm9vYmFyZm9vYmFyZm9vYmFyZm9vYmFyMDA="
	req := signedRequest(t, testPhaseSecret, peerKey, time.Second)
	ctx, cancel := context.WithCancel(metadata.NewIncomingContext(context.Background(),
		metadata.Pairs(proto.HeaderId, peerKey, alignedhb.MetadataKey, req.Value())))
	defer cancel()
	stream := &hbStream{ctx: ctx}

	done := make(chan error, 1)
	go func() { done <- s.ConnectStream(stream) }()

	require.Eventually(t, func() bool { return s.registry.IsPeerRegistered(peerKey) }, time.Second, 10*time.Millisecond)

	want := alignedhb.Answer{Period: time.Second, Phase: req.Signed.Phase}
	require.Eventually(t, func() bool { return len(stream.answer()) == 1 }, time.Second, 10*time.Millisecond)
	assert.Equal(t, []string{want.Value()}, stream.answer(), "the header must carry the answer")
	stream.mu.Lock()
	assert.NotEmpty(t, stream.header.Get(proto.HeaderRegistered), "the answer must not replace the registration header")
	stream.mu.Unlock()

	// Forward messages while heartbeats fire; writes must never overlap.
	stop := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
					s.forwardMessageToPeer(context.Background(), &proto.EncryptedMessage{Key: "sender", RemoteKey: peerKey})
				}
			}
		}()
	}

	require.Eventually(t, func() bool { return len(stream.heartbeats()) >= 2 }, 4*time.Second, 20*time.Millisecond)
	close(stop)
	wg.Wait()

	for _, hb := range stream.heartbeats() {
		require.Empty(t, hb.Key, "a heartbeat has no sender")
		require.Equal(t, peerKey, hb.RemoteKey)
		require.Nil(t, hb.Body, "a heartbeat has no body")
		require.Equal(t, uint32(want.Phase.Milliseconds()), hb.GetServerHeartbeat().GetPhaseMillis(),
			"heartbeat must carry the phase the server sends on")
	}
	for i, at := range stream.times() {
		off := phaseOffset(at, want.Phase, time.Second)
		assert.LessOrEqual(t, off, 100*time.Millisecond, "heartbeat %d %s from phase %s", i, off, want.Phase)
	}
	require.Equal(t, int32(1), stream.maxSeen.Load(), "heartbeat and forwarded sends must not overlap")

	cancel()
	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(2 * time.Second):
		t.Fatal("ConnectStream did not return after stream closed")
	}

	n := len(stream.heartbeats())
	time.Sleep(1500 * time.Millisecond)
	require.Equal(t, n, len(stream.heartbeats()), "heartbeat must stop after stream closes")
}

func TestConnectStreamStockWithoutRequest(t *testing.T) {
	s, err := NewServer(context.Background(), otel.Meter(""))
	require.NoError(t, err)

	stock := connectTestPeer(t, s, "Zm9vYmFyZm9vYmFyZm9vYmFyZm9vYmFyZm9vYmFyMDI=")
	invalid := connectTestPeer(t, s, "Zm9vYmFyZm9vYmFyZm9vYmFyZm9vYmFyZm9vYmFyMDU=", alignedhb.MetadataKey, "period=0")
	noVerifier := connectTestPeer(t, s, "Zm9vYmFyZm9vYmFyZm9vYmFyZm9vYmFyZm9vYmFyMDY=", alignedhb.MetadataKey,
		alignedhb.StreamRequest{Period: 2 * time.Second}.Value())

	time.Sleep(1500 * time.Millisecond)
	streams := map[string]*hbStream{"no request": stock, "invalid request": invalid, "no phase verifier": noVerifier}
	for name, stream := range streams {
		assert.Empty(t, stream.times(), "%s: no heartbeats", name)
		assert.Empty(t, stream.answer(), "%s: no answer", name)
		// A stock client never writes on its stream, so the server starts no
		// reader for it.
		assert.Zero(t, stream.recvs.Load(), "%s: stock stream must not be read", name)
		stream.mu.Lock()
		assert.NotEmpty(t, stream.header.Get(proto.HeaderRegistered), "%s: registration header", name)
		stream.mu.Unlock()
	}
}
