package server

import (
	"context"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel"
	"google.golang.org/grpc/metadata"

	"github.com/netbirdio/netbird/shared/signal/proto"
)

func TestMain(m *testing.M) {
	// testhb reads env once per process, so set it before any test runs.
	_ = os.Setenv("NB_TEST_HB_MODE", "aligned")
	_ = os.Setenv("NB_TEST_HB_PERIOD_SEC", "1")
	os.Exit(m.Run())
}

type hbStream struct {
	proto.SignalExchange_ConnectStreamServer
	ctx      context.Context
	inflight atomic.Int32
	maxSeen  atomic.Int32
	mu       sync.Mutex
	msgs     []*proto.EncryptedMessage
}

func (s *hbStream) Context() context.Context     { return s.ctx }
func (s *hbStream) SendHeader(metadata.MD) error { return nil }

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
	s.mu.Unlock()
	s.inflight.Add(-1)
	return nil
}

func (s *hbStream) heartbeats() []*proto.EncryptedMessage {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []*proto.EncryptedMessage
	for _, m := range s.msgs {
		if m.Key == TestHeartbeatKey {
			out = append(out, m)
		}
	}
	return out
}

func TestConnectStreamSendsTestHeartbeat(t *testing.T) {
	s, err := NewServer(context.Background(), otel.Meter(""))
	require.NoError(t, err)

	const peerKey = "Zm9vYmFyZm9vYmFyZm9vYmFyZm9vYmFyZm9vYmFyMDA="
	ctx, cancel := context.WithCancel(metadata.NewIncomingContext(context.Background(),
		metadata.Pairs(proto.HeaderId, peerKey)))
	defer cancel()
	stream := &hbStream{ctx: ctx}

	done := make(chan error, 1)
	go func() { done <- s.ConnectStream(stream) }()

	require.Eventually(t, func() bool { return s.registry.IsPeerRegistered(peerKey) }, time.Second, 10*time.Millisecond)

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
		require.Equal(t, TestHeartbeatKey, hb.Key)
		require.Equal(t, peerKey, hb.RemoteKey)
		require.Nil(t, hb.Body)
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
