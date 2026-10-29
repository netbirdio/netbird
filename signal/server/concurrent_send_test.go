package server

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel"

	"github.com/netbirdio/netbird/shared/signal/proto"
	"github.com/netbirdio/netbird/signal/peer"
)

// concurrencyCheckStream records the maximum number of Send calls in flight at
// once. gRPC forbids concurrent SendMsg on the same ServerStream, so a correct
// server must never have more than one in flight per peer.
type concurrencyCheckStream struct {
	proto.SignalExchange_ConnectStreamServer
	ctx      context.Context
	inflight atomic.Int32
	maxSeen  atomic.Int32
}

func (s *concurrencyCheckStream) Send(*proto.EncryptedMessage) error {
	n := s.inflight.Add(1)
	for {
		old := s.maxSeen.Load()
		if n <= old || s.maxSeen.CompareAndSwap(old, n) {
			break
		}
	}
	// Widen the window so overlapping callers are reliably observed.
	time.Sleep(time.Millisecond)
	s.inflight.Add(-1)
	return nil
}

func (s *concurrencyCheckStream) Context() context.Context { return s.ctx }

// TestForwardMessageToPeerSerializesSend verifies that concurrent forwards to the
// same peer never call Stream.Send concurrently, which would violate the gRPC
// ServerStream contract.
func TestForwardMessageToPeerSerializesSend(t *testing.T) {
	s, err := NewServer(context.Background(), otel.Meter(""))
	require.NoError(t, err)

	const peerID = "peerX"
	stream := &concurrencyCheckStream{ctx: context.Background()}
	_, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	require.NoError(t, s.registry.Register(peer.NewPeer(peerID, stream, cancel)))

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.forwardMessageToPeer(context.Background(), &proto.EncryptedMessage{Key: "sender", RemoteKey: peerID})
		}()
	}
	wg.Wait()

	require.Equal(t, int32(1), stream.maxSeen.Load(), "Stream.Send must never run concurrently on the same peer stream")
}
