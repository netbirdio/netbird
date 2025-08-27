package peer

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"

	"github.com/netbirdio/netbird/shared/signal/proto"
	"github.com/netbirdio/netbird/signal/metrics"
)

func TestRegistry_ShouldNotDeregisterWhenHasNewerStreamRegistered(t *testing.T) {
	metrics, err := metrics.NewAppMetrics(otel.Meter(""))
	require.NoError(t, err)

	r := NewRegistry(metrics)

	peerID := "peer"

	_, cancel1 := context.WithCancel(context.Background())
	olderPeer := NewPeer(peerID, nil, cancel1)
	r.Register(olderPeer)
	time.Sleep(time.Nanosecond)

	_, cancel2 := context.WithCancel(context.Background())
	newerPeer := NewPeer(peerID, nil, cancel2)
	r.Register(newerPeer)
	registered, _ := r.Get(olderPeer.Id)

	assert.NotNil(t, registered, "peer can't be nil")
	assert.Equal(t, newerPeer, registered)

	r.Deregister(olderPeer)
	registered, _ = r.Get(olderPeer.Id)

	assert.NotNil(t, registered, "peer can't be nil")
	assert.Equal(t, newerPeer, registered)
}

func TestRegistry_GetNonExistentPeer(t *testing.T) {
	metrics, err := metrics.NewAppMetrics(otel.Meter(""))
	require.NoError(t, err)

	r := NewRegistry(metrics)

	peer, ok := r.Get("non_existent_peer")

	if peer != nil {
		t.Errorf("expected non_existent_peer not found in the registry")
	}

	if ok {
		t.Errorf("expected non_existent_peer not found in the registry")
	}
}

func TestRegistry_Register(t *testing.T) {
	metrics, err := metrics.NewAppMetrics(otel.Meter(""))
	require.NoError(t, err)

	r := NewRegistry(metrics)
	_, cancel1 := context.WithCancel(context.Background())
	peer1 := NewPeer("test_peer_1", nil, cancel1)
	_, cancel2 := context.WithCancel(context.Background())
	peer2 := NewPeer("test_peer_2", nil, cancel2)
	r.Register(peer1)
	r.Register(peer2)

	if _, ok := r.Get("test_peer_1"); !ok {
		t.Errorf("expected test_peer_1 not found in the registry")
	}

	if _, ok := r.Get("test_peer_2"); !ok {
		t.Errorf("expected test_peer_2 not found in the registry")
	}
}

func TestRegistry_Deregister(t *testing.T) {
	metrics, err := metrics.NewAppMetrics(otel.Meter(""))
	require.NoError(t, err)

	r := NewRegistry(metrics)
	_, cancel1 := context.WithCancel(context.Background())
	peer1 := NewPeer("test_peer_1", nil, cancel1)
	_, cancel2 := context.WithCancel(context.Background())
	peer2 := NewPeer("test_peer_2", nil, cancel2)
	r.Register(peer1)
	r.Register(peer2)

	r.Deregister(peer1)

	if _, ok := r.Get("test_peer_1"); ok {
		t.Errorf("expected test_peer_1 to absent in the registry after deregistering")
	}

	if _, ok := r.Get("test_peer_2"); !ok {
		t.Errorf("expected test_peer_2 not found in the registry")
	}

}

func TestRegistry_MultipleRegister_Concurrency(t *testing.T) {

	metrics, err := metrics.NewAppMetrics(otel.Meter(""))
	require.NoError(t, err)
	registry := NewRegistry(metrics)

	numGoroutines := 1000

	ids := make(chan int64, numGoroutines)

	var wg sync.WaitGroup
	wg.Add(numGoroutines)
	peerID := "peer-concurrent"
	for i := range numGoroutines {
		go func(routineIndex int) {
			defer wg.Done()

			_, cancel := context.WithCancel(context.Background())
			peer := NewPeer(peerID, nil, cancel)
			_ = registry.Register(peer)
			ids <- peer.StreamID
		}(i)
	}

	wg.Wait()
	close(ids)
	maxId := int64(0)
	for id := range ids {
		maxId = max(maxId, id)
	}

	peer, ok := registry.Get(peerID)
	require.True(t, ok, "expected peer to be registered")
	require.Equal(t, maxId, peer.StreamID, "expected the highest StreamID to be registered")
}

func Benchmark_MultipleRegister_Concurrency(b *testing.B) {

	metrics, err := metrics.NewAppMetrics(otel.Meter(""))
	require.NoError(b, err)

	numGoroutines := 1000

	var wg sync.WaitGroup
	peerID := "peer-concurrent"
	_, cancel := context.WithCancel(context.Background())
	b.Run("multiple-register", func(b *testing.B) {
		registry := NewRegistry(metrics)
		b.ResetTimer()
		for j := 0; j < b.N; j++ {
			wg.Add(numGoroutines)
			for i := range numGoroutines {
				go func(routineIndex int) {
					defer wg.Done()

					peer := NewPeer(peerID, nil, cancel)
					_ = registry.Register(peer)
				}(i)
			}
			wg.Wait()
		}
	})
}

func TestRegistry_MultipleDeregister_Concurrency(t *testing.T) {

	metrics, err := metrics.NewAppMetrics(otel.Meter(""))
	require.NoError(t, err)
	registry := NewRegistry(metrics)

	numGoroutines := 1000

	ids := make(chan int64, numGoroutines)

	var wg sync.WaitGroup
	wg.Add(numGoroutines)
	peerID := "peer-concurrent"
	for i := range numGoroutines {
		go func(routineIndex int) {
			defer wg.Done()

			_, cancel := context.WithCancel(context.Background())
			peer := NewPeer(peerID, nil, cancel)
			_ = registry.Register(peer)
			ids <- peer.StreamID
			registry.Deregister(peer)
		}(i)
	}

	wg.Wait()
	close(ids)
	maxId := int64(0)
	for id := range ids {
		maxId = max(maxId, id)
	}

	_, ok := registry.Get(peerID)
	require.False(t, ok, "expected peer to be deregistered")
}

func Benchmark_MultipleDeregister_Concurrency(b *testing.B) {

	metrics, err := metrics.NewAppMetrics(otel.Meter(""))
	require.NoError(b, err)

	numGoroutines := 1000

	var wg sync.WaitGroup
	peerID := "peer-concurrent"
	_, cancel := context.WithCancel(context.Background())
	b.Run("register-deregister", func(b *testing.B) {
		registry := NewRegistry(metrics)
		b.ResetTimer()
		for j := 0; j < b.N; j++ {
			wg.Add(numGoroutines)
			for i := range numGoroutines {
				go func(routineIndex int) {
					defer wg.Done()

					peer := NewPeer(peerID, nil, cancel)
					_ = registry.Register(peer)
					time.Sleep(time.Nanosecond)
					registry.Deregister(peer)
				}(i)
			}
			wg.Wait()
		}
	})
}

type mockConnectStreamServer struct {
	grpc.ServerStream
	ctx context.Context
}

func (m *mockConnectStreamServer) Context() context.Context {
	return m.ctx
}

func (m *mockConnectStreamServer) SendHeader(md metadata.MD) error {
	return nil
}

func (m *mockConnectStreamServer) Send(msg *proto.EncryptedMessage) error {
	return nil
}

func (m *mockConnectStreamServer) Recv() (*proto.EncryptedMessage, error) {
	<-m.ctx.Done()
	return nil, m.ctx.Err()
}

func TestReconnectHandling(t *testing.T) {
	metrics, err := metrics.NewAppMetrics(otel.Meter(""))
	require.NoError(t, err)
	registry := NewRegistry(metrics)
	peerID := "test-peer-reconnect"

	ctx1, cancel1 := context.WithCancel(context.Background())
	defer cancel1()
	stream1 := &mockConnectStreamServer{ctx: ctx1}
	peer1 := NewPeer(peerID, stream1, cancel1)

	err = registry.Register(peer1)
	require.NoError(t, err, "first registration should succeed")

	p, found := registry.Get(peerID)
	require.True(t, found, "peer should be found in the registry")
	require.Equal(t, peer1.StreamID, p.StreamID, "StreamID of registered peer should match")

	time.Sleep(time.Nanosecond)
	ctx2, cancel2 := context.WithCancel(context.Background())
	defer cancel2()
	stream2 := &mockConnectStreamServer{ctx: ctx2}
	peer2 := NewPeer(peerID, stream2, cancel2)

	err = registry.Register(peer2)
	require.NoError(t, err, "reconnect registration should succeed")

	select {
	case <-ctx1.Done():
		require.ErrorIs(t, ctx1.Err(), context.Canceled, "context of old stream should be canceled after successful reconnection")
	case <-time.After(100 * time.Millisecond):
		t.Fatal("context of old stream was not canceled after reconnection")
	}

	p, found = registry.Get(peerID)
	require.True(t, found)
	require.Equal(t, peer2.StreamID, p.StreamID, "registered peer should have the new StreamID after reconnection")

	ctx3, cancel3 := context.WithCancel(context.Background())
	defer cancel3()
	stream3 := &mockConnectStreamServer{ctx: ctx3}
	stalePeer := NewPeer(peerID, stream3, cancel3)
	stalePeer.StreamID = peer1.StreamID

	err = registry.Register(stalePeer)
	require.ErrorIs(t, err, ErrPeerAlreadyRegistered, "reconnecting with an old StreamID should return an error")

	p, found = registry.Get(peerID)
	require.True(t, found)
	require.Equal(t, peer2.StreamID, p.StreamID, "active peer should still be the one with the latest StreamID")

	select {
	case <-ctx2.Done():
		t.Fatal("context of the new stream should not be canceled after trying to register with an old StreamID")
	default:
	}
}
