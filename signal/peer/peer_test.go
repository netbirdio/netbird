package peer

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel"

	"github.com/netbirdio/netbird/signal/metrics"
)

func TestRegistry_ShouldNotDeregisterWhenHasNewerStreamRegistered(t *testing.T) {
	metrics, err := metrics.NewAppMetrics(otel.Meter(""))
	require.NoError(t, err)

	r := NewRegistry(metrics)

	peerID := "peer"

	olderPeer := NewPeer(peerID, nil)
	r.Register(olderPeer)
	time.Sleep(time.Nanosecond)

	newerPeer := NewPeer(peerID, nil)
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
	peer1 := NewPeer("test_peer_1", nil)
	peer2 := NewPeer("test_peer_2", nil)
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
	peer1 := NewPeer("test_peer_1", nil)
	peer2 := NewPeer("test_peer_2", nil)
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

func BenchmarkPeerAllocation(b *testing.B) {
	b.Run("no pool", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = NewPeer("peer", nil)
		}
	})
	b.Run("with pool", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			p := NewPeerPool("peer", nil, nil)
			p.Reset()
		}
	})
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
	_, cancel := context.WithCancel(context.Background())
	for i := range numGoroutines {
		go func(routineIndex int) {
			defer wg.Done()

			peer := NewPeerPool(peerID, nil, cancel)
			registry.RegisterPool(peer)
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
	b.Run("old", func(b *testing.B) {
		registry := NewRegistry(metrics)
		b.ResetTimer()
		for j := 0; j < b.N; j++ {
			wg.Add(numGoroutines)
			for i := range numGoroutines {
				go func(routineIndex int) {
					defer wg.Done()

					peer := NewPeer(peerID, nil)
					registry.Register(peer)
				}(i)
			}
			wg.Wait()
		}
	})
	_, cancel := context.WithCancel(context.Background())
	b.Run("new", func(b *testing.B) {
		registry := NewRegistry(metrics)
		b.ResetTimer()
		for j := 0; j < b.N; j++ {
			wg.Add(numGoroutines)
			for i := range numGoroutines {
				go func(routineIndex int) {
					defer wg.Done()

					peer := NewPeerPool(peerID, nil, cancel)
					registry.RegisterPool(peer)
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
	_, cancel := context.WithCancel(context.Background())
	for i := range numGoroutines {
		go func(routineIndex int) {
			defer wg.Done()

			peer := NewPeerPool(peerID, nil, cancel)
			registry.RegisterPool(peer)
			ids <- peer.StreamID
			registry.DeregisterPool(peer)
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
	b.Run("old", func(b *testing.B) {
		registry := NewRegistry(metrics)
		b.ResetTimer()
		for j := 0; j < b.N; j++ {
			wg.Add(numGoroutines)
			for i := range numGoroutines {
				go func(routineIndex int) {
					defer wg.Done()

					peer := NewPeer(peerID, nil)
					registry.Register(peer)
					time.Sleep(time.Nanosecond)
					registry.Deregister(peer)
				}(i)
			}
			wg.Wait()
		}
	})
	_, cancel := context.WithCancel(context.Background())
	b.Run("new", func(b *testing.B) {
		registry := NewRegistry(metrics)
		b.ResetTimer()
		for j := 0; j < b.N; j++ {
			wg.Add(numGoroutines)
			for i := range numGoroutines {
				go func(routineIndex int) {
					defer wg.Done()

					peer := NewPeerPool(peerID, nil, cancel)
					registry.RegisterPool(peer)
					time.Sleep(time.Nanosecond)
					registry.DeregisterPool(peer)
				}(i)
			}
			wg.Wait()
		}
	})
}
