package roundtrip

import (
	"context"
	"crypto/rand"
	"math/big"
	"sync"
	"testing"
	"time"

	"github.com/netbirdio/netbird/proxy/internal/types"
)

// Simple benchmark for comparison with AddPeer contention.
func BenchmarkHasClient(b *testing.B) {
	// Knobs for dialling in:
	initialClientCount := 100 // Size of initial peer map to generate.

	nb := mockNetBird()

	var target types.AccountID
	targetIndex, err := rand.Int(rand.Reader, big.NewInt(int64(initialClientCount)))
	if err != nil {
		b.Fatal(err)
	}
	for i := range initialClientCount {
		id := types.AccountID(rand.Text())
		if int64(i) == targetIndex.Int64() {
			target = id
		}
		nb.clients[id] = &clientEntry{
			services: map[ServiceKey]serviceInfo{
				ServiceKey(rand.Text()): {
					serviceID: types.ServiceID(rand.Text()),
				},
			},
			createdAt: time.Now(),
			started:   true,
		}
	}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			nb.HasClient(target)
		}
	})
	b.StopTimer()
}

func BenchmarkHasClientDuringAddPeer(b *testing.B) {
	// Knobs for dialling in:
	initialClientCount := 100 // Size of initial peer map to generate.
	addPeerWorkers := 5       // Number of workers to concurrently call AddPeer.

	nb := mockNetBird()

	// Add random client entries to the netbird instance.
	// We're trying to test map lock contention, so starting with
	// a populated map should help with this.
	// Pick a random one to target for retrieval later.
	var target types.AccountID
	targetIndex, err := rand.Int(rand.Reader, big.NewInt(int64(initialClientCount)))
	if err != nil {
		b.Fatal(err)
	}
	for i := range initialClientCount {
		id := types.AccountID(rand.Text())
		if int64(i) == targetIndex.Int64() {
			target = id
		}
		nb.clients[id] = &clientEntry{
			services: map[ServiceKey]serviceInfo{
				ServiceKey(rand.Text()): {
					serviceID: types.ServiceID(rand.Text()),
				},
			},
			createdAt: time.Now(),
			started:   true,
		}
	}

	// Launch workers that continuously call AddPeer with new random accountIDs.
	ctx, cancel := context.WithCancel(b.Context())
	var wg sync.WaitGroup
	for range addPeerWorkers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for ctx.Err() == nil {
				if err := nb.AddPeer(ctx,
					types.AccountID(rand.Text()),
					ServiceKey(rand.Text()),
					rand.Text(),
					types.ServiceID(rand.Text())); err != nil {
					return
				}
			}
		}()
	}

	// Benchmark calling HasClient during AddPeer contention.
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			nb.HasClient(target)
		}
	})
	b.StopTimer()
	cancel()
	wg.Wait()
}
