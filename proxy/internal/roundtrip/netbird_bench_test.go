package roundtrip

import (
	"crypto/rand"
	"math/big"
	"sync"
	"testing"
	"time"

	"github.com/netbirdio/netbird/proxy/internal/types"
	"github.com/netbirdio/netbird/shared/management/domain"
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
			domains: map[domain.Domain]domainInfo{
				domain.Domain(rand.Text()): {
					serviceID: rand.Text(),
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
			domains: map[domain.Domain]domainInfo{
				domain.Domain(rand.Text()): {
					serviceID: rand.Text(),
				},
			},
			createdAt: time.Now(),
			started:   true,
		}
	}

	// Launch workers that continuously call AddPeer with new random accountIDs.
	var wg sync.WaitGroup
	for range addPeerWorkers {
		wg.Go(func() {
			for {
				if err := nb.AddPeer(b.Context(),
					types.AccountID(rand.Text()),
					domain.Domain(rand.Text()),
					rand.Text(),
					rand.Text()); err != nil {
					b.Log(err)
				}
			}
		})
	}

	// Benchmark calling HasClient during AddPeer contention.
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			nb.HasClient(target)
		}
	})
	b.StopTimer()
}
