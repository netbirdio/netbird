package client

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func newTestForeignStore(t *testing.T, ctx context.Context) *ForeignRelaysStore {
	t.Helper()
	return NewForeignRelaysStore(ctx, hmacTokenStore, "alice", 1280, newTransportFallback(), func(string) {}, keepUnusedServerTime)
}

func TestForeignStore_AcquireDedupsConcurrentOpens(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	addr := startTestRelayServer(t, "127.0.0.1:52601")
	server := RelayServer{Addr: "rel://" + addr}

	store := newTestForeignStore(t, ctx)

	const n = 8
	var wg sync.WaitGroup
	results := make([]*foreignRelay, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			fr, err := store.acquire(server)
			require.NoError(t, err)
			results[i] = fr
		}(i)
	}
	wg.Wait()

	first := results[0]
	require.NotNil(t, first)
	for _, fr := range results {
		require.Same(t, first, fr, "all acquires must share the same foreign relay")
	}

	store.mu.RLock()
	require.Len(t, store.clients, 1, "only one client entry must be stored")
	require.Equal(t, n, first.inUse, "every acquire must be counted")
	store.mu.RUnlock()
}

func TestForeignStore_AcquireReleaseRefcount(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	addr := startTestRelayServer(t, "127.0.0.1:52602")
	server := RelayServer{Addr: "rel://" + addr}

	store := newTestForeignStore(t, ctx)

	fr, err := store.acquire(server)
	require.NoError(t, err)
	_, err = store.acquire(server)
	require.NoError(t, err)

	store.mu.RLock()
	require.Equal(t, 2, fr.inUse)
	store.mu.RUnlock()

	store.release(fr)
	store.mu.RLock()
	require.Equal(t, 1, fr.inUse)
	require.Len(t, store.clients, 1, "release must not evict the client")
	store.mu.RUnlock()
}

func TestForeignStore_AcquireConnectFailure(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)

	store := newTestForeignStore(t, ctx)

	// Nothing is listening on this port, so Connect fails.
	_, err := store.acquire(RelayServer{Addr: "rel://127.0.0.1:1"})
	require.Error(t, err)

	store.mu.RLock()
	require.Empty(t, store.clients, "a failed connect must not leave a client behind")
	store.mu.RUnlock()
}

func TestForeignStore_Evict(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	store := newTestForeignStore(t, ctx)
	store.clients["rel://a"] = &foreignRelay{}
	store.clients["rel://b"] = &foreignRelay{}

	store.evict("rel://a")
	store.evict("rel://missing")

	require.NotContains(t, store.clients, "rel://a")
	require.Contains(t, store.clients, "rel://b")
}

func TestForeignStore_CleanupUnused_KeepsRecent(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	addr := startTestRelayServer(t, "127.0.0.1:52603")
	store := newTestForeignStore(t, ctx)

	fr, err := store.acquire(RelayServer{Addr: "rel://" + addr})
	require.NoError(t, err)
	store.release(fr)

	store.cleanupUnused()

	store.mu.RLock()
	require.Len(t, store.clients, 1, "a freshly created client must be kept")
	store.mu.RUnlock()
}

func TestForeignStore_CleanupUnused_KeepsInUse(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	addr := startTestRelayServer(t, "127.0.0.1:52604")
	store := newTestForeignStore(t, ctx)

	fr, err := store.acquire(RelayServer{Addr: "rel://" + addr})
	require.NoError(t, err)

	store.mu.Lock()
	fr.created = time.Now().Add(-2 * keepUnusedServerTime)
	store.mu.Unlock()

	store.cleanupUnused()

	store.mu.RLock()
	require.Len(t, store.clients, 1, "an in-use client must be kept even when aged")
	store.mu.RUnlock()
}

func TestForeignStore_CleanupUnused_EvictsAgedIdle(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	addr := startTestRelayServer(t, "127.0.0.1:52605")
	store := newTestForeignStore(t, ctx)

	fr, err := store.acquire(RelayServer{Addr: "rel://" + addr})
	require.NoError(t, err)
	store.release(fr)

	store.mu.Lock()
	fr.created = time.Now().Add(-2 * keepUnusedServerTime)
	store.mu.Unlock()

	require.False(t, fr.client.HasConns(), "no peer connections were opened")

	store.cleanupUnused()

	store.mu.RLock()
	require.Empty(t, store.clients, "an aged idle client must be evicted")
	store.mu.RUnlock()
}

func TestForeignStore_States(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	addr := startTestRelayServer(t, "127.0.0.1:52606")
	store := newTestForeignStore(t, ctx)

	fr, err := store.acquire(RelayServer{Addr: "rel://" + addr})
	require.NoError(t, err)
	store.release(fr)

	states := store.states()
	require.Len(t, states, 1)
	require.NotEmpty(t, states[0].URL)
}
