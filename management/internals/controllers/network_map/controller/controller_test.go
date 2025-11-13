package controller

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/netbirdio/netbird/management/internals/controllers/network_map"
	"github.com/netbirdio/netbird/management/server/mock_server"
	nbpeer "github.com/netbirdio/netbird/management/server/peer"
)

func TestComputeForwarderPort(t *testing.T) {
	// Test with empty peers list
	peers := []*nbpeer.Peer{}
	result := computeForwarderPort(peers, "v0.59.0")
	if result != int64(network_map.OldForwarderPort) {
		t.Errorf("Expected %d for empty peers list, got %d", network_map.OldForwarderPort, result)
	}

	// Test with peers that have old versions
	peers = []*nbpeer.Peer{
		{
			Meta: nbpeer.PeerSystemMeta{
				WtVersion: "0.57.0",
			},
		},
		{
			Meta: nbpeer.PeerSystemMeta{
				WtVersion: "0.26.0",
			},
		},
	}
	result = computeForwarderPort(peers, "v0.59.0")
	if result != int64(network_map.OldForwarderPort) {
		t.Errorf("Expected %d for peers with old versions, got %d", network_map.OldForwarderPort, result)
	}

	// Test with peers that have new versions
	peers = []*nbpeer.Peer{
		{
			Meta: nbpeer.PeerSystemMeta{
				WtVersion: "0.59.0",
			},
		},
		{
			Meta: nbpeer.PeerSystemMeta{
				WtVersion: "0.59.0",
			},
		},
	}
	result = computeForwarderPort(peers, "v0.59.0")
	if result != int64(network_map.DnsForwarderPort) {
		t.Errorf("Expected %d for peers with new versions, got %d", network_map.DnsForwarderPort, result)
	}

	// Test with peers that have mixed versions
	peers = []*nbpeer.Peer{
		{
			Meta: nbpeer.PeerSystemMeta{
				WtVersion: "0.59.0",
			},
		},
		{
			Meta: nbpeer.PeerSystemMeta{
				WtVersion: "0.57.0",
			},
		},
	}
	result = computeForwarderPort(peers, "v0.59.0")
	if result != int64(network_map.OldForwarderPort) {
		t.Errorf("Expected %d for peers with mixed versions, got %d", network_map.OldForwarderPort, result)
	}

	// Test with peers that have empty version
	peers = []*nbpeer.Peer{
		{
			Meta: nbpeer.PeerSystemMeta{
				WtVersion: "",
			},
		},
	}
	result = computeForwarderPort(peers, "v0.59.0")
	if result != int64(network_map.OldForwarderPort) {
		t.Errorf("Expected %d for peers with empty version, got %d", network_map.OldForwarderPort, result)
	}

	peers = []*nbpeer.Peer{
		{
			Meta: nbpeer.PeerSystemMeta{
				WtVersion: "development",
			},
		},
	}
	result = computeForwarderPort(peers, "v0.59.0")
	if result == int64(network_map.OldForwarderPort) {
		t.Errorf("Expected %d for peers with dev version, got %d", network_map.DnsForwarderPort, result)
	}

	// Test with peers that have unknown version string
	peers = []*nbpeer.Peer{
		{
			Meta: nbpeer.PeerSystemMeta{
				WtVersion: "unknown",
			},
		},
	}
	result = computeForwarderPort(peers, "v0.59.0")
	if result != int64(network_map.OldForwarderPort) {
		t.Errorf("Expected %d for peers with unknown version, got %d", network_map.OldForwarderPort, result)
	}
}

func TestBufferUpdateAccountPeers(t *testing.T) {
	const (
		peersCount            = 1000
		updateAccountInterval = 50 * time.Millisecond
	)

	var (
		deletedPeers, updatePeersDeleted, updatePeersRuns atomic.Int32
		uapLastRun, dpLastRun                             atomic.Int64

		totalNewRuns, totalOldRuns int
	)

	uap := func(ctx context.Context, accountID string) {
		updatePeersDeleted.Store(deletedPeers.Load())
		updatePeersRuns.Add(1)
		uapLastRun.Store(time.Now().UnixMilli())
		time.Sleep(100 * time.Millisecond)
	}

	t.Run("new approach", func(t *testing.T) {
		updatePeersRuns.Store(0)
		updatePeersDeleted.Store(0)
		deletedPeers.Store(0)

		var mustore sync.Map
		bufupd := func(ctx context.Context, accountID string) {
			mu, _ := mustore.LoadOrStore(accountID, &bufferUpdate{})
			b := mu.(*bufferUpdate)

			if !b.mu.TryLock() {
				b.update.Store(true)
				return
			}

			if b.next != nil {
				b.next.Stop()
			}

			go func() {
				defer b.mu.Unlock()
				uap(ctx, accountID)
				if !b.update.Load() {
					return
				}
				b.update.Store(false)
				b.next = time.AfterFunc(updateAccountInterval, func() {
					uap(ctx, accountID)
				})
			}()
		}
		dp := func(ctx context.Context, accountID, peerID, userID string) error {
			deletedPeers.Add(1)
			dpLastRun.Store(time.Now().UnixMilli())
			time.Sleep(10 * time.Millisecond)
			bufupd(ctx, accountID)
			return nil
		}

		am := mock_server.MockAccountManager{
			UpdateAccountPeersFunc:       uap,
			BufferUpdateAccountPeersFunc: bufupd,
			DeletePeerFunc:               dp,
		}
		empty := ""
		for range peersCount {
			//nolint
			am.DeletePeer(context.Background(), empty, empty, empty)
		}
		time.Sleep(100 * time.Millisecond)

		assert.Equal(t, peersCount, int(deletedPeers.Load()), "Expected all peers to be deleted")
		assert.Equal(t, peersCount, int(updatePeersDeleted.Load()), "Expected all peers to be updated in the buffer")
		assert.GreaterOrEqual(t, uapLastRun.Load(), dpLastRun.Load(), "Expected update account peers to run after delete peer")

		totalNewRuns = int(updatePeersRuns.Load())
	})

	t.Run("old approach", func(t *testing.T) {
		updatePeersRuns.Store(0)
		updatePeersDeleted.Store(0)
		deletedPeers.Store(0)

		var mustore sync.Map
		bufupd := func(ctx context.Context, accountID string) {
			mu, _ := mustore.LoadOrStore(accountID, &sync.Mutex{})
			b := mu.(*sync.Mutex)

			if !b.TryLock() {
				return
			}

			go func() {
				time.Sleep(updateAccountInterval)
				b.Unlock()
				uap(ctx, accountID)
			}()
		}
		dp := func(ctx context.Context, accountID, peerID, userID string) error {
			deletedPeers.Add(1)
			dpLastRun.Store(time.Now().UnixMilli())
			time.Sleep(10 * time.Millisecond)
			bufupd(ctx, accountID)
			return nil
		}

		am := mock_server.MockAccountManager{
			UpdateAccountPeersFunc:       uap,
			BufferUpdateAccountPeersFunc: bufupd,
			DeletePeerFunc:               dp,
		}
		empty := ""
		for range peersCount {
			//nolint
			am.DeletePeer(context.Background(), empty, empty, empty)
		}
		time.Sleep(100 * time.Millisecond)

		assert.Equal(t, peersCount, int(deletedPeers.Load()), "Expected all peers to be deleted")
		assert.Equal(t, peersCount, int(updatePeersDeleted.Load()), "Expected all peers to be updated in the buffer")
		assert.GreaterOrEqual(t, uapLastRun.Load(), dpLastRun.Load(), "Expected update account peers to run after delete peer")

		totalOldRuns = int(updatePeersRuns.Load())
	})
	assert.Less(t, totalNewRuns, totalOldRuns, "Expected new approach to run less than old approach. New runs: %d, Old runs: %d", totalNewRuns, totalOldRuns)
	t.Logf("New runs: %d, Old runs: %d", totalNewRuns, totalOldRuns)
}
