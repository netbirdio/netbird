package manager

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/management/internals/modules/reverseproxy"
)

func TestExposeKey(t *testing.T) {
	assert.Equal(t, "peer1:example.com", exposeKey("peer1", "example.com"))
	assert.Equal(t, "peer2:other.com", exposeKey("peer2", "other.com"))
	assert.NotEqual(t, exposeKey("peer1", "a.com"), exposeKey("peer1", "b.com"))
}

func TestTrackExposeIfAllowed(t *testing.T) {
	t.Run("first track succeeds", func(t *testing.T) {
		tracker := &exposeTracker{}
		alreadyTracked, ok := tracker.TrackExposeIfAllowed("peer1", "a.com", "acct1")
		assert.False(t, alreadyTracked, "first track should not be duplicate")
		assert.True(t, ok, "first track should be allowed")
	})

	t.Run("duplicate track detected", func(t *testing.T) {
		tracker := &exposeTracker{}
		tracker.TrackExposeIfAllowed("peer1", "a.com", "acct1")

		alreadyTracked, ok := tracker.TrackExposeIfAllowed("peer1", "a.com", "acct1")
		assert.True(t, alreadyTracked, "second track should be duplicate")
		assert.False(t, ok)
	})

	t.Run("rejects when at limit", func(t *testing.T) {
		tracker := &exposeTracker{}
		for i := range maxExposesPerPeer {
			_, ok := tracker.TrackExposeIfAllowed("peer1", "domain-"+string(rune('a'+i))+".com", "acct1")
			assert.True(t, ok, "track %d should be allowed", i)
		}

		alreadyTracked, ok := tracker.TrackExposeIfAllowed("peer1", "over-limit.com", "acct1")
		assert.False(t, alreadyTracked)
		assert.False(t, ok, "should reject when at limit")
	})

	t.Run("other peer unaffected by limit", func(t *testing.T) {
		tracker := &exposeTracker{}
		for i := range maxExposesPerPeer {
			tracker.TrackExposeIfAllowed("peer1", "domain-"+string(rune('a'+i))+".com", "acct1")
		}

		_, ok := tracker.TrackExposeIfAllowed("peer2", "a.com", "acct1")
		assert.True(t, ok, "other peer should still be within limit")
	})
}

func TestUntrackExpose(t *testing.T) {
	tracker := &exposeTracker{}

	tracker.TrackExposeIfAllowed("peer1", "a.com", "acct1")
	assert.Equal(t, 1, tracker.CountPeerExposes("peer1"))

	tracker.UntrackExpose("peer1", "a.com")
	assert.Equal(t, 0, tracker.CountPeerExposes("peer1"))
}

func TestCountPeerExposes(t *testing.T) {
	tracker := &exposeTracker{}

	assert.Equal(t, 0, tracker.CountPeerExposes("peer1"))

	tracker.TrackExposeIfAllowed("peer1", "a.com", "acct1")
	tracker.TrackExposeIfAllowed("peer1", "b.com", "acct1")
	tracker.TrackExposeIfAllowed("peer2", "a.com", "acct1")

	assert.Equal(t, 2, tracker.CountPeerExposes("peer1"), "peer1 should have 2 exposes")
	assert.Equal(t, 1, tracker.CountPeerExposes("peer2"), "peer2 should have 1 expose")
	assert.Equal(t, 0, tracker.CountPeerExposes("peer3"), "peer3 should have 0 exposes")
}

func TestMaxExposesPerPeer(t *testing.T) {
	tracker := &exposeTracker{}
	assert.Equal(t, maxExposesPerPeer, tracker.MaxExposesPerPeer())
}

func TestRenewTrackedExpose(t *testing.T) {
	tracker := &exposeTracker{}

	found := tracker.RenewTrackedExpose("peer1", "a.com")
	assert.False(t, found, "should not find untracked expose")

	tracker.TrackExposeIfAllowed("peer1", "a.com", "acct1")

	found = tracker.RenewTrackedExpose("peer1", "a.com")
	assert.True(t, found, "should find tracked expose")
}

func TestRenewTrackedExpose_RejectsExpiring(t *testing.T) {
	tracker := &exposeTracker{}
	tracker.TrackExposeIfAllowed("peer1", "a.com", "acct1")

	// Simulate reaper marking the expose as expiring
	key := exposeKey("peer1", "a.com")
	val, _ := tracker.activeExposes.Load(key)
	expose := val.(*trackedExpose)
	expose.mu.Lock()
	expose.expiring = true
	expose.mu.Unlock()

	found := tracker.RenewTrackedExpose("peer1", "a.com")
	assert.False(t, found, "should reject renewal when expiring")
}

func TestReapExpiredExposes(t *testing.T) {
	mgr, _ := setupIntegrationTest(t)
	tracker := mgr.exposeTracker

	ctx := context.Background()
	resp, err := mgr.CreateServiceFromPeer(ctx, testAccountID, testPeerID, &reverseproxy.ExposeServiceRequest{
		Port:     8080,
		Protocol: "http",
	})
	require.NoError(t, err)

	// Manually expire the tracked entry
	key := exposeKey(testPeerID, resp.Domain)
	val, _ := tracker.activeExposes.Load(key)
	expose := val.(*trackedExpose)
	expose.mu.Lock()
	expose.lastRenewed = time.Now().Add(-2 * exposeTTL)
	expose.mu.Unlock()

	// Add an active (non-expired) tracking entry
	tracker.activeExposes.Store(exposeKey("peer1", "active.com"), &trackedExpose{
		domain:      "active.com",
		accountID:   testAccountID,
		peerID:      "peer1",
		lastRenewed: time.Now(),
	})

	tracker.reapExpiredExposes()

	_, exists := tracker.activeExposes.Load(key)
	assert.False(t, exists, "expired expose should be removed")

	_, exists = tracker.activeExposes.Load(exposeKey("peer1", "active.com"))
	assert.True(t, exists, "active expose should remain")
}

func TestReapExpiredExposes_SetsExpiringFlag(t *testing.T) {
	mgr, _ := setupIntegrationTest(t)
	tracker := mgr.exposeTracker

	ctx := context.Background()
	resp, err := mgr.CreateServiceFromPeer(ctx, testAccountID, testPeerID, &reverseproxy.ExposeServiceRequest{
		Port:     8080,
		Protocol: "http",
	})
	require.NoError(t, err)

	key := exposeKey(testPeerID, resp.Domain)
	val, _ := tracker.activeExposes.Load(key)
	expose := val.(*trackedExpose)

	// Expire it
	expose.mu.Lock()
	expose.lastRenewed = time.Now().Add(-2 * exposeTTL)
	expose.mu.Unlock()

	// Renew should succeed before reaping
	assert.True(t, tracker.RenewTrackedExpose(testPeerID, resp.Domain), "renew should succeed before reaper runs")

	// Re-expire and reap
	expose.mu.Lock()
	expose.lastRenewed = time.Now().Add(-2 * exposeTTL)
	expose.mu.Unlock()

	tracker.reapExpiredExposes()

	// Entry is deleted, renew returns false
	assert.False(t, tracker.RenewTrackedExpose(testPeerID, resp.Domain), "renew should fail after reap")
}

func TestConcurrentTrackAndCount(t *testing.T) {
	mgr, _ := setupIntegrationTest(t)
	tracker := mgr.exposeTracker
	ctx := context.Background()

	for i := range 5 {
		_, err := mgr.CreateServiceFromPeer(ctx, testAccountID, testPeerID, &reverseproxy.ExposeServiceRequest{
			Port:     8080 + i,
			Protocol: "http",
		})
		require.NoError(t, err)
	}

	// Manually expire all tracked entries
	tracker.activeExposes.Range(func(_, val any) bool {
		expose := val.(*trackedExpose)
		expose.mu.Lock()
		expose.lastRenewed = time.Now().Add(-2 * exposeTTL)
		expose.mu.Unlock()
		return true
	})

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		tracker.reapExpiredExposes()
	}()
	go func() {
		defer wg.Done()
		tracker.CountPeerExposes(testPeerID)
	}()
	wg.Wait()

	assert.Equal(t, 0, tracker.CountPeerExposes(testPeerID), "all expired exposes should be reaped")
}

func TestTrackedExposeMutexProtectsLastRenewed(t *testing.T) {
	expose := &trackedExpose{
		lastRenewed: time.Now().Add(-1 * time.Hour),
	}

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		for range 100 {
			expose.mu.Lock()
			expose.lastRenewed = time.Now()
			expose.mu.Unlock()
		}
	}()

	go func() {
		defer wg.Done()
		for range 100 {
			expose.mu.Lock()
			_ = time.Since(expose.lastRenewed)
			expose.mu.Unlock()
		}
	}()

	wg.Wait()

	expose.mu.Lock()
	require.False(t, expose.lastRenewed.IsZero(), "lastRenewed should not be zero after concurrent access")
	expose.mu.Unlock()
}
