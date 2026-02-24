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

func TestTrackExpose(t *testing.T) {
	tracker := &exposeTracker{}

	alreadyTracked := tracker.TrackExpose("peer1", "a.com", "acct1")
	assert.False(t, alreadyTracked, "first track should not be duplicate")

	alreadyTracked = tracker.TrackExpose("peer1", "a.com", "acct1")
	assert.True(t, alreadyTracked, "second track should be duplicate")
}

func TestUntrackExpose(t *testing.T) {
	tracker := &exposeTracker{}

	tracker.TrackExpose("peer1", "a.com", "acct1")
	assert.Equal(t, 1, tracker.CountPeerExposes("peer1"))

	tracker.UntrackExpose("peer1", "a.com")
	assert.Equal(t, 0, tracker.CountPeerExposes("peer1"))
}

func TestCountPeerExposes(t *testing.T) {
	tracker := &exposeTracker{}

	assert.Equal(t, 0, tracker.CountPeerExposes("peer1"))

	tracker.TrackExpose("peer1", "a.com", "acct1")
	tracker.TrackExpose("peer1", "b.com", "acct1")
	tracker.TrackExpose("peer2", "a.com", "acct1")

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

	tracker.TrackExpose("peer1", "a.com", "acct1")

	found = tracker.RenewTrackedExpose("peer1", "a.com")
	assert.True(t, found, "should find tracked expose")
}

func TestCheckPeerExposeLimitWithLock(t *testing.T) {
	tracker := &exposeTracker{}

	assert.True(t, tracker.CheckPeerExposeLimitWithLock("peer1"), "should be within limit initially")

	for i := range maxExposesPerPeer {
		tracker.TrackExpose("peer1", "domain-"+string(rune('a'+i))+".com", "acct1")
	}

	assert.False(t, tracker.CheckPeerExposeLimitWithLock("peer1"), "should be at limit")
	assert.True(t, tracker.CheckPeerExposeLimitWithLock("peer2"), "other peer should still be within limit")
}

func TestReapExpiredExposes(t *testing.T) {
	mgr, _ := setupIntegrationTest(t)
	tracker := mgr.exposeTracker

	// Create a real service so the reaper can delete it
	ctx := context.Background()
	resp, err := mgr.CreateServiceFromPeer(ctx, testAccountID, testPeerID, &reverseproxy.ExposeServiceRequest{
		Port:     8080,
		Protocol: "http",
	})
	require.NoError(t, err)

	// Track it, then manually expire the tracked entry
	tracker.TrackExpose(testPeerID, resp.Domain, testAccountID)

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

func TestConcurrentTrackAndCount(t *testing.T) {
	mgr, _ := setupIntegrationTest(t)
	tracker := mgr.exposeTracker
	ctx := context.Background()

	// Create real services so reaper can delete them
	for i := range 5 {
		resp, err := mgr.CreateServiceFromPeer(ctx, testAccountID, testPeerID, &reverseproxy.ExposeServiceRequest{
			Port:     8080 + i,
			Protocol: "http",
		})
		require.NoError(t, err)
		tracker.TrackExpose(testPeerID, resp.Domain, testAccountID)
	}

	// Manually expire all tracked entries
	tracker.activeExposes.Range(func(key, val any) bool {
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
