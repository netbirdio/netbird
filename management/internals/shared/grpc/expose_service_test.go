package grpc

import (
	"sync"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/management/internals/modules/reverseproxy"
)

func TestExposeKey(t *testing.T) {
	assert.Equal(t, "peer1:example.com", exposeKey("peer1", "example.com"))
	assert.Equal(t, "peer2:other.com", exposeKey("peer2", "other.com"))
	assert.NotEqual(t, exposeKey("peer1", "a.com"), exposeKey("peer1", "b.com"))
}

func TestCountPeerExposes(t *testing.T) {
	s := &Server{}

	// No exposes
	assert.Equal(t, 0, s.countPeerExposes("peer1"))

	// Add some exposes for different peers
	s.activeExposes.Store("peer1:a.com", &activeExpose{peerID: "peer1"})
	s.activeExposes.Store("peer1:b.com", &activeExpose{peerID: "peer1"})
	s.activeExposes.Store("peer2:a.com", &activeExpose{peerID: "peer2"})

	assert.Equal(t, 2, s.countPeerExposes("peer1"), "peer1 should have 2 exposes")
	assert.Equal(t, 1, s.countPeerExposes("peer2"), "peer2 should have 1 expose")
	assert.Equal(t, 0, s.countPeerExposes("peer3"), "peer3 should have 0 exposes")
}

func TestReapExpiredExposes(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockMgr := reverseproxy.NewMockManager(ctrl)

	s := &Server{}
	s.SetReverseProxyManager(mockMgr)

	now := time.Now()

	// Add an expired expose and a still-active one
	s.activeExposes.Store("peer1:expired.com", &activeExpose{
		serviceID:   "svc-expired",
		domain:      "expired.com",
		accountID:   "acct1",
		peerID:      "peer1",
		lastRenewed: now.Add(-2 * exposeTTL),
	})
	s.activeExposes.Store("peer1:active.com", &activeExpose{
		serviceID:   "svc-active",
		domain:      "active.com",
		accountID:   "acct1",
		peerID:      "peer1",
		lastRenewed: now,
	})

	// Expect ExpireServiceFromPeer called only for the expired one
	mockMgr.EXPECT().
		ExpireServiceFromPeer(gomock.Any(), "acct1", "peer1", "svc-expired").
		Return(nil)

	s.reapExpiredExposes()

	// Verify expired one is removed
	_, exists := s.activeExposes.Load("peer1:expired.com")
	assert.False(t, exists, "expired expose should be removed")

	// Verify active one remains
	_, exists = s.activeExposes.Load("peer1:active.com")
	assert.True(t, exists, "active expose should remain")
}

func TestCleanupExpose_Delete(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockMgr := reverseproxy.NewMockManager(ctrl)

	s := &Server{}
	s.SetReverseProxyManager(mockMgr)

	mockMgr.EXPECT().
		DeleteServiceFromPeer(gomock.Any(), "acct1", "peer1", "svc1").
		Return(nil)

	s.cleanupExpose(&activeExpose{
		serviceID: "svc1",
		accountID: "acct1",
		peerID:    "peer1",
	}, false)
}

func TestCleanupExpose_Expire(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockMgr := reverseproxy.NewMockManager(ctrl)

	s := &Server{}
	s.SetReverseProxyManager(mockMgr)

	mockMgr.EXPECT().
		ExpireServiceFromPeer(gomock.Any(), "acct1", "peer1", "svc1").
		Return(nil)

	s.cleanupExpose(&activeExpose{
		serviceID: "svc1",
		accountID: "acct1",
		peerID:    "peer1",
	}, true)
}

func TestCleanupExpose_NilManager(t *testing.T) {
	s := &Server{}
	// Should not panic when reverse proxy manager is nil
	s.cleanupExpose(&activeExpose{
		serviceID: "svc1",
		accountID: "acct1",
		peerID:    "peer1",
	}, false)
}

func TestSetReverseProxyManager(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	s := &Server{}

	// Initially nil
	assert.Nil(t, s.getReverseProxyManager())

	mockMgr := reverseproxy.NewMockManager(ctrl)
	s.SetReverseProxyManager(mockMgr)
	assert.NotNil(t, s.getReverseProxyManager())

	// Can set to nil
	s.SetReverseProxyManager(nil)
	assert.Nil(t, s.getReverseProxyManager())
}

func TestReapExpiredExposes_ConcurrentSafety(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockMgr := reverseproxy.NewMockManager(ctrl)
	mockMgr.EXPECT().
		ExpireServiceFromPeer(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
		Return(nil).
		AnyTimes()

	s := &Server{}
	s.SetReverseProxyManager(mockMgr)

	// Pre-populate with expired sessions
	for i := range 20 {
		peerID := "peer1"
		domain := "domain-" + string(rune('a'+i))
		s.activeExposes.Store(exposeKey(peerID, domain), &activeExpose{
			serviceID:   "svc-" + domain,
			domain:      domain,
			accountID:   "acct1",
			peerID:      peerID,
			lastRenewed: time.Now().Add(-2 * exposeTTL),
		})
	}

	// Run reaper concurrently with count
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		s.reapExpiredExposes()
	}()
	go func() {
		defer wg.Done()
		s.countPeerExposes("peer1")
	}()
	wg.Wait()

	assert.Equal(t, 0, s.countPeerExposes("peer1"), "all expired exposes should be reaped")
}

func TestActiveExposeMutexProtectsLastRenewed(t *testing.T) {
	expose := &activeExpose{
		lastRenewed: time.Now().Add(-1 * time.Hour),
	}

	// Simulate concurrent renew and read
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
