package manager

import (
	"context"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
)

const (
	exposeTTL          = 90 * time.Second
	exposeReapInterval = 30 * time.Second
	maxExposesPerPeer  = 10
)

type trackedExpose struct {
	mu          sync.Mutex
	domain      string
	accountID   string
	peerID      string
	lastRenewed time.Time
}

type exposeTracker struct {
	activeExposes  sync.Map
	exposeCreateMu sync.Mutex
	manager        *managerImpl
}

func exposeKey(peerID, domain string) string {
	return peerID + ":" + domain
}

// TrackExpose registers a new active expose session. Returns true if the expose
// was already tracked (duplicate).
func (t *exposeTracker) TrackExpose(peerID, domain, accountID string) bool {
	key := exposeKey(peerID, domain)
	_, loaded := t.activeExposes.LoadOrStore(key, &trackedExpose{
		domain:      domain,
		accountID:   accountID,
		peerID:      peerID,
		lastRenewed: time.Now(),
	})
	return loaded
}

// UntrackExpose removes an active expose session from tracking.
func (t *exposeTracker) UntrackExpose(peerID, domain string) {
	t.activeExposes.Delete(exposeKey(peerID, domain))
}

// CountPeerExposes returns the number of active expose sessions for a peer.
func (t *exposeTracker) CountPeerExposes(peerID string) int {
	count := 0
	t.activeExposes.Range(func(_, val any) bool {
		if expose := val.(*trackedExpose); expose.peerID == peerID {
			count++
		}
		return true
	})
	return count
}

// MaxExposesPerPeer returns the maximum number of concurrent exposes allowed per peer.
func (t *exposeTracker) MaxExposesPerPeer() int {
	return maxExposesPerPeer
}

// RenewTrackedExpose updates the in-memory lastRenewed timestamp for a tracked expose.
// Returns false if the expose is not tracked.
func (t *exposeTracker) RenewTrackedExpose(peerID, domain string) bool {
	key := exposeKey(peerID, domain)
	val, ok := t.activeExposes.Load(key)
	if !ok {
		return false
	}

	expose := val.(*trackedExpose)
	expose.mu.Lock()
	expose.lastRenewed = time.Now()
	expose.mu.Unlock()

	return true
}

// StopTrackedExpose removes an active expose session from tracking.
// Returns false if the expose was not tracked.
func (t *exposeTracker) StopTrackedExpose(peerID, domain string) bool {
	key := exposeKey(peerID, domain)
	_, ok := t.activeExposes.LoadAndDelete(key)
	return ok
}

// CheckPeerExposeLimitWithLock atomically checks whether the peer can create a new expose.
// Returns true if the peer is within the limit.
func (t *exposeTracker) CheckPeerExposeLimitWithLock(peerID string) bool {
	t.exposeCreateMu.Lock()
	defer t.exposeCreateMu.Unlock()
	return t.CountPeerExposes(peerID) < maxExposesPerPeer
}

// StartExposeReaper starts a background goroutine that reaps expired expose sessions.
func (t *exposeTracker) StartExposeReaper(ctx context.Context) {
	go func() {
		ticker := time.NewTicker(exposeReapInterval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				t.reapExpiredExposes()
			}
		}
	}()
}

func (t *exposeTracker) reapExpiredExposes() {
	t.activeExposes.Range(func(key, val any) bool {
		expose := val.(*trackedExpose)
		expose.mu.Lock()
		expired := time.Since(expose.lastRenewed) > exposeTTL
		expose.mu.Unlock()

		if expired {
			if _, deleted := t.activeExposes.LoadAndDelete(key); deleted {
				log.Infof("reaping expired expose session for peer %s, domain %s", expose.peerID, expose.domain)
				if err := t.manager.deleteServiceFromPeer(context.Background(), expose.accountID, expose.peerID, expose.domain, true); err != nil {
					log.Errorf("failed to delete expired peer-exposed service for domain %s: %v", expose.domain, err)
				}
			}
		}
		return true
	})
}
