package manager

import (
	"context"
	"sync"
	"time"

	"github.com/netbirdio/netbird/shared/management/status"
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
	expiring    bool
}

type exposeTracker struct {
	activeExposes  sync.Map
	exposeCreateMu sync.Mutex
	manager        *managerImpl
}

func exposeKey(peerID, domain string) string {
	return peerID + ":" + domain
}

// TrackExposeIfAllowed atomically checks the per-peer limit and registers a new
// active expose session under the same lock. Returns (true, false) if the expose
// was already tracked (duplicate), (false, true) if tracking succeeded, and
// (false, false) if the peer has reached the limit.
func (t *exposeTracker) TrackExposeIfAllowed(peerID, domain, accountID string) (alreadyTracked, ok bool) {
	t.exposeCreateMu.Lock()
	defer t.exposeCreateMu.Unlock()

	key := exposeKey(peerID, domain)
	_, loaded := t.activeExposes.LoadOrStore(key, &trackedExpose{
		domain:      domain,
		accountID:   accountID,
		peerID:      peerID,
		lastRenewed: time.Now(),
	})
	if loaded {
		return true, false
	}

	if t.CountPeerExposes(peerID) > maxExposesPerPeer {
		t.activeExposes.Delete(key)
		return false, false
	}

	return false, true
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
// Returns false if the expose is not tracked or is being reaped.
func (t *exposeTracker) RenewTrackedExpose(peerID, domain string) bool {
	key := exposeKey(peerID, domain)
	val, ok := t.activeExposes.Load(key)
	if !ok {
		return false
	}

	expose := val.(*trackedExpose)
	expose.mu.Lock()
	if expose.expiring {
		expose.mu.Unlock()
		return false
	}
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
		if expired {
			expose.expiring = true
		}
		expose.mu.Unlock()

		if !expired {
			return true
		}

		log.Infof("reaping expired expose session for peer %s, domain %s", expose.peerID, expose.domain)

		err := t.manager.deleteServiceFromPeer(context.Background(), expose.accountID, expose.peerID, expose.domain, true)

		s, _ := status.FromError(err)

		switch {
		case err == nil:
			t.activeExposes.Delete(key)
		case s.ErrorType == status.NotFound:
			log.Debugf("service %s was already deleted", expose.domain)
		default:
			log.Errorf("failed to delete expired peer-exposed service for domain %s: %v", expose.domain, err)
		}

		return true
	})
}
