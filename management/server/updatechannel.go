package server

import (
	"context"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/management/server/telemetry"
	"github.com/netbirdio/netbird/shared/management/proto"
)

type UpdateMessage struct {
	Update *proto.SyncResponse
}

type peerUpdate struct {
	mu      sync.Mutex
	message *UpdateMessage
	notify  chan struct{}
}

type PeersUpdateManager struct {
	// latestUpdates stores the latest update message per peer
	latestUpdates sync.Map // map[string]*peerUpdate
	// activePeers tracks which peers have active sender goroutines
	activePeers sync.Map // map[string]struct{}
	// metrics provides method to collect application metrics
	metrics telemetry.AppMetrics
}

// NewPeersUpdateManager returns a new instance of PeersUpdateManager
func NewPeersUpdateManager(metrics telemetry.AppMetrics) *PeersUpdateManager {
	return &PeersUpdateManager{
		metrics: metrics,
	}
}

// SendUpdate stores the latest update message for a peer and notifies the sender goroutine
func (p *PeersUpdateManager) SendUpdate(ctx context.Context, peerID string, update *UpdateMessage) {
	start := time.Now()
	var found, dropped bool

	defer func() {
		if p.metrics != nil {
			p.metrics.UpdateChannelMetrics().CountSendUpdateDuration(time.Since(start), found, dropped)
		}
	}()

	// Check if peer has an active sender goroutine
	if _, ok := p.activePeers.Load(peerID); !ok {
		log.WithContext(ctx).Debugf("peer %s has no active sender", peerID)
		return
	}

	found = true

	// Load or create peerUpdate entry
	val, _ := p.latestUpdates.LoadOrStore(peerID, &peerUpdate{
		notify: make(chan struct{}, 1),
	})

	pu := val.(*peerUpdate)

	// Store the latest message (overwrites any previous unsent message)
	pu.mu.Lock()
	pu.message = update
	pu.mu.Unlock()

	// Non-blocking notification
	select {
	case pu.notify <- struct{}{}:
		log.WithContext(ctx).Debugf("update notification sent for peer %s", peerID)
	default:
		// Already notified, sender will pick up the latest message anyway
		log.WithContext(ctx).Tracef("peer %s already notified, update will be picked up", peerID)
	}
}

// CreateChannel creates a sender goroutine for a given peer and returns a channel to receive updates
func (p *PeersUpdateManager) CreateChannel(ctx context.Context, peerID string) chan *UpdateMessage {
	start := time.Now()

	closed := false

	defer func() {
		if p.metrics != nil {
			p.metrics.UpdateChannelMetrics().CountCreateChannelDuration(time.Since(start), closed)
		}
	}()

	// Close existing sender if any
	if _, exists := p.activePeers.LoadOrStore(peerID, struct{}{}); exists {
		closed = true
		p.closeChannel(ctx, peerID)
	}

	// Create peerUpdate entry with notification channel
	pu := &peerUpdate{
		notify: make(chan struct{}, 1),
	}
	p.latestUpdates.Store(peerID, pu)

	// Create output channel for consumer
	outChan := make(chan *UpdateMessage, 1)

	// Start sender goroutine
	go func() {
		defer close(outChan)
		for {
			select {
			case <-ctx.Done():
				log.WithContext(ctx).Debugf("sender goroutine for peer %s stopped due to context cancellation", peerID)
				return
			case <-pu.notify:
				// Check if still active
				if _, ok := p.activePeers.Load(peerID); !ok {
					log.WithContext(ctx).Debugf("sender goroutine for peer %s stopped", peerID)
					return
				}

				// Get the latest message with mutex protection
				pu.mu.Lock()
				msg := pu.message
				pu.message = nil // Clear after reading
				pu.mu.Unlock()

				if msg != nil {
					select {
					case outChan <- msg:
						log.WithContext(ctx).Tracef("sent update to peer %s", peerID)
					case <-ctx.Done():
						return
					}
				}
			}
		}
	}()

	log.WithContext(ctx).Debugf("created sender goroutine for peer %s", peerID)

	return outChan
}

func (p *PeersUpdateManager) closeChannel(ctx context.Context, peerID string) {
	// Mark peer as inactive to stop the sender goroutine
	if _, ok := p.activePeers.LoadAndDelete(peerID); ok {
		// Close notification channel
		if val, ok := p.latestUpdates.Load(peerID); ok {
			pu := val.(*peerUpdate)
			close(pu.notify)
		}
		p.latestUpdates.Delete(peerID)
		log.WithContext(ctx).Debugf("closed sender for peer %s", peerID)
		return
	}

	log.WithContext(ctx).Debugf("closing sender: peer %s has no active sender", peerID)
}

// CloseChannels closes sender goroutines for each given peer
func (p *PeersUpdateManager) CloseChannels(ctx context.Context, peerIDs []string) {
	start := time.Now()

	defer func() {
		if p.metrics != nil {
			p.metrics.UpdateChannelMetrics().CountCloseChannelsDuration(time.Since(start), len(peerIDs))
		}
	}()

	for _, id := range peerIDs {
		p.closeChannel(ctx, id)
	}
}

// CloseChannel closes the sender goroutine of a given peer
func (p *PeersUpdateManager) CloseChannel(ctx context.Context, peerID string) {
	start := time.Now()

	defer func() {
		if p.metrics != nil {
			p.metrics.UpdateChannelMetrics().CountCloseChannelDuration(time.Since(start))
		}
	}()

	p.closeChannel(ctx, peerID)
}

// GetAllConnectedPeers returns a copy of the connected peers map
func (p *PeersUpdateManager) GetAllConnectedPeers() map[string]struct{} {
	start := time.Now()

	m := make(map[string]struct{})

	defer func() {
		if p.metrics != nil {
			p.metrics.UpdateChannelMetrics().CountGetAllConnectedPeersDuration(time.Since(start), len(m))
		}
	}()

	p.activePeers.Range(func(key, value interface{}) bool {
		m[key.(string)] = struct{}{}
		return true
	})

	return m
}

// HasChannel returns true if peer has an active sender goroutine, otherwise false
func (p *PeersUpdateManager) HasChannel(peerID string) bool {
	start := time.Now()

	defer func() {
		if p.metrics != nil {
			p.metrics.UpdateChannelMetrics().CountHasChannelDuration(time.Since(start))
		}
	}()

	_, ok := p.activePeers.Load(peerID)

	return ok
}

// GetChannelCount returns the number of active peer channels
func (p *PeersUpdateManager) GetChannelCount() int {
	count := 0
	p.activePeers.Range(func(key, value interface{}) bool {
		count++
		return true
	})
	return count
}
