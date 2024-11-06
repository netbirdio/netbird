package server

import (
	"context"
	"sync"
	"time"

	"github.com/google/uuid"
	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/management/proto"
	"github.com/netbirdio/netbird/management/server/telemetry"
)

const channelBufferSize = 100
const SessionIdForceOverwrite = "FORCE"

type UpdateMessage struct {
	Update     *proto.SyncResponse
	NetworkMap *NetworkMap
}

type PeerUpdateChannel struct {
	peerID    string
	sessionID string
	channel   chan *UpdateMessage
}

type PeersUpdateManager struct {
	// peerChannels is a map of peerID to the channel used to deliver updates relevant to the peer
	peerChannels map[string]*PeerUpdateChannel
	// channelsMux keeps the mutex to access peerChannels
	channelsMux *sync.RWMutex
	// metrics provides method to collect application metrics
	metrics telemetry.AppMetrics
}

// NewPeersUpdateManager returns a new instance of PeersUpdateManager
func NewPeersUpdateManager(metrics telemetry.AppMetrics) *PeersUpdateManager {
	return &PeersUpdateManager{
		peerChannels: make(map[string]*PeerUpdateChannel),
		channelsMux:  &sync.RWMutex{},
		metrics:      metrics,
	}
}

// SendUpdate sends update message to the peer's channel
func (p *PeersUpdateManager) SendUpdate(ctx context.Context, peerID string, update *UpdateMessage) {
	start := time.Now()
	var found, dropped bool

	p.channelsMux.Lock()

	defer func() {
		p.channelsMux.Unlock()
		if p.metrics != nil {
			p.metrics.UpdateChannelMetrics().CountSendUpdateDuration(time.Since(start), found, dropped)
		}
	}()

	if peerUpdates, ok := p.peerChannels[peerID]; ok {
		found = true
		select {
		case peerUpdates.channel <- update:
			log.WithContext(ctx).Debugf("update was sent to channel for peer %s", peerID)
		default:
			dropped = true
			log.WithContext(ctx).Warnf("channel for peer %s is %d full or closed", peerID, len(peerUpdates.channel))
		}
	} else {
		log.WithContext(ctx).Debugf("peer %s has no channel", peerID)
	}
}

// CreateChannel creates a go channel for a given peer used to deliver updates relevant to the peer.
func (p *PeersUpdateManager) CreateChannel(ctx context.Context, peerID string) *PeerUpdateChannel {
	start := time.Now()

	closed := false

	p.channelsMux.Lock()
	defer func() {
		p.channelsMux.Unlock()
		if p.metrics != nil {
			p.metrics.UpdateChannelMetrics().CountCreateChannelDuration(time.Since(start), closed)
		}
	}()

	if channel, ok := p.peerChannels[peerID]; ok {
		closed = true
		delete(p.peerChannels, peerID)
		close(channel.channel)
		log.WithContext(ctx).Debugf("overwriting existing channel for peer %s", peerID)
	}

	peerUpdateChannel := &PeerUpdateChannel{
		peerID:    peerID,
		sessionID: uuid.New().String(),
		// mbragin: todo shouldn't it be more? or configurable?
		channel: make(chan *UpdateMessage, channelBufferSize),
	}

	p.peerChannels[peerID] = peerUpdateChannel

	log.WithContext(ctx).Debugf("opened updates channel for a peer %s and session %s", peerID, peerUpdateChannel.sessionID)

	return peerUpdateChannel
}

func (p *PeersUpdateManager) closeChannel(ctx context.Context, peerID string, sessionID string) bool {
	if peerUpdates, ok := p.peerChannels[peerID]; ok {
		if peerUpdates.sessionID == sessionID || sessionID == SessionIdForceOverwrite {
			delete(p.peerChannels, peerID)
			close(peerUpdates.channel)
			log.WithContext(ctx).Debugf("closed updates channel of a peer %s and session %s", peerID, sessionID)
			return true
		}
		log.WithContext(ctx).Warnf("tried to close updates channel of a peer %s with session %s, but current session is %s", peerID, sessionID, peerUpdates.sessionID)
		return false
	}

	log.WithContext(ctx).Warnf("tried to close updates channel of a peer %s with session %s, but no channel found", peerID, sessionID)

	return true
}

// CloseChannels closes updates channel for each given peer
func (p *PeersUpdateManager) CloseChannels(ctx context.Context, peerIDs []string) {
	start := time.Now()

	p.channelsMux.Lock()
	defer func() {
		p.channelsMux.Unlock()
		if p.metrics != nil {
			p.metrics.UpdateChannelMetrics().CountCloseChannelsDuration(time.Since(start), len(peerIDs))
		}
	}()

	for _, id := range peerIDs {
		p.closeChannel(ctx, id, SessionIdForceOverwrite)
	}
}

// CloseChannel closes updates channel of a given peer
func (p *PeersUpdateManager) CloseChannel(ctx context.Context, peerID string, sessionID string) bool {
	start := time.Now()

	p.channelsMux.Lock()
	defer func() {
		p.channelsMux.Unlock()
		if p.metrics != nil {
			p.metrics.UpdateChannelMetrics().CountCloseChannelDuration(time.Since(start))
		}
	}()

	return p.closeChannel(ctx, peerID, sessionID)
}

// GetAllConnectedPeers returns a copy of the connected peers map
func (p *PeersUpdateManager) GetAllConnectedPeers() map[string]struct{} {
	start := time.Now()

	p.channelsMux.Lock()

	m := make(map[string]struct{})

	defer func() {
		p.channelsMux.Unlock()
		if p.metrics != nil {
			p.metrics.UpdateChannelMetrics().CountGetAllConnectedPeersDuration(time.Since(start), len(m))
		}
	}()

	for ID := range p.peerChannels {
		m[ID] = struct{}{}
	}

	return m
}

// HasChannel returns true if peers has channel in update manager, otherwise false
func (p *PeersUpdateManager) HasChannel(peerID string) bool {
	start := time.Now()

	p.channelsMux.Lock()

	defer func() {
		p.channelsMux.Unlock()
		if p.metrics != nil {
			p.metrics.UpdateChannelMetrics().CountHasChannelDuration(time.Since(start))
		}
	}()

	_, ok := p.peerChannels[peerID]

	return ok
}
