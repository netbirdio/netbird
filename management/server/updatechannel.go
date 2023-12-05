package server

import (
	"sync"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/management/proto"
	"github.com/netbirdio/netbird/management/server/telemetry"
)

const channelBufferSize = 100

type UpdateMessage struct {
	Update *proto.SyncResponse
}

type PeersUpdateManager struct {
	// peerChannels is an update channel indexed by Peer.ID
	peerChannels map[string]chan *UpdateMessage
	// channelsMux keeps the mutex to access peerChannels
	channelsMux *sync.Mutex
	// metrics provides method to collect application metrics
	metrics telemetry.AppMetrics
}

// NewPeersUpdateManager returns a new instance of PeersUpdateManager
func NewPeersUpdateManager(metrics telemetry.AppMetrics) *PeersUpdateManager {
	return &PeersUpdateManager{
		peerChannels: make(map[string]chan *UpdateMessage),
		channelsMux:  &sync.Mutex{},
		metrics:      metrics,
	}
}

// SendUpdate sends update message to the peer's channel
func (p *PeersUpdateManager) SendUpdate(peerID string, update *UpdateMessage) {
	start := time.Now()
	var found, dropped bool

	p.channelsMux.Lock()
	defer func() {
		p.channelsMux.Unlock()
		if p.metrics != nil {
			p.metrics.UpdateChannelMetrics().CountSendUpdateDuration(time.Since(start), found, dropped)
		}
	}()

	if channel, ok := p.peerChannels[peerID]; ok {
		found = true
		select {
		case channel <- update:
			log.Debugf("update was sent to channel for peer %s", peerID)
		default:
			dropped = true
			log.Warnf("channel for peer %s is %d full", peerID, len(channel))
		}
	} else {
		log.Debugf("peer %s has no channel", peerID)
	}
}

// CreateChannel creates a go channel for a given peer used to deliver updates relevant to the peer.
func (p *PeersUpdateManager) CreateChannel(peerID string) chan *UpdateMessage {
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
		close(channel)
	}
	// mbragin: todo shouldn't it be more? or configurable?
	channel := make(chan *UpdateMessage, channelBufferSize)
	p.peerChannels[peerID] = channel

	log.Debugf("opened updates channel for a peer %s", peerID)

	return channel
}

func (p *PeersUpdateManager) closeChannel(peerID string) {
	if channel, ok := p.peerChannels[peerID]; ok {
		delete(p.peerChannels, peerID)
		close(channel)
	}

	log.Debugf("closed updates channel of a peer %s", peerID)
}

// CloseChannels closes updates channel for each given peer
func (p *PeersUpdateManager) CloseChannels(peerIDs []string) {
	start := time.Now()

	p.channelsMux.Lock()
	defer func() {
		p.channelsMux.Unlock()
		if p.metrics != nil {
			p.metrics.UpdateChannelMetrics().CountCloseChannelsDuration(time.Since(start), len(peerIDs))
		}
	}()

	for _, id := range peerIDs {
		p.closeChannel(id)
	}
}

// CloseChannel closes updates channel of a given peer
func (p *PeersUpdateManager) CloseChannel(peerID string) {
	start := time.Now()

	p.channelsMux.Lock()
	defer func() {
		p.channelsMux.Unlock()
		if p.metrics != nil {
			p.metrics.UpdateChannelMetrics().CountCloseChannelDuration(time.Since(start))
		}
	}()

	p.closeChannel(peerID)
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
