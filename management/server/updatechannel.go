package server

import (
	"context"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/management/server/telemetry"
	"github.com/netbirdio/netbird/shared/management/proto"
)

const channelBufferSize = 100

type UpdateChannel struct {
	Important  chan *UpdateMessage
	NetworkMap *UpdateBuffer
}

func NewUpdateChannel(metrics *telemetry.UpdateChannelMetrics) *UpdateChannel {
	channel := make(chan *UpdateMessage, channelBufferSize)
	buffer := NewUpdateBuffer(metrics)

	return &UpdateChannel{
		Important:  channel,
		NetworkMap: buffer,
	}
}

func (u *UpdateChannel) Close() {
	close(u.Important)
	u.NetworkMap.Close()
}

type UpdateMessage struct {
	Update *proto.SyncResponse
}

type PeersUpdateManager struct {
	// peerChannels is an update channel indexed by Peer.ID
	peerChannels map[string]*UpdateChannel
	// channelsMux keeps the mutex to access peerChannels
	channelsMux *sync.RWMutex
	// metrics provides method to collect application metrics
	metrics telemetry.AppMetrics
}

// NewPeersUpdateManager returns a new instance of PeersUpdateManager
func NewPeersUpdateManager(metrics telemetry.AppMetrics) *PeersUpdateManager {
	return &PeersUpdateManager{
		peerChannels: make(map[string]*UpdateChannel),
		channelsMux:  &sync.RWMutex{},
		metrics:      metrics,
	}
}

// SendImportantUpdate sends update message to the peer that needs to be received
func (p *PeersUpdateManager) SendImportantUpdate(ctx context.Context, peerID string, update *UpdateMessage) {
	start := time.Now()
	var found, dropped bool

	p.channelsMux.RLock()

	defer func() {
		p.channelsMux.RUnlock()
		if p.metrics != nil {
			p.metrics.UpdateChannelMetrics().CountSendUpdateDuration(time.Since(start), found, dropped)
		}
	}()

	if channel, ok := p.peerChannels[peerID]; ok {
		found = true
		select {
		case channel.Important <- update:
			log.WithContext(ctx).Debugf("update was sent to important channel for peer %s", peerID)
		default:
			dropped = true
			log.WithContext(ctx).Warnf("important channel for peer %s is %d full or closed", peerID, len(channel.Important))
		}
	} else {
		log.WithContext(ctx).Debugf("peer %s has no important channel", peerID)
	}
}

// SendNetworkMapUpdate sends a network map update to the peer's channel
func (p *PeersUpdateManager) SendNetworkMapUpdate(ctx context.Context, peerID string, update *UpdateMessage) {
	start := time.Now()
	var found, dropped bool

	p.channelsMux.RLock()

	defer func() {
		p.channelsMux.RUnlock()
		if p.metrics != nil {
			p.metrics.UpdateChannelMetrics().CountSendUpdateDuration(time.Since(start), found, dropped)
		}
	}()

	if channel, ok := p.peerChannels[peerID]; ok {
		found = true
		channel.NetworkMap.Push(update)
		log.WithContext(ctx).Debugf("update was sent to network map buffer for peer %s", peerID)
	} else {
		log.WithContext(ctx).Debugf("peer %s has no network map buffer", peerID)
	}
}

// CreateChannel creates a go channel for a given peer used to deliver updates relevant to the peer.
func (p *PeersUpdateManager) CreateChannel(ctx context.Context, peerID string) *UpdateChannel {
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
		channel.Close()
	}

	newChannel := NewUpdateChannel(p.metrics.UpdateChannelMetrics())
	p.peerChannels[peerID] = newChannel

	log.WithContext(ctx).Debugf("opened updates channel for a peer %s", peerID)

	return newChannel
}

func (p *PeersUpdateManager) closeChannel(ctx context.Context, peerID string) {
	if channel, ok := p.peerChannels[peerID]; ok {
		delete(p.peerChannels, peerID)
		channel.Close()

		log.WithContext(ctx).Debugf("closed updates channel of a peer %s", peerID)
		return
	}

	log.WithContext(ctx).Debugf("closing updates channel: peer %s has no channel", peerID)
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
		p.closeChannel(ctx, id)
	}
}

// CloseChannel closes updates channel of a given peer
func (p *PeersUpdateManager) CloseChannel(ctx context.Context, peerID string) {
	start := time.Now()

	p.channelsMux.Lock()
	defer func() {
		p.channelsMux.Unlock()
		if p.metrics != nil {
			p.metrics.UpdateChannelMetrics().CountCloseChannelDuration(time.Since(start))
		}
	}()

	p.closeChannel(ctx, peerID)
}

// GetAllConnectedPeers returns a copy of the connected peers map
func (p *PeersUpdateManager) GetAllConnectedPeers() map[string]struct{} {
	start := time.Now()

	p.channelsMux.RLock()

	m := make(map[string]struct{})

	defer func() {
		p.channelsMux.RUnlock()
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

	p.channelsMux.RLock()

	defer func() {
		p.channelsMux.RUnlock()
		if p.metrics != nil {
			p.metrics.UpdateChannelMetrics().CountHasChannelDuration(time.Since(start))
		}
	}()

	_, ok := p.peerChannels[peerID]

	return ok
}

// GetChannelCount returns the number of active peer channels
func (p *PeersUpdateManager) GetChannelCount() int {
	p.channelsMux.RLock()
	defer p.channelsMux.RUnlock()
	return len(p.peerChannels)
}
