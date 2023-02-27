package server

import (
	"github.com/netbirdio/netbird/management/proto"
	log "github.com/sirupsen/logrus"
	"sync"
)

const channelBufferSize = 100

type UpdateMessage struct {
	Update *proto.SyncResponse
}

type PeersUpdateManager struct {
	// peerChannels is an update channel indexed by Peer.ID
	peerChannels map[string]chan *UpdateMessage
	channelsMux  *sync.Mutex
}

// NewPeersUpdateManager returns a new instance of PeersUpdateManager
func NewPeersUpdateManager() *PeersUpdateManager {
	return &PeersUpdateManager{
		peerChannels: make(map[string]chan *UpdateMessage),
		channelsMux:  &sync.Mutex{},
	}
}

// SendUpdate sends update message to the peer's channel
func (p *PeersUpdateManager) SendUpdate(peerID string, update *UpdateMessage) error {
	p.channelsMux.Lock()
	defer p.channelsMux.Unlock()
	if channel, ok := p.peerChannels[peerID]; ok {
		select {
		case channel <- update:
			log.Infof("update was sent to channel for peer %s", peerID)
		default:
			log.Warnf("channel for peer %s is %d full", peerID, len(channel))
		}
		return nil
	}
	log.Debugf("peer %s has no channel", peerID)
	return nil
}

// CreateChannel creates a go channel for a given peer used to deliver updates relevant to the peer.
func (p *PeersUpdateManager) CreateChannel(peerID string) chan *UpdateMessage {
	p.channelsMux.Lock()
	defer p.channelsMux.Unlock()

	if channel, ok := p.peerChannels[peerID]; ok {
		delete(p.peerChannels, peerID)
		close(channel)
	}
	//mbragin: todo shouldn't it be more? or configurable?
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
	p.channelsMux.Lock()
	defer p.channelsMux.Unlock()
	for _, id := range peerIDs {
		p.closeChannel(id)
	}
}

// CloseChannel closes updates channel of a given peer
func (p *PeersUpdateManager) CloseChannel(peerID string) {
	p.channelsMux.Lock()
	defer p.channelsMux.Unlock()
	p.closeChannel(peerID)
}

// GetAllConnectedPeers returns a copy of the connected peers map
func (p *PeersUpdateManager) GetAllConnectedPeers() map[string]struct{} {
	p.channelsMux.Lock()
	defer p.channelsMux.Unlock()
	m := make(map[string]struct{})
	for ID := range p.peerChannels {
		m[ID] = struct{}{}
	}
	return m
}
