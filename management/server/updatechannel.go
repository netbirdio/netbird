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
func (p *PeersUpdateManager) SendUpdate(peer string, update *UpdateMessage) error {
	p.channelsMux.Lock()
	defer p.channelsMux.Unlock()
	if channel, ok := p.peerChannels[peer]; ok {
		select {
		case channel <- update:
			log.Infof("update was sent to channel for peer %s", peer)
		default:
			log.Warnf("channel for peer %s is %d full", peer, len(channel))
		}
		return nil
	}
	log.Debugf("peer %s has no channel", peer)
	return nil
}

// CreateChannel creates a go channel for a given peer used to deliver updates relevant to the peer.
func (p *PeersUpdateManager) CreateChannel(peerKey string) chan *UpdateMessage {
	p.channelsMux.Lock()
	defer p.channelsMux.Unlock()

	if channel, ok := p.peerChannels[peerKey]; ok {
		delete(p.peerChannels, peerKey)
		close(channel)
	}
	//mbragin: todo shouldn't it be more? or configurable?
	channel := make(chan *UpdateMessage, channelBufferSize)
	p.peerChannels[peerKey] = channel

	log.Debugf("opened updates channel for a peer %s", peerKey)
	return channel
}

// CloseChannel closes updates channel of a given peer
func (p *PeersUpdateManager) CloseChannel(peerKey string) {
	p.channelsMux.Lock()
	defer p.channelsMux.Unlock()
	if channel, ok := p.peerChannels[peerKey]; ok {
		delete(p.peerChannels, peerKey)
		close(channel)
	}

	log.Debugf("closed updates channel of a peer %s", peerKey)
}

// GetAllConnectedPeers returns a copy of the connected peers map
func (p *PeersUpdateManager) GetAllConnectedPeers() map[string]struct{} {
	p.channelsMux.Lock()
	defer p.channelsMux.Unlock()
	m := make(map[string]struct{})
	for key := range p.peerChannels {
		m[key] = struct{}{}
	}
	return m
}
