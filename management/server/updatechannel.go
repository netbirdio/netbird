package server

import (
	log "github.com/sirupsen/logrus"
	"github.com/wiretrustee/wiretrustee/management/proto"
	"sync"
)

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
		channel <- update
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
	channel := make(chan *UpdateMessage, 100)
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
