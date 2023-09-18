package server

import (
	"fmt"
	"sync"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/management/proto"
)

const channelBufferSize = 100

type UpdateMessage struct {
	Update *proto.SyncResponse
}

type UpdateChannel chan *UpdateMessage

type PeersUpdateManager struct {
	// peerChannels is an update channel indexed by Peer.ID
	peerChannels sync.Map
}

// NewPeersUpdateManager returns a new instance of PeersUpdateManager
func NewPeersUpdateManager() *PeersUpdateManager {
	return &PeersUpdateManager{}
}

// SendUpdate sends update message to the peer's channel
func (p *PeersUpdateManager) SendUpdate(peerID string, update *UpdateMessage) error {
	if ch, ok := p.peerChannels.Load(peerID); ok {
		channel, ok := ch.(UpdateChannel)
		if !ok {
			return fmt.Errorf("could not cast to UpdateChannel")
		}
		select {
		case channel <- update:
			log.Debugf("update was sent to channel for peer %s", peerID)
		default:
			log.Warnf("channel for peer %s is %d full", peerID, len(channel))
		}
		return nil
	}
	log.Debugf("peer %s has no channel", peerID)
	return nil
}

// CreateChannel creates a go channel for a given peer used to deliver updates relevant to the peer.
func (p *PeersUpdateManager) CreateChannel(peerID string) UpdateChannel {
	p.closeChannel(peerID)

	// mbragin: todo shouldn't it be more? or configurable?
	channel := make(UpdateChannel, channelBufferSize)
	p.peerChannels.Store(peerID, channel)

	log.Debugf("opened updates channel for a peer %s", peerID)
	return channel
}

func (p *PeersUpdateManager) GetChannel(peerID string) UpdateChannel {
	if ch, ok := p.peerChannels.Load(peerID); ok {
		channel := ch.(UpdateChannel)
		return channel
	}
	return nil
}

func (p *PeersUpdateManager) closeChannel(peerID string) {
	if ch, ok := p.peerChannels.LoadAndDelete(peerID); ok {
		channel, ok := ch.(UpdateChannel)
		if !ok {
			log.Errorf("could not cast to chan *UpdateMessage")
		}
		close(channel)
		log.Debugf("closed updates channel of a peer %s", peerID)
	}
}

// CloseChannels closes updates channel for each given peer
func (p *PeersUpdateManager) CloseChannels(peerIDs []string) {
	for _, id := range peerIDs {
		p.closeChannel(id)
	}
}

// CloseChannel closes updates channel of a given peer
func (p *PeersUpdateManager) CloseChannel(peerID string) {
	p.closeChannel(peerID)
}

// GetAllConnectedPeers returns a copy of the connected peers map
func (p *PeersUpdateManager) GetAllConnectedPeers() map[string]struct{} {
	m := make(map[string]struct{})
	p.peerChannels.Range(func(key any, value any) bool {
		if ID, ok := key.(string); ok {
			m[ID] = struct{}{}
		}
		return true
	})
	return m
}

// Len returns the length of the peer channels
func (p *PeersUpdateManager) Len() (len int64) {
	p.peerChannels.Range(func(key any, value any) bool {
		len++
		return true
	})
	return len
}
