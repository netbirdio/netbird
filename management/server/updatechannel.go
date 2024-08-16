package server

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/netbirdio/netbird/management/server/differs"
	"github.com/netbirdio/netbird/management/server/posture"
	"github.com/r3labs/diff"
	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/management/proto"
	"github.com/netbirdio/netbird/management/server/telemetry"
)

const channelBufferSize = 100

type UpdateMessage struct {
	Update     *proto.SyncResponse
	NetworkMap *NetworkMap
	Checks     []*posture.Checks
}

type PeersUpdateManager struct {
	// peerChannels is an update channel indexed by Peer.ID
	peerChannels map[string]chan *UpdateMessage
	// peerNetworkMaps is the UpdateMessage indexed by Peer.ID.
	peerUpdateMessage map[string]*UpdateMessage
	// channelsMux keeps the mutex to access peerChannels
	channelsMux *sync.RWMutex
	// metrics provides method to collect application metrics
	metrics telemetry.AppMetrics
}

// NewPeersUpdateManager returns a new instance of PeersUpdateManager
func NewPeersUpdateManager(metrics telemetry.AppMetrics) *PeersUpdateManager {
	return &PeersUpdateManager{
		peerChannels:      make(map[string]chan *UpdateMessage),
		peerUpdateMessage: make(map[string]*UpdateMessage),
		channelsMux:       &sync.RWMutex{},
		metrics:           metrics,
	}
}

// SendUpdate sends update message to the peer's channel
func (p *PeersUpdateManager) SendUpdate(ctx context.Context, peerID string, update *UpdateMessage) {
	start := time.Now()
	var found, dropped bool

	// skip sending sync update to the peer if there is no change in update message,
	// it will not check on turn credential refresh as we do not send network map or client posture checks
	if update.NetworkMap != nil {
		updated := p.handlePeerMessageUpdate(ctx, peerID, update)
		if !updated {
			return
		}
	}

	p.channelsMux.Lock()

	defer func() {
		p.channelsMux.Unlock()
		if p.metrics != nil {
			p.metrics.UpdateChannelMetrics().CountSendUpdateDuration(time.Since(start), found, dropped)
		}
	}()

	if update.NetworkMap != nil {
		lastSentUpdate := p.peerUpdateMessage[peerID]
		if lastSentUpdate != nil && lastSentUpdate.Update.NetworkMap.GetSerial() >= update.Update.NetworkMap.GetSerial() {
			log.WithContext(ctx).Debugf("peer %s new network map serial: %d not greater than last sent: %d, skip sending update",
				peerID, update.Update.NetworkMap.GetSerial(), lastSentUpdate.Update.NetworkMap.GetSerial())
			return
		}
		p.peerUpdateMessage[peerID] = update
	}

	if channel, ok := p.peerChannels[peerID]; ok {
		found = true
		select {
		case channel <- update:
			log.WithContext(ctx).Debugf("update was sent to channel for peer %s", peerID)
		default:
			dropped = true
			log.WithContext(ctx).Warnf("channel for peer %s is %d full", peerID, len(channel))
		}
	} else {
		log.WithContext(ctx).Debugf("peer %s has no channel", peerID)
	}
}

// CreateChannel creates a go channel for a given peer used to deliver updates relevant to the peer.
func (p *PeersUpdateManager) CreateChannel(ctx context.Context, peerID string) chan *UpdateMessage {
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
		delete(p.peerUpdateMessage, peerID)
	}
	// mbragin: todo shouldn't it be more? or configurable?
	channel := make(chan *UpdateMessage, channelBufferSize)
	p.peerChannels[peerID] = channel

	log.WithContext(ctx).Debugf("opened updates channel for a peer %s", peerID)

	return channel
}

func (p *PeersUpdateManager) closeChannel(ctx context.Context, peerID string) {
	if channel, ok := p.peerChannels[peerID]; ok {
		delete(p.peerChannels, peerID)
		close(channel)
		delete(p.peerUpdateMessage, peerID)
	}

	log.WithContext(ctx).Debugf("closed updates channel of a peer %s", peerID)
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

// handlePeerMessageUpdate checks if the update message for a peer is new and should be sent.
func (p *PeersUpdateManager) handlePeerMessageUpdate(ctx context.Context, peerID string, update *UpdateMessage) bool {
	p.channelsMux.RLock()
	lastSentUpdate := p.peerUpdateMessage[peerID]
	p.channelsMux.RUnlock()

	if lastSentUpdate != nil {
		updated, err := isNewPeerUpdateMessage(lastSentUpdate, update)
		if err != nil {
			log.WithContext(ctx).Errorf("error checking for SyncResponse updates: %v", err)
			return false
		}
		if !updated {
			log.WithContext(ctx).Debugf("peer %s network map is not updated, skip sending update", peerID)
			return false
		}
	}

	return true
}

// isNewPeerUpdateMessage checks if the given current update message is a new update that should be sent.
func isNewPeerUpdateMessage(lastSentUpdate, currUpdateToSend *UpdateMessage) (bool, error) {
	if lastSentUpdate.Update.NetworkMap.GetSerial() >= currUpdateToSend.Update.NetworkMap.GetSerial() {
		return false, nil
	}

	changelog, err := diff.Diff(lastSentUpdate.Checks, currUpdateToSend.Checks)
	if err != nil {
		return false, fmt.Errorf("failed to diff checks: %v", err)
	}
	if len(changelog) > 0 {
		return true, nil
	}

	differ, err := diff.NewDiffer(
		diff.CustomValueDiffers(differs.NewNameServerComparator(), differs.NewRouteComparator()),
	)
	if err != nil {
		return false, err
	}

	changelog, err = differ.Diff(lastSentUpdate.NetworkMap, currUpdateToSend.NetworkMap)
	if err != nil {
		return false, fmt.Errorf("failed to diff network map: %v", err)
	}
	return len(changelog) > 0, nil
}
