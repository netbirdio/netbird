package client

import (
	"context"
	"errors"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/relay/messages"
)

const (
	OpenConnectionTimeout = 30 * time.Second
)

type relayedConnWriter interface {
	Write(p []byte) (n int, err error)
}

type PeersStateSubscription struct {
	log             *log.Entry
	relayConn       relayedConnWriter
	offlineCallback func(peerIDs []messages.PeerID)

	listenForOfflinePeers map[messages.PeerID]struct{}
	waitingPeers          map[messages.PeerID]chan struct{}
}

func NewPeersStateSubscription(log *log.Entry, relayConn relayedConnWriter, offlineCallback func(peerIDs []messages.PeerID)) *PeersStateSubscription {
	return &PeersStateSubscription{
		log:                   log,
		relayConn:             relayConn,
		offlineCallback:       offlineCallback,
		listenForOfflinePeers: make(map[messages.PeerID]struct{}),
		waitingPeers:          make(map[messages.PeerID]chan struct{}),
	}
}

func (s *PeersStateSubscription) OnPeersOnline(peersID []messages.PeerID) {
	for _, peerID := range peersID {
		waitCh, ok := s.waitingPeers[peerID]
		if !ok {
			continue
		}

		close(waitCh)
		delete(s.waitingPeers, peerID)
	}
}

func (s *PeersStateSubscription) OnPeersWentOffline(peersID []messages.PeerID) {
	relevantPeers := make([]messages.PeerID, 0, len(peersID))
	for _, peerID := range peersID {
		if _, ok := s.listenForOfflinePeers[peerID]; ok {
			relevantPeers = append(relevantPeers, peerID)
		}
	}

	if len(relevantPeers) > 0 {
		s.offlineCallback(relevantPeers)
	}
}

// WaitToBeOnlineAndSubscribe
// todo: when we unsubscribe while this is running, this will not return with error
// todo: unsubscribe should be called in case of error or context cancellation
func (s *PeersStateSubscription) WaitToBeOnlineAndSubscribe(ctx context.Context, peerID messages.PeerID) error {
	// Check if already waiting for this peer
	if _, exists := s.waitingPeers[peerID]; exists {
		return errors.New("already waiting for peer to come online")
	}

	// Create a channel to wait for the peer to come online
	waitCh := make(chan struct{}, 0)
	s.waitingPeers[peerID] = waitCh

	if err := s.subscribeStateChange([]messages.PeerID{peerID}); err != nil {
		s.log.Errorf("failed to subscribe to peer state: %s", err)
		close(waitCh)
		delete(s.waitingPeers, peerID)
		return err
	}

	defer func() {
		if ch, exists := s.waitingPeers[peerID]; exists && ch == waitCh {
			close(waitCh)
			delete(s.waitingPeers, peerID)
		}
	}()

	log.Debugf("peer %s wait for ", peerID)
	// Wait for peer to come online or context to be cancelled
	timeoutCtx, cancel := context.WithTimeout(ctx, OpenConnectionTimeout)
	defer cancel()
	select {
	case <-waitCh:
		s.log.Debugf("peer %s is now online", peerID)
		return nil
	case <-timeoutCtx.Done():
		s.log.Debugf("context timed out while waiting for peer %s to come online", peerID)
		return ctx.Err()
	}
}

func (s *PeersStateSubscription) UnsubscribeStateChange(peerIDs []messages.PeerID) error {
	msgs, err := messages.MarshalUnsubPeerStateMsg(peerIDs)
	if err != nil {
		return err
	}

	var connWriteErr error
	for _, msg := range msgs {
		_, connWriteErr = s.relayConn.Write(msg)
	}

	for _, peerID := range peerIDs {
		if wch, ok := s.waitingPeers[peerID]; ok {
			close(wch)
			delete(s.waitingPeers, peerID)
		}

		delete(s.listenForOfflinePeers, peerID)
	}

	return connWriteErr
}

func (s *PeersStateSubscription) subscribeStateChange(peerIDs []messages.PeerID) error {
	msgs, err := messages.MarshalSubPeerStateMsg(peerIDs)
	if err != nil {
		return err
	}

	for _, peer := range peerIDs {
		s.listenForOfflinePeers[peer] = struct{}{}
	}

	for _, msg := range msgs {
		if _, err := s.relayConn.Write(msg); err != nil {
			return err
		}

	}
	return nil
}

func (s *PeersStateSubscription) Cleanup() {
	for _, waitCh := range s.waitingPeers {
		close(waitCh)
	}

	s.waitingPeers = make(map[messages.PeerID]chan struct{})
	s.listenForOfflinePeers = make(map[messages.PeerID]struct{})
}
