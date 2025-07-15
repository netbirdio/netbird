package client

import (
	"context"
	"errors"
	"fmt"
	"sync"
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

// PeersStateSubscription manages subscriptions to peer state changes (online/offline)
// over a relay connection. It allows tracking peers' availability and handling offline
// events via a callback. We get online notification from the server only once.
type PeersStateSubscription struct {
	log             *log.Entry
	relayConn       relayedConnWriter
	offlineCallback func(peerIDs []messages.PeerID)

	listenForOfflinePeers map[messages.PeerID]struct{}
	waitingPeers          map[messages.PeerID]chan struct{}
	mu                    sync.Mutex // Mutex to protect access to waitingPeers and listenForOfflinePeers
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

// OnPeersOnline should be called when a notification is received that certain peers have come online.
// It checks if any of the peers are being waited on and signals their availability.
func (s *PeersStateSubscription) OnPeersOnline(peersID []messages.PeerID) {
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, peerID := range peersID {
		waitCh, ok := s.waitingPeers[peerID]
		if !ok {
			// If meanwhile the peer was unsubscribed, we don't need to signal it
			continue
		}

		waitCh <- struct{}{}
		delete(s.waitingPeers, peerID)
		close(waitCh)
	}
}

func (s *PeersStateSubscription) OnPeersWentOffline(peersID []messages.PeerID) {
	s.mu.Lock()
	relevantPeers := make([]messages.PeerID, 0, len(peersID))
	for _, peerID := range peersID {
		if _, ok := s.listenForOfflinePeers[peerID]; ok {
			relevantPeers = append(relevantPeers, peerID)
		}
	}
	s.mu.Unlock()

	if len(relevantPeers) > 0 {
		s.offlineCallback(relevantPeers)
	}
}

// WaitToBeOnlineAndSubscribe waits for a specific peer to come online and subscribes to its state changes.
func (s *PeersStateSubscription) WaitToBeOnlineAndSubscribe(ctx context.Context, peerID messages.PeerID) error {
	// Check if already waiting for this peer
	s.mu.Lock()
	if _, exists := s.waitingPeers[peerID]; exists {
		s.mu.Unlock()
		return errors.New("already waiting for peer to come online")
	}

	// Create a channel to wait for the peer to come online
	waitCh := make(chan struct{}, 1)
	s.waitingPeers[peerID] = waitCh
	s.mu.Unlock()

	if err := s.subscribeStateChange([]messages.PeerID{peerID}); err != nil {
		s.log.Errorf("failed to subscribe to peer state: %s", err)
		s.mu.Lock()
		if ch, exists := s.waitingPeers[peerID]; exists && ch == waitCh {
			close(waitCh)
			delete(s.waitingPeers, peerID)
		}
		s.mu.Unlock()
		return err
	}

	// Wait for peer to come online or context to be cancelled
	timeoutCtx, cancel := context.WithTimeout(ctx, OpenConnectionTimeout)
	defer cancel()
	select {
	case _, ok := <-waitCh:
		if !ok {
			return fmt.Errorf("peer is offline")
		}

		s.log.Debugf("peer %s is now online", peerID)
		return nil
	case <-timeoutCtx.Done():
		s.log.Debugf("context timed out while waiting for peer %s to come online", peerID)
		if err := s.unsubscribeStateChange([]messages.PeerID{peerID}); err != nil {
			s.log.Errorf("failed to unsubscribe from peer state: %s", err)
		}
		s.mu.Lock()
		if ch, exists := s.waitingPeers[peerID]; exists && ch == waitCh {
			close(waitCh)
			delete(s.waitingPeers, peerID)
		}
		s.mu.Unlock()
		return timeoutCtx.Err()
	}
}

func (s *PeersStateSubscription) UnsubscribeStateChange(peerIDs []messages.PeerID) error {
	msgErr := s.unsubscribeStateChange(peerIDs)

	s.mu.Lock()
	for _, peerID := range peerIDs {
		if wch, ok := s.waitingPeers[peerID]; ok {
			close(wch)
			delete(s.waitingPeers, peerID)
		}

		delete(s.listenForOfflinePeers, peerID)
	}
	s.mu.Unlock()

	return msgErr
}

func (s *PeersStateSubscription) Cleanup() {
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, waitCh := range s.waitingPeers {
		close(waitCh)
	}

	s.waitingPeers = make(map[messages.PeerID]chan struct{})
	s.listenForOfflinePeers = make(map[messages.PeerID]struct{})
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

func (s *PeersStateSubscription) unsubscribeStateChange(peerIDs []messages.PeerID) error {
	msgs, err := messages.MarshalUnsubPeerStateMsg(peerIDs)
	if err != nil {
		return err
	}

	var connWriteErr error
	for _, msg := range msgs {
		if _, err := s.relayConn.Write(msg); err != nil {
			connWriteErr = err
		}
	}
	return connWriteErr
}
