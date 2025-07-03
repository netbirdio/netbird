package store

import (
	"context"
	"sync"

	"github.com/netbirdio/netbird/relay/messages"
)

type Listener struct {
	store *Store

	onlineChan                chan messages.PeerID
	offlineChan               chan messages.PeerID
	interestedPeersForOffline map[messages.PeerID]struct{}
	interestedPeersForOnline  map[messages.PeerID]struct{}
	mu                        sync.RWMutex
}

func newListener(store *Store) *Listener {
	l := &Listener{
		store: store,

		onlineChan:                make(chan messages.PeerID, 244), //244 is the message size limit in the relay protocol
		offlineChan:               make(chan messages.PeerID, 244), //244 is the message size limit in the relay protocol
		interestedPeersForOffline: make(map[messages.PeerID]struct{}),
		interestedPeersForOnline:  make(map[messages.PeerID]struct{}),
	}

	return l
}

func (l *Listener) AddInterestedPeers(peerIDs []messages.PeerID) []messages.PeerID {
	availablePeers := make([]messages.PeerID, 0)
	l.mu.Lock()
	defer l.mu.Unlock()

	for _, id := range peerIDs {
		l.interestedPeersForOnline[id] = struct{}{}
		l.interestedPeersForOffline[id] = struct{}{}
	}

	// collect online peers to response back to the caller
	for _, id := range peerIDs {
		_, ok := l.store.Peer(id)
		if !ok {
			continue
		}

		availablePeers = append(availablePeers, id)
	}
	return availablePeers
}

func (l *Listener) RemoveInterestedPeer(peerIDs []messages.PeerID) {
	l.mu.Lock()
	defer l.mu.Unlock()

	for _, id := range peerIDs {
		delete(l.interestedPeersForOffline, id)
		delete(l.interestedPeersForOnline, id)

	}
}

func (l *Listener) listenForEvents(ctx context.Context, onPeersComeOnline, onPeersWentOffline func([]messages.PeerID)) {
	for {
		peers := make([]messages.PeerID, 0)

		select {
		case <-ctx.Done():
			return
		case pID := <-l.onlineChan:
			peers = append(peers, pID)

			for len(l.offlineChan) > 0 {
				pID = <-l.offlineChan
				peers = append(peers, pID)
			}

			onPeersComeOnline(peers)
		case pID := <-l.offlineChan:
			// todo maybe check here if the peer is still interested
			peers = append(peers, pID)

			for len(l.offlineChan) > 0 {
				pID = <-l.offlineChan
				peers = append(peers, pID)
			}

			onPeersWentOffline(peers)
		}
	}
}

// todo handle context cancellation properly
func (l *Listener) peerWentOffline(peerID messages.PeerID) {
	l.mu.RLock()
	defer l.mu.RUnlock()

	if _, ok := l.interestedPeersForOffline[peerID]; ok {
		// todo: if the listener cancelled and the notifier write to here then will be blocked fore
		l.offlineChan <- peerID
	}
}

// todo handle context cancellation properly
func (l *Listener) peerComeOnline(peerID messages.PeerID) {
	l.mu.Lock()
	defer l.mu.Unlock()

	if _, ok := l.interestedPeersForOnline[peerID]; ok {
		l.onlineChan <- peerID
		delete(l.interestedPeersForOnline, peerID)
	}
}
