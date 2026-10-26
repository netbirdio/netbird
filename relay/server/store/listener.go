package store

import (
	"context"
	"sync"

	"github.com/netbirdio/netbird/shared/relay/messages"
)

type event struct {
	peerID messages.PeerID
	online bool
}

type Listener struct {
	ctx context.Context

	eventChan chan *event
	// interestedPeers stays registered across reconnections of a peer until it is
	// removed, so every registration of the peer produces an online event.
	interestedPeers map[messages.PeerID]struct{}
	mu              sync.RWMutex
}

func newListener(ctx context.Context) *Listener {
	l := &Listener{
		ctx: ctx,

		// important to use a single channel for offline and online events because with it we can ensure all events
		// will be processed in the order they were sent
		eventChan:       make(chan *event, 244), //244 is the message size limit in the relay protocol
		interestedPeers: make(map[messages.PeerID]struct{}),
	}

	return l
}

func (l *Listener) AddInterestedPeers(peerIDs []messages.PeerID) {
	l.mu.Lock()
	defer l.mu.Unlock()

	for _, id := range peerIDs {
		l.interestedPeers[id] = struct{}{}
	}
}

func (l *Listener) RemoveInterestedPeer(peerIDs []messages.PeerID) {
	l.mu.Lock()
	defer l.mu.Unlock()

	for _, id := range peerIDs {
		delete(l.interestedPeers, id)
	}
}

func (l *Listener) listenForEvents(onPeersComeOnline, onPeersWentOffline func([]messages.PeerID)) {
	for {
		select {
		case <-l.ctx.Done():
			return
		case e := <-l.eventChan:
			// Events are delivered by the final state of each peer, so a peer that went
			// offline and registered again within one batch is reported as online only.
			order := []messages.PeerID{e.peerID}
			online := map[messages.PeerID]bool{e.peerID: e.online}

			// Drain the channel to collect all events
			for len(l.eventChan) > 0 {
				e = <-l.eventChan
				if _, seen := online[e.peerID]; !seen {
					order = append(order, e.peerID)
				}
				online[e.peerID] = e.online
			}

			peersOnline := make([]messages.PeerID, 0)
			peersOffline := make([]messages.PeerID, 0)
			for _, id := range order {
				if online[id] {
					peersOnline = append(peersOnline, id)
				} else {
					peersOffline = append(peersOffline, id)
				}
			}

			if len(peersOnline) > 0 {
				onPeersComeOnline(peersOnline)
			}
			if len(peersOffline) > 0 {
				onPeersWentOffline(peersOffline)
			}
		}
	}
}

func (l *Listener) peerWentOffline(peerID messages.PeerID) {
	l.mu.RLock()
	defer l.mu.RUnlock()

	if _, ok := l.interestedPeers[peerID]; ok {
		select {
		case l.eventChan <- &event{
			peerID: peerID,
			online: false,
		}:
		case <-l.ctx.Done():
		}
	}
}

func (l *Listener) peerComeOnline(peerID messages.PeerID) {
	l.mu.RLock()
	defer l.mu.RUnlock()

	if _, ok := l.interestedPeers[peerID]; ok {
		select {
		case l.eventChan <- &event{
			peerID: peerID,
			online: true,
		}:
		case <-l.ctx.Done():
		}
	}
}
