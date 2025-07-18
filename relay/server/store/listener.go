package store

import (
	"context"
	"sync"

	"github.com/netbirdio/netbird/relay/messages"
)

type event struct {
	peerID messages.PeerID
	online bool
}

type Listener struct {
	ctx context.Context

	eventChan                 chan *event
	interestedPeersForOffline map[messages.PeerID]struct{}
	interestedPeersForOnline  map[messages.PeerID]struct{}
	mu                        sync.RWMutex
}

func newListener(ctx context.Context) *Listener {
	l := &Listener{
		ctx: ctx,

		// important to use a single channel for offline and online events because with it we can ensure all events
		// will be processed in the order they were sent
		eventChan:                 make(chan *event, 244), //244 is the message size limit in the relay protocol
		interestedPeersForOffline: make(map[messages.PeerID]struct{}),
		interestedPeersForOnline:  make(map[messages.PeerID]struct{}),
	}

	return l
}

func (l *Listener) AddInterestedPeers(peerIDs []messages.PeerID) {
	l.mu.Lock()
	defer l.mu.Unlock()

	for _, id := range peerIDs {
		l.interestedPeersForOnline[id] = struct{}{}
		l.interestedPeersForOffline[id] = struct{}{}
	}
	return
}

func (l *Listener) RemoveInterestedPeer(peerIDs []messages.PeerID) {
	l.mu.Lock()
	defer l.mu.Unlock()

	for _, id := range peerIDs {
		delete(l.interestedPeersForOffline, id)
		delete(l.interestedPeersForOnline, id)
	}
}

func (l *Listener) listenForEvents(onPeersComeOnline, onPeersWentOffline func([]messages.PeerID)) {
	for {
		select {
		case <-l.ctx.Done():
			return
		case e := <-l.eventChan:
			peersOffline := make([]messages.PeerID, 0)
			peersOnline := make([]messages.PeerID, 0)
			if e.online {
				peersOnline = append(peersOnline, e.peerID)
			} else {
				peersOffline = append(peersOffline, e.peerID)
			}

			// Drain the channel to collect all events
			for len(l.eventChan) > 0 {
				e = <-l.eventChan
				if e.online {
					peersOnline = append(peersOnline, e.peerID)
				} else {
					peersOffline = append(peersOffline, e.peerID)
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

	if _, ok := l.interestedPeersForOffline[peerID]; ok {
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
	l.mu.Lock()
	defer l.mu.Unlock()

	if _, ok := l.interestedPeersForOnline[peerID]; ok {
		select {
		case l.eventChan <- &event{
			peerID: peerID,
			online: true,
		}:
		case <-l.ctx.Done():
		}

		delete(l.interestedPeersForOnline, peerID)
	}
}
