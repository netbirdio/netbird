package store

import (
	"context"
	"slices"
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
			events := []*event{e}
			for len(l.eventChan) > 0 {
				events = append(events, <-l.eventChan)
			}

			for _, run := range sameStateRuns(events) {
				if run.online {
					onPeersComeOnline(run.peerIDs)
				} else {
					onPeersWentOffline(run.peerIDs)
				}
			}
		}
	}
}

// stateRun is a set of peers that reached the same state in consecutive events.
type stateRun struct {
	online  bool
	peerIDs []messages.PeerID
}

// sameStateRuns groups consecutive events of the same state, keeping the order in
// which the states were reached, so a peer that went offline and registered again is
// reported offline before it is reported online. Every registration of a peer is kept
// in an online run, since each one is a new connection of the peer on the relay.
func sameStateRuns(events []*event) []stateRun {
	var runs []stateRun
	for _, e := range events {
		if len(runs) == 0 || runs[len(runs)-1].online != e.online {
			runs = append(runs, stateRun{online: e.online})
		}
		run := &runs[len(runs)-1]
		if e.online || !slices.Contains(run.peerIDs, e.peerID) {
			run.peerIDs = append(run.peerIDs, e.peerID)
		}
	}
	return runs
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
