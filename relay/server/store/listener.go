package store

import (
	"context"
	"sync"

	"github.com/netbirdio/netbird/shared/relay/messages"
)

// pendingState is the undelivered notifications of one peer. Only four cases need
// to reach the client: online, offline, online then offline, offline then online.
// A pair must stay a pair because the client acts on both, while a third flip
// cancels the pair back to its first notification. Two bits encode the four cases:
// what comes first, and whether its opposite follows.
type pendingState struct {
	firstOnline        bool
	followedByOpposite bool
}

type notificationBatch struct {
	online  []messages.PeerID
	offline []messages.PeerID
}

type Listener struct {
	ctx context.Context

	wake                      chan struct{}
	pending                   map[messages.PeerID]pendingState
	interestedPeersForOffline map[messages.PeerID]struct{}
	interestedPeersForOnline  map[messages.PeerID]struct{}
	mu                        sync.Mutex
}

func newListener(ctx context.Context) *Listener {
	l := &Listener{
		ctx: ctx,

		wake:                      make(chan struct{}, 1),
		pending:                   make(map[messages.PeerID]pendingState),
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
}

func (l *Listener) RemoveInterestedPeer(peerIDs []messages.PeerID) {
	l.mu.Lock()
	defer l.mu.Unlock()

	for _, id := range peerIDs {
		delete(l.interestedPeersForOffline, id)
		delete(l.interestedPeersForOnline, id)
		delete(l.pending, id)
	}
}

func (l *Listener) listenForEvents(onPeersComeOnline, onPeersWentOffline func([]messages.PeerID)) {
	for {
		select {
		case <-l.ctx.Done():
			return
		case <-l.wake:
		}

		if l.ctx.Err() != nil {
			return
		}

		first, second := l.takePending()
		first.deliver(onPeersComeOnline, onPeersWentOffline)
		second.deliver(onPeersComeOnline, onPeersWentOffline)
	}
}

func (l *Listener) peerWentOffline(peerID messages.PeerID) {
	l.mu.Lock()
	defer l.mu.Unlock()

	if _, ok := l.interestedPeersForOffline[peerID]; !ok {
		return
	}
	l.enqueue(peerID, false)
}

func (l *Listener) peerComeOnline(peerID messages.PeerID) {
	l.mu.Lock()
	defer l.mu.Unlock()

	if _, ok := l.interestedPeersForOnline[peerID]; !ok {
		return
	}
	delete(l.interestedPeersForOnline, peerID)
	l.enqueue(peerID, true)
}

func (l *Listener) enqueue(peerID messages.PeerID, online bool) {
	state, ok := l.pending[peerID]
	if !ok {
		state = pendingState{firstOnline: online}
	} else {
		state = state.followedBy(online)
	}
	l.pending[peerID] = state

	select {
	case l.wake <- struct{}{}:
	default:
	}
}

func (l *Listener) takePending() (notificationBatch, notificationBatch) {
	l.mu.Lock()
	pending := l.pending
	l.pending = make(map[messages.PeerID]pendingState)
	l.mu.Unlock()

	var first, second notificationBatch
	for id, state := range pending {
		first.add(id, state.firstOnline)
		if state.followedByOpposite {
			second.add(id, !state.firstOnline)
		}
	}
	return first, second
}

func (s pendingState) lastOnline() bool {
	if s.followedByOpposite {
		return !s.firstOnline
	}
	return s.firstOnline
}

func (s pendingState) followedBy(online bool) pendingState {
	if online == s.lastOnline() {
		return s
	}
	s.followedByOpposite = !s.followedByOpposite
	return s
}

func (b *notificationBatch) add(peerID messages.PeerID, online bool) {
	if online {
		b.online = append(b.online, peerID)
		return
	}
	b.offline = append(b.offline, peerID)
}

func (b notificationBatch) deliver(onPeersComeOnline, onPeersWentOffline func([]messages.PeerID)) {
	if len(b.online) > 0 {
		onPeersComeOnline(b.online)
	}
	if len(b.offline) > 0 {
		onPeersWentOffline(b.offline)
	}
}
