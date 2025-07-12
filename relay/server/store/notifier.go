package store

import (
	"context"
	"sync"

	"github.com/netbirdio/netbird/relay/messages"
)

type PeerNotifier struct {
	store *Store

	listeners      map[*Listener]context.CancelFunc
	listenersMutex sync.RWMutex
}

func NewPeerNotifier(store *Store) *PeerNotifier {
	pn := &PeerNotifier{
		store:     store,
		listeners: make(map[*Listener]context.CancelFunc),
	}
	return pn
}

func (pn *PeerNotifier) NewListener(onPeersComeOnline, onPeersWentOffline func([]messages.PeerID)) *Listener {
	ctx, cancel := context.WithCancel(context.Background())
	listener := newListener(pn.store)
	go listener.listenForEvents(ctx, onPeersComeOnline, onPeersWentOffline)

	pn.listenersMutex.Lock()
	pn.listeners[listener] = cancel
	pn.listenersMutex.Unlock()
	return listener
}

func (pn *PeerNotifier) RemoveListener(listener *Listener) {
	pn.listenersMutex.Lock()
	defer pn.listenersMutex.Unlock()

	cancel, ok := pn.listeners[listener]
	if !ok {
		return
	}
	cancel()
	delete(pn.listeners, listener)
}

func (pn *PeerNotifier) PeerWentOffline(peerID messages.PeerID) {
	pn.listenersMutex.RLock()
	defer pn.listenersMutex.RUnlock()

	for listener := range pn.listeners {
		listener.peerWentOffline(peerID)
	}
}

func (pn *PeerNotifier) PeerCameOnline(peerID messages.PeerID) {
	pn.listenersMutex.RLock()
	defer pn.listenersMutex.RUnlock()

	for listener := range pn.listeners {
		listener.peerComeOnline(peerID)
	}
}
