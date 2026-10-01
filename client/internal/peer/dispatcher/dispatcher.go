package dispatcher

import (
	"sync"

	"github.com/netbirdio/netbird/client/internal/peer/id"
)

type ConnectionListener struct {
	OnConnected    func(peerID id.ConnID)
	OnDisconnected func(peerID id.ConnID)
}

type ConnectionDispatcher struct {
	listeners map[*ConnectionListener]struct{}
	mu        sync.Mutex
}

func NewConnectionDispatcher() *ConnectionDispatcher {
	return &ConnectionDispatcher{
		listeners: make(map[*ConnectionListener]struct{}),
	}
}

func (e *ConnectionDispatcher) AddListener(listener *ConnectionListener) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.listeners[listener] = struct{}{}
}

func (e *ConnectionDispatcher) RemoveListener(listener *ConnectionListener) {
	e.mu.Lock()
	defer e.mu.Unlock()

	delete(e.listeners, listener)
}

func (e *ConnectionDispatcher) NotifyConnected(peerConnID id.ConnID) {
	e.mu.Lock()
	defer e.mu.Unlock()
	for listener := range e.listeners {
		listener.OnConnected(peerConnID)
	}
}

func (e *ConnectionDispatcher) NotifyDisconnected(peerConnID id.ConnID) {
	e.mu.Lock()
	defer e.mu.Unlock()
	for listener := range e.listeners {
		listener.OnDisconnected(peerConnID)
	}
}
