package peer

import (
	"sync"
)

type ConnectionListener struct {
	OnConnected    func(peerID string)
	OnDisconnected func(peerID string)
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

func (e *ConnectionDispatcher) NotifyConnected(peerID string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	for listener := range e.listeners {
		listener.OnConnected(peerID)
	}
}

func (e *ConnectionDispatcher) NotifyDisconnected(peerID string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	for listener := range e.listeners {
		listener.OnDisconnected(peerID)
	}
}
