package peer

import (
	"sync"
)

/*
	handler := peer.ConnectionListener{
		OnConnected:    m.onPeerConnected,
		OnDisconnected: m.onPeerDisconnected,
	}

	dispatcher.AddListener(handler)
*/

type ConnectionListener struct {
	OnConnected    func(peer *Conn)
	OnDisconnected func(peer *Conn)
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

func (e *ConnectionDispatcher) NotifyConnected(peer *Conn) {
	e.mu.Lock()
	defer e.mu.Unlock()
	for listener, _ := range e.listeners {
		listener.OnConnected(peer)
	}
}

func (e *ConnectionDispatcher) NotifyDisconnected(peer *Conn) {
	e.mu.Lock()
	defer e.mu.Unlock()
	for listener, _ := range e.listeners {
		listener.OnDisconnected(peer)
	}
}
