package filedrop

import (
	"context"
	"sync"
)

// PortRegistry tracks the file drop listen port each peer advertised over
// signaling; 0 means the well-known default. Senders can wait on it to learn a
// better port after a failed attempt.
type PortRegistry struct {
	mu    sync.Mutex
	ports map[PeerKey]uint16
	waits map[PeerKey][]chan uint16
}

// NewPortRegistry returns an empty registry.
func NewPortRegistry() *PortRegistry {
	return &PortRegistry{
		ports: make(map[PeerKey]uint16),
		waits: make(map[PeerKey][]chan uint16),
	}
}

// Set records the port a peer advertised and releases every waiter for it.
func (r *PortRegistry) Set(key PeerKey, port uint16) {
	r.mu.Lock()
	r.ports[key] = port
	waiters := r.waits[key]
	delete(r.waits, key)
	r.mu.Unlock()

	for _, ch := range waiters {
		ch <- port
	}
}

// Port returns the last advertised port for a peer; 0 means default or unknown.
func (r *PortRegistry) Port(key PeerKey) uint16 {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.ports[key]
}

// Await returns the peer's port as soon as it differs from used, or after the next
// advertisement even when it does not, reporting whether it differs. It returns
// immediately when the currently known port already differs.
func (r *PortRegistry) Await(ctx context.Context, key PeerKey, used uint16) (uint16, bool) {
	r.mu.Lock()
	if port, ok := r.ports[key]; ok && port != used {
		r.mu.Unlock()
		return port, true
	}
	ch := make(chan uint16, 1)
	r.waits[key] = append(r.waits[key], ch)
	r.mu.Unlock()

	select {
	case port := <-ch:
		return port, port != used
	case <-ctx.Done():
		r.drop(key, ch)
		return 0, false
	}
}

func (r *PortRegistry) drop(key PeerKey, ch chan uint16) {
	r.mu.Lock()
	defer r.mu.Unlock()

	waiters := r.waits[key]
	for i, w := range waiters {
		if w == ch {
			r.waits[key] = append(waiters[:i], waiters[i+1:]...)
			break
		}
	}
	if len(r.waits[key]) == 0 {
		delete(r.waits, key)
	}
}
