package peer_connections

import "sync"

// SnapshotRouter holds per-peer-pubkey send-channels so REST handlers
// can inject a SnapshotRequest into the active Sync server-stream.
// Stream owners (mgmt grpc handleUpdates) Register on stream-start and
// Unregister on stream-close. Phase 3.7i of #5989.
type SnapshotRouter struct {
	mu       sync.Mutex
	channels map[string]chan uint64
}

func NewSnapshotRouter() *SnapshotRouter {
	return &SnapshotRouter{channels: make(map[string]chan uint64)}
}

// Register returns a buffered channel the stream owner reads from to
// receive snapshot-request nonces. The returned channel is the token
// the caller must pass to Unregister so a stale stream cannot tear
// down a fresh stream's channel after a quick reconnect.
func (r *SnapshotRouter) Register(peerPubKey string) <-chan uint64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	ch := make(chan uint64, 4)
	if old, ok := r.channels[peerPubKey]; ok {
		// A second concurrent stream for the same peer (e.g. fast
		// reconnect) — close the previous channel so its goroutine
		// exits cleanly, then install the new one.
		close(old)
	}
	r.channels[peerPubKey] = ch
	return ch
}

// Unregister closes the given channel (token returned from Register)
// and removes the peer from the router only if that channel is still
// the live one. A stale stream calling Unregister after a fresh stream
// has registered must not tear down the new stream's channel.
// Idempotent.
func (r *SnapshotRouter) Unregister(peerPubKey string, token <-chan uint64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	current, ok := r.channels[peerPubKey]
	if !ok {
		return
	}
	if (<-chan uint64)(current) != token {
		// A newer Register replaced our channel; that newer Register
		// already closed our old channel, so nothing to do here.
		return
	}
	close(current)
	delete(r.channels, peerPubKey)
}

// Request enqueues a nonce for the given peer's snapshot channel.
// Returns true if delivered, false if no active stream for that peer
// or the channel is full (channel capacity 4).
func (r *SnapshotRouter) Request(peerPubKey string, nonce uint64) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	ch, ok := r.channels[peerPubKey]
	if !ok {
		return false
	}
	select {
	case ch <- nonce:
		return true
	default:
		return false
	}
}
