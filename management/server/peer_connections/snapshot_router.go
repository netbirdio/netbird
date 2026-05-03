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
// receive snapshot-request nonces. Caller must call Unregister when the
// stream closes.
func (r *SnapshotRouter) Register(peerPubKey string) <-chan uint64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	ch := make(chan uint64, 4)
	r.channels[peerPubKey] = ch
	return ch
}

// Unregister closes the channel returned by Register and removes the
// peer from the router. Idempotent.
func (r *SnapshotRouter) Unregister(peerPubKey string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if ch, ok := r.channels[peerPubKey]; ok {
		close(ch)
		delete(r.channels, peerPubKey)
	}
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
