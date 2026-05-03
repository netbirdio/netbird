package peer_connections

import (
	"sync"
	"time"

	"google.golang.org/protobuf/proto"

	mgmProto "github.com/netbirdio/netbird/shared/management/proto"
)

// Clock is the time source MemoryStore consults. Production passes
// realClock{}; tests inject fakeClock to control TTL deterministically.
// Phase 3.7i of #5989.
type Clock interface {
	Now() time.Time
}

type realClock struct{}

func (realClock) Now() time.Time { return time.Now() }

// Store is the interface peer-connections-map storage implementations
// must satisfy. Phase 3.7i ships only MemoryStore. RedisStore is a
// future possibility behind the same interface (deferred).
type Store interface {
	Put(peerPubKey string, m *mgmProto.PeerConnectionMap)
	Get(peerPubKey string) (*mgmProto.PeerConnectionMap, bool)
	GetWithNonceCheck(peerPubKey string, sinceNonce uint64) (*mgmProto.PeerConnectionMap, bool)
}

// MemoryStore is the in-memory Store implementation. Phase 3.7i.
type MemoryStore struct {
	ttl   time.Duration
	clock Clock
	mu    sync.Mutex
	maps  map[string]*memEntry
}

type memEntry struct {
	m         *mgmProto.PeerConnectionMap
	updatedAt time.Time
}

// NewMemoryStore returns a MemoryStore using wall-clock time.
func NewMemoryStore(ttl time.Duration) *MemoryStore {
	return newMemoryStoreWithClock(ttl, realClock{})
}

// newMemoryStoreWithClock is the test-only ctor that lets tests inject a
// fakeClock for deterministic TTL behaviour.
func newMemoryStoreWithClock(ttl time.Duration, clk Clock) *MemoryStore {
	return &MemoryStore{
		ttl:   ttl,
		clock: clk,
		maps:  make(map[string]*memEntry),
	}
}

// Put stores or merges a connection-map for peerPubKey.
//   - full_snapshot=true -> ALWAYS replace, regardless of seq. The
//     pusher resets seq to 1 on every daemon-restart, so a fresh full
//     snapshot may carry seq=1 against a cached prev.seq=50.
//   - delta + no prior entry -> store as-is.
//   - delta + prior entry, mismatched session_id -> drop. Codex
//     follow-up: SyncPeerConnections is a unary RPC, so a stale
//     in-flight retry from the previous daemon process can arrive
//     AFTER the new process's full snapshot. Without the session_id
//     check, the stale delta's seq (e.g. 51) would beat the new
//     process's seq (e.g. 2) and merge old data into the fresh map.
//     session_id=0 means a legacy client and falls back to seq-only.
//   - delta + prior entry, matching session, out-of-order seq -> drop.
//   - delta + prior entry, matching session, in-order seq -> merge.
func (s *MemoryStore) Put(peerPubKey string, m *mgmProto.PeerConnectionMap) {
	s.mu.Lock()
	defer s.mu.Unlock()

	prev := s.maps[peerPubKey]
	if !m.GetFullSnapshot() && prev != nil {
		// Drop deltas from a different daemon session than the cached
		// state. Both sides must advertise a session_id for the check
		// to apply; if either is 0 we fall back to the seq-only path.
		if m.GetSessionId() != 0 && prev.m.GetSessionId() != 0 &&
			m.GetSessionId() != prev.m.GetSessionId() {
			return
		}
		if m.GetSeq() > 0 && m.GetSeq() <= prev.m.GetSeq() {
			return
		}
	}

	stored := proto.Clone(m).(*mgmProto.PeerConnectionMap)
	if !m.GetFullSnapshot() && prev != nil {
		merged := proto.Clone(prev.m).(*mgmProto.PeerConnectionMap)
		merged.Seq = m.GetSeq()
		merged.FullSnapshot = false
		// Keep the latest non-zero refresh-nonce. A snapshot pushed in
		// response to nonce N must remain reachable via GET ?since=N
		// even when a regular delta with InResponseToNonce=0 arrives
		// shortly after; otherwise the refresh polling client gives up
		// and falls back to the next sync interval (~60 s gap).
		if m.GetInResponseToNonce() > merged.GetInResponseToNonce() {
			merged.InResponseToNonce = m.GetInResponseToNonce()
		}
		byKey := make(map[string]int, len(merged.Entries))
		for i, e := range merged.Entries {
			byKey[e.GetRemotePubkey()] = i
		}
		for _, ne := range stored.Entries {
			if idx, ok := byKey[ne.GetRemotePubkey()]; ok {
				merged.Entries[idx] = ne
			} else {
				merged.Entries = append(merged.Entries, ne)
				byKey[ne.GetRemotePubkey()] = len(merged.Entries) - 1
			}
		}
		stored = merged
	}
	s.maps[peerPubKey] = &memEntry{m: stored, updatedAt: s.clock.Now()}
}

// Get returns a deep copy of the cached map for peerPubKey, or false if
// missing or TTL-expired.
func (s *MemoryStore) Get(peerPubKey string) (*mgmProto.PeerConnectionMap, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.maps[peerPubKey]
	if !ok {
		return nil, false
	}
	if s.clock.Now().Sub(e.updatedAt) > s.ttl {
		delete(s.maps, peerPubKey)
		return nil, false
	}
	return proto.Clone(e.m).(*mgmProto.PeerConnectionMap), true
}

// GetWithNonceCheck returns the cached map only if its
// InResponseToNonce >= sinceNonce (refresh-flow polling). Same TTL +
// deep-copy semantics as Get.
func (s *MemoryStore) GetWithNonceCheck(peerPubKey string, since uint64) (*mgmProto.PeerConnectionMap, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.maps[peerPubKey]
	if !ok {
		return nil, false
	}
	if since > 0 && e.m.GetInResponseToNonce() < since {
		return nil, false
	}
	if s.clock.Now().Sub(e.updatedAt) > s.ttl {
		delete(s.maps, peerPubKey)
		return nil, false
	}
	return proto.Clone(e.m).(*mgmProto.PeerConnectionMap), true
}
