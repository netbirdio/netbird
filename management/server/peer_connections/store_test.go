package peer_connections

import (
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	mgmProto "github.com/netbirdio/netbird/shared/management/proto"
)

type fakeClock struct{ now time.Time }

func (c *fakeClock) Now() time.Time          { return c.now }
func (c *fakeClock) advance(d time.Duration) { c.now = c.now.Add(d) }

func newStoreWithClock(ttl time.Duration) (*MemoryStore, *fakeClock) {
	clk := &fakeClock{now: time.Now()}
	s := newMemoryStoreWithClock(ttl, clk)
	return s, clk
}

func TestMemoryStore_PutFullThenGet(t *testing.T) {
	s, _ := newStoreWithClock(time.Hour)
	s.Put("peerA", &mgmProto.PeerConnectionMap{
		Seq: 1, FullSnapshot: true,
		Entries: []*mgmProto.PeerConnectionEntry{{RemotePubkey: "peerB", LatencyMs: 10}},
	})
	got, ok := s.Get("peerA")
	if !ok {
		t.Fatal("expected entry")
	}
	if len(got.GetEntries()) != 1 || got.GetEntries()[0].GetRemotePubkey() != "peerB" {
		t.Errorf("unexpected entries: %+v", got.GetEntries())
	}
}

func TestMemoryStore_DeepCopyOnReturn(t *testing.T) {
	s, _ := newStoreWithClock(time.Hour)
	s.Put("peerA", &mgmProto.PeerConnectionMap{
		Seq: 1, FullSnapshot: true,
		Entries: []*mgmProto.PeerConnectionEntry{
			{RemotePubkey: "peerB", LastHandshake: timestamppb.New(time.Now())},
		},
	})
	got1, _ := s.Get("peerA")
	got1.GetEntries()[0].RemotePubkey = "MUTATED"
	got2, _ := s.Get("peerA")
	if got2.GetEntries()[0].GetRemotePubkey() != "peerB" {
		t.Errorf("Get returned shared pointer; mutation leaked: %s", got2.GetEntries()[0].GetRemotePubkey())
	}
}

func TestMemoryStore_DeltaMerges(t *testing.T) {
	s, _ := newStoreWithClock(time.Hour)
	s.Put("peerA", &mgmProto.PeerConnectionMap{Seq: 1, FullSnapshot: true,
		Entries: []*mgmProto.PeerConnectionEntry{
			{RemotePubkey: "peerB", LatencyMs: 10},
			{RemotePubkey: "peerC", LatencyMs: 30},
		}})
	s.Put("peerA", &mgmProto.PeerConnectionMap{Seq: 2, FullSnapshot: false,
		Entries: []*mgmProto.PeerConnectionEntry{{RemotePubkey: "peerB", LatencyMs: 14}}})
	got, _ := s.Get("peerA")
	if len(got.GetEntries()) != 2 {
		t.Fatalf("want 2 entries, got %d", len(got.GetEntries()))
	}
	for _, e := range got.GetEntries() {
		if e.GetRemotePubkey() == "peerB" && e.GetLatencyMs() != 14 {
			t.Errorf("peerB latency not updated: %d", e.GetLatencyMs())
		}
	}
}

func TestMemoryStore_OutOfOrderDeltaDropped(t *testing.T) {
	s, _ := newStoreWithClock(time.Hour)
	s.Put("peerA", &mgmProto.PeerConnectionMap{Seq: 5, FullSnapshot: true,
		Entries: []*mgmProto.PeerConnectionEntry{{RemotePubkey: "peerB", LatencyMs: 99}}})
	// Stale delta with lower seq must be dropped (in-order seq guarantee
	// applies to deltas within a single stream).
	s.Put("peerA", &mgmProto.PeerConnectionMap{Seq: 3, FullSnapshot: false,
		Entries: []*mgmProto.PeerConnectionEntry{{RemotePubkey: "peerB", LatencyMs: 11}}})
	got, _ := s.Get("peerA")
	if got.GetSeq() != 5 {
		t.Errorf("want seq 5, got %d", got.GetSeq())
	}
	if got.GetEntries()[0].GetLatencyMs() != 99 {
		t.Errorf("want latency 99 (stale delta dropped), got %d", got.GetEntries()[0].GetLatencyMs())
	}
}

// TestMemoryStore_FullSnapshotResetsEpoch covers Codex finding 2: the
// pusher resets seq to 1 on every daemon-/stream-restart, so a fresh
// full snapshot may carry seq=1 against a cached prev.seq=50 from the
// previous session. Without the full-snapshot epoch escape, the
// dashboard would stay stale until TTL expiry.
func TestMemoryStore_FullSnapshotResetsEpoch(t *testing.T) {
	s, _ := newStoreWithClock(time.Hour)
	// Old session: pusher reached seq=50 with one peer.
	s.Put("peerA", &mgmProto.PeerConnectionMap{Seq: 50, FullSnapshot: true,
		Entries: []*mgmProto.PeerConnectionEntry{{RemotePubkey: "oldPeer", LatencyMs: 100}}})
	// Daemon restart: new session starts fresh at seq=1 with a different
	// peer set. Must replace, NOT be dropped.
	s.Put("peerA", &mgmProto.PeerConnectionMap{Seq: 1, FullSnapshot: true,
		Entries: []*mgmProto.PeerConnectionEntry{{RemotePubkey: "newPeer", LatencyMs: 7}}})
	got, ok := s.Get("peerA")
	if !ok {
		t.Fatal("expected entry after restart full-snapshot")
	}
	if got.GetSeq() != 1 {
		t.Errorf("want seq 1 (post-restart epoch), got %d", got.GetSeq())
	}
	if len(got.GetEntries()) != 1 || got.GetEntries()[0].GetRemotePubkey() != "newPeer" {
		t.Errorf("want only newPeer in entries, got %+v", got.GetEntries())
	}
	// Subsequent in-order delta (seq=2) from new session must merge.
	s.Put("peerA", &mgmProto.PeerConnectionMap{Seq: 2, FullSnapshot: false,
		Entries: []*mgmProto.PeerConnectionEntry{{RemotePubkey: "newPeer", LatencyMs: 9}}})
	got, _ = s.Get("peerA")
	if got.GetEntries()[0].GetLatencyMs() != 9 {
		t.Errorf("want latency 9 (delta from new session), got %d", got.GetEntries()[0].GetLatencyMs())
	}
}

func TestMemoryStore_TTLExpires(t *testing.T) {
	s, clk := newStoreWithClock(50 * time.Millisecond)
	s.Put("peerA", &mgmProto.PeerConnectionMap{Seq: 1, FullSnapshot: true})
	clk.advance(60 * time.Millisecond)
	if _, ok := s.Get("peerA"); ok {
		t.Error("expected TTL-expired entry to be gone")
	}
}

func TestMemoryStore_NonceCheck(t *testing.T) {
	s, _ := newStoreWithClock(time.Hour)
	s.Put("peerA", &mgmProto.PeerConnectionMap{Seq: 1, FullSnapshot: true, InResponseToNonce: 0})
	if _, ok := s.GetWithNonceCheck("peerA", 5); ok {
		t.Error("expected GetWithNonceCheck to refuse stale data when sinceNonce > InResponseToNonce")
	}
	s.Put("peerA", &mgmProto.PeerConnectionMap{Seq: 2, FullSnapshot: true, InResponseToNonce: 5})
	if _, ok := s.GetWithNonceCheck("peerA", 5); !ok {
		t.Error("expected GetWithNonceCheck to return when InResponseToNonce >= sinceNonce")
	}
}
