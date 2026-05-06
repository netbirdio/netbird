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

func TestMemoryStore_OutOfOrderDropped(t *testing.T) {
	s, _ := newStoreWithClock(time.Hour)
	s.Put("peerA", &mgmProto.PeerConnectionMap{Seq: 5, FullSnapshot: true})
	s.Put("peerA", &mgmProto.PeerConnectionMap{Seq: 3, FullSnapshot: true})
	got, _ := s.Get("peerA")
	if got.GetSeq() != 5 {
		t.Errorf("want seq 5, got %d", got.GetSeq())
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
