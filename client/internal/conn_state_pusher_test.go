package internal

import (
	"context"
	"sync"
	"testing"
	"time"

	mgmProto "github.com/netbirdio/netbird/shared/management/proto"
)

type stubPushSink struct {
	mu     sync.Mutex
	pushes []*mgmProto.PeerConnectionMap
	notif  chan struct{}
}

func newStubSink() *stubPushSink { return &stubPushSink{notif: make(chan struct{}, 16)} }

func (s *stubPushSink) Push(_ context.Context, m *mgmProto.PeerConnectionMap) error {
	s.mu.Lock()
	s.pushes = append(s.pushes, m)
	s.mu.Unlock()
	select {
	case s.notif <- struct{}{}:
	default:
	}
	return nil
}

func (s *stubPushSink) waitForPush(t *testing.T, timeout time.Duration) {
	t.Helper()
	select {
	case <-s.notif:
	case <-time.After(timeout):
		t.Fatal("timed out waiting for push")
	}
}

func (s *stubPushSink) snapshot() []*mgmProto.PeerConnectionMap {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]*mgmProto.PeerConnectionMap, len(s.pushes))
	copy(out, s.pushes)
	return out
}

type stubPeerStateSource struct {
	mu       sync.Mutex
	snapshot []PeerStateChangeEvent
}

func (s *stubPeerStateSource) set(es []PeerStateChangeEvent) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.snapshot = es
}

func (s *stubPeerStateSource) SnapshotAllRemotePeers() []PeerStateChangeEvent {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]PeerStateChangeEvent, len(s.snapshot))
	copy(out, s.snapshot)
	return out
}

func TestConnStatePusher_StateChangeIsPushedImmediately(t *testing.T) {
	sink := newStubSink()
	p := newConnStatePusher(sink, nil)
	defer p.Stop()

	p.OnPeerStateChange(PeerStateChangeEvent{
		Pubkey: "peerA", ConnType: mgmProto.ConnType_CONN_TYPE_P2P,
	})
	sink.waitForPush(t, 500*time.Millisecond)

	got := sink.snapshot()
	if len(got) != 1 {
		t.Fatalf("want 1 push, got %d", len(got))
	}
	if got[0].GetFullSnapshot() {
		t.Error("state-change push must not be full snapshot")
	}
}

func TestConnStatePusher_NoExtraPushesWhenSnapshotUnchanged(t *testing.T) {
	sink := newStubSink()
	src := &stubPeerStateSource{}
	src.set([]PeerStateChangeEvent{{Pubkey: "peerA", ConnType: mgmProto.ConnType_CONN_TYPE_P2P, LatencyMS: 10}})
	p := newConnStatePusherForTest(sink, src,
		pusherTuning{baseInterval: 30 * time.Millisecond, maxInterval: 200 * time.Millisecond, doubleAfter: 2})
	defer p.Stop()

	sink.waitForPush(t, 500*time.Millisecond)
	deadline := time.After(200 * time.Millisecond)
	for {
		select {
		case <-deadline:
			if got := sink.snapshot(); len(got) != 1 {
				t.Fatalf("want exactly 1 push (initial snapshot), got %d", len(got))
			}
			return
		case <-sink.notif:
			t.Fatal("unexpected push (delta should have been empty)")
		}
	}
}

func TestConnStatePusher_OnSnapshotRequestSendsFullWithNonceEcho(t *testing.T) {
	sink := newStubSink()
	src := &stubPeerStateSource{}
	src.set([]PeerStateChangeEvent{
		{Pubkey: "peerA", ConnType: mgmProto.ConnType_CONN_TYPE_P2P},
		{Pubkey: "peerB", ConnType: mgmProto.ConnType_CONN_TYPE_RELAYED},
	})
	p := newConnStatePusherForTest(sink, src,
		pusherTuning{baseInterval: time.Hour, maxInterval: time.Hour, doubleAfter: 999})
	defer p.Stop()
	sink.waitForPush(t, 500*time.Millisecond) // initial snapshot
	sink.mu.Lock()
	sink.pushes = nil
	sink.mu.Unlock()

	p.OnSnapshotRequest(42)
	sink.waitForPush(t, 500*time.Millisecond)

	got := sink.snapshot()
	if len(got) != 1 {
		t.Fatalf("want 1 push, got %d", len(got))
	}
	if !got[0].GetFullSnapshot() {
		t.Error("snapshot-request push must be full")
	}
	if got[0].GetInResponseToNonce() != 42 {
		t.Errorf("want nonce echo 42, got %d", got[0].GetInResponseToNonce())
	}
	if len(got[0].GetEntries()) != 2 {
		t.Errorf("want 2 entries, got %d", len(got[0].GetEntries()))
	}
}
