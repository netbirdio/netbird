package peer_connections

import "testing"

func TestSnapshotRouter_RegisterAndRequest(t *testing.T) {
	r := NewSnapshotRouter()
	ch := r.Register("peerA-pubkey")
	if !r.Request("peerA-pubkey", 42) {
		t.Fatal("Request should return true for registered peer")
	}
	select {
	case n := <-ch:
		if n != 42 {
			t.Errorf("want nonce 42, got %d", n)
		}
	default:
		t.Fatal("nonce was not delivered to channel")
	}
}

func TestSnapshotRouter_RequestUnregisteredPeer(t *testing.T) {
	r := NewSnapshotRouter()
	if r.Request("ghost", 1) {
		t.Error("Request for unregistered peer should return false")
	}
}

func TestSnapshotRouter_UnregisterClosesChannel(t *testing.T) {
	r := NewSnapshotRouter()
	ch := r.Register("peerA")
	r.Unregister("peerA")
	if _, ok := <-ch; ok {
		t.Error("channel should be closed after Unregister")
	}
}
