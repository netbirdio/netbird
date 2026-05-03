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
	r.Unregister("peerA", ch)
	if _, ok := <-ch; ok {
		t.Error("channel should be closed after Unregister")
	}
}

func TestSnapshotRouter_StaleUnregisterDoesNotEvictNewStream(t *testing.T) {
	r := NewSnapshotRouter()
	old := r.Register("peerA")
	// Second Register simulates a fast reconnect: it must close the
	// previous channel and replace it.
	fresh := r.Register("peerA")
	if _, ok := <-old; ok {
		t.Error("old channel should be closed when a second Register comes in")
	}
	// Stale stream calling Unregister with the (now-closed) old token
	// must not touch the fresh channel.
	r.Unregister("peerA", old)
	select {
	case _, ok := <-fresh:
		if !ok {
			t.Error("fresh channel must not be closed by stale Unregister")
		}
	default:
		// expected: channel still open and empty
	}
	// Proper Unregister with the fresh token tears it down.
	r.Unregister("peerA", fresh)
	if _, ok := <-fresh; ok {
		t.Error("fresh channel should be closed after its own Unregister")
	}
}
