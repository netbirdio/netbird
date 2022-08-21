package peer

import (
	"github.com/stretchr/testify/assert"
	"testing"
	"time"
)

func TestRegistry_ShouldNotDeregisterWhenHasNewerStreamRegistered(t *testing.T) {
	r := NewRegistry()

	peerID := "peer"

	olderPeer := NewPeer(peerID, nil)
	r.Register(olderPeer)
	time.Sleep(time.Nanosecond)

	newerPeer := NewPeer(peerID, nil)
	r.Register(newerPeer)
	registered, _ := r.Get(olderPeer.Id)

	assert.NotNil(t, registered, "peer can't be nil")
	assert.Equal(t, newerPeer, registered)

	r.Deregister(olderPeer)
	registered, _ = r.Get(olderPeer.Id)

	assert.NotNil(t, registered, "peer can't be nil")
	assert.Equal(t, newerPeer, registered)
}

func TestRegistry_GetNonExistentPeer(t *testing.T) {
	r := NewRegistry()

	peer, ok := r.Get("non_existent_peer")

	if peer != nil {
		t.Errorf("expected non_existent_peer not found in the registry")
	}

	if ok {
		t.Errorf("expected non_existent_peer not found in the registry")
	}
}

func TestRegistry_Register(t *testing.T) {
	r := NewRegistry()
	peer1 := NewPeer("test_peer_1", nil)
	peer2 := NewPeer("test_peer_2", nil)
	r.Register(peer1)
	r.Register(peer2)

	if _, ok := r.Get("test_peer_1"); !ok {
		t.Errorf("expected test_peer_1 not found in the registry")
	}

	if _, ok := r.Get("test_peer_2"); !ok {
		t.Errorf("expected test_peer_2 not found in the registry")
	}
}

func TestRegistry_Deregister(t *testing.T) {
	r := NewRegistry()
	peer1 := NewPeer("test_peer_1", nil)
	peer2 := NewPeer("test_peer_2", nil)
	r.Register(peer1)
	r.Register(peer2)

	r.Deregister(peer1)

	if _, ok := r.Get("test_peer_1"); ok {
		t.Errorf("expected test_peer_1 to absent in the registry after deregistering")
	}

	if _, ok := r.Get("test_peer_2"); !ok {
		t.Errorf("expected test_peer_2 not found in the registry")
	}

}
