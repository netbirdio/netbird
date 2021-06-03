package peer

import (
	"testing"
)

func TestRegistry_Register(t *testing.T) {
	r := NewRegistry()
	peer1 := NewPeer("test_peer_1", nil)
	peer2 := NewPeer("test_peer_2", nil)
	r.Register(peer1)
	r.Register(peer2)

	if len(r.Peers) != 2 {
		t.Errorf("expected 2 registered peers")
	}

	if _, ok := r.Peers["test_peer_1"]; !ok {
		t.Errorf("expected test_peer_1 not found in the registry")
	}

	if _, ok := r.Peers["test_peer_2"]; !ok {
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

	if len(r.Peers) != 1 {
		t.Errorf("expected 1 registered peers after deregistring")
	}

	if _, ok := r.Peers["test_peer_1"]; ok {
		t.Errorf("expected test_peer_1 to absent in the registry after deregistering")
	}

	if _, ok := r.Peers["test_peer_2"]; !ok {
		t.Errorf("expected test_peer_2 not found in the registry")
	}

}
