package server

import (
	"testing"
)

func TestStore_DeletePeer(t *testing.T) {
	s := NewStore()
	p := NewPeer([]byte("peer_one"), nil, nil)
	s.AddPeer(p)
	s.DeletePeer(p)
	if _, ok := s.Peer(p.String()); ok {
		t.Errorf("peer was not deleted")
	}
}

func TestStore_DeleteDeprecatedPeer(t *testing.T) {
	s := NewStore()

	p1 := NewPeer([]byte("peer_id"), nil, nil)
	p2 := NewPeer([]byte("peer_id"), nil, nil)

	s.AddPeer(p1)
	s.AddPeer(p2)
	s.DeletePeer(p1)

	if _, ok := s.Peer(p2.String()); !ok {
		t.Errorf("second peer was deleted")
	}
}
