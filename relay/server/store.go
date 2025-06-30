package server

import (
	"github.com/netbirdio/netbird/relay/messages"
	"sync"
)

type IPeer interface {
	Close()
	ID() messages.PeerID
}

// Store is a thread-safe store of peers
// It is used to store the peers that are connected to the relay server
type Store struct {
	peers     map[messages.PeerID]IPeer
	peersLock sync.RWMutex
}

// NewStore creates a new Store instance
func NewStore() *Store {
	return &Store{
		peers: make(map[messages.PeerID]IPeer),
	}
}

// AddPeer adds a peer to the store
func (s *Store) AddPeer(peer IPeer) {
	s.peersLock.Lock()
	defer s.peersLock.Unlock()
	odlPeer, ok := s.peers[peer.ID()]
	if ok {
		odlPeer.Close()
	}

	s.peers[peer.ID()] = peer
}

// DeletePeer deletes a peer from the store
func (s *Store) DeletePeer(peer IPeer) {
	s.peersLock.Lock()
	defer s.peersLock.Unlock()

	dp, ok := s.peers[peer.ID()]
	if !ok {
		return
	}
	if dp != peer {
		return
	}

	delete(s.peers, peer.ID())
}

// Peer returns a peer by its ID
func (s *Store) Peer(id messages.PeerID) (IPeer, bool) {
	s.peersLock.RLock()
	defer s.peersLock.RUnlock()

	p, ok := s.peers[id]
	return p, ok
}

// Peers returns all the peers in the store
func (s *Store) Peers() []IPeer {
	s.peersLock.RLock()
	defer s.peersLock.RUnlock()

	peers := make([]IPeer, 0, len(s.peers))
	for _, p := range s.peers {
		peers = append(peers, p)
	}
	return peers
}
