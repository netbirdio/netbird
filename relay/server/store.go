package server

import (
	"sync"
)

// Store is a thread-safe store of peers
// It is used to store the peers that are connected to the relay server
type Store struct {
	peers     map[string]*Peer // consider to use [32]byte as key. The Peer(id string) would be faster
	peersLock sync.RWMutex
}

// NewStore creates a new Store instance
func NewStore() *Store {
	return &Store{
		peers: make(map[string]*Peer),
	}
}

// AddPeer adds a peer to the store
func (s *Store) AddPeer(peer *Peer) {
	s.peersLock.Lock()
	defer s.peersLock.Unlock()
	odlPeer, ok := s.peers[peer.String()]
	if ok {
		odlPeer.Close()
	}

	s.peers[peer.String()] = peer
}

// DeletePeer deletes a peer from the store
func (s *Store) DeletePeer(peer *Peer) {
	s.peersLock.Lock()
	defer s.peersLock.Unlock()

	dp, ok := s.peers[peer.String()]
	if !ok {
		return
	}
	if dp != peer {
		return
	}

	delete(s.peers, peer.String())
}

// Peer returns a peer by its ID
func (s *Store) Peer(id string) (*Peer, bool) {
	s.peersLock.RLock()
	defer s.peersLock.RUnlock()

	p, ok := s.peers[id]
	return p, ok
}

// Peers returns all the peers in the store
func (s *Store) Peers() []*Peer {
	s.peersLock.RLock()
	defer s.peersLock.RUnlock()

	peers := make([]*Peer, 0, len(s.peers))
	for _, p := range s.peers {
		peers = append(peers, p)
	}
	return peers
}
