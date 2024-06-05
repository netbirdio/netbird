package server

import (
	"sync"
)

type Store struct {
	peers     map[string]*Peer // consider to use [32]byte as key. The Peer(id string) would be faster
	peersLock sync.RWMutex
}

func NewStore() *Store {
	return &Store{
		peers: make(map[string]*Peer),
	}
}

func (s *Store) AddPeer(peer *Peer) {
	s.peersLock.Lock()
	defer s.peersLock.Unlock()
	s.peers[peer.String()] = peer
}

func (s *Store) DeletePeer(peer *Peer) {
	s.peersLock.Lock()
	defer s.peersLock.Unlock()
	delete(s.peers, peer.String())
}

func (s *Store) Peer(id string) (*Peer, bool) {
	s.peersLock.RLock()
	defer s.peersLock.RUnlock()

	p, ok := s.peers[id]
	return p, ok
}

func (s *Store) Peers() []*Peer {
	s.peersLock.RLock()
	defer s.peersLock.RUnlock()

	peers := make([]*Peer, 0, len(s.peers))
	for _, p := range s.peers {
		peers = append(peers, p)
	}
	return peers
}
