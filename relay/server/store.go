package server

import (
	"sync"
)

type Store struct {
	peers     map[string]*Peer // Key is the id (public key or sha-256) of the peer
	peersLock sync.Mutex
}

func NewStore() *Store {
	return &Store{
		peers: make(map[string]*Peer),
	}
}

func (s *Store) AddPeer(peer *Peer) {
	s.peersLock.Lock()
	defer s.peersLock.Unlock()
	s.peers[peer.ID()] = peer
}

func (s *Store) Link(peer *Peer, peerForeignID string) uint16 {
	s.peersLock.Lock()
	defer s.peersLock.Unlock()

	channelId := peer.BindChannel(peerForeignID)
	dstPeer, ok := s.peers[peerForeignID]
	if !ok {
		return channelId
	}

	foreignChannelID, ok := dstPeer.AddParticipant(peer, channelId)
	if !ok {
		return channelId
	}
	peer.AddParticipant(dstPeer, foreignChannelID)
	return channelId
}

func (s *Store) DeletePeer(peer *Peer) {
	s.peersLock.Lock()
	defer s.peersLock.Unlock()

	delete(s.peers, peer.ID())
	peer.DeleteParticipants()
}
