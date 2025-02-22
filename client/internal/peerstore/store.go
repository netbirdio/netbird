package peerstore

import (
	"net/netip"
	"sync"

	"golang.org/x/exp/maps"

	"github.com/netbirdio/netbird/client/internal/peer"
)

// Store is a thread-safe store for peer connections.
type Store struct {
	peerConns   map[string]*peer.Conn
	peerConnsMu sync.RWMutex
}

func NewConnStore() *Store {
	return &Store{
		peerConns: make(map[string]*peer.Conn),
	}
}

func (s *Store) AddPeerConn(pubKey string, conn *peer.Conn) bool {
	s.peerConnsMu.Lock()
	defer s.peerConnsMu.Unlock()

	_, ok := s.peerConns[pubKey]
	if ok {
		return false
	}

	s.peerConns[pubKey] = conn
	return true
}

func (s *Store) Remove(pubKey string) (*peer.Conn, bool) {
	s.peerConnsMu.Lock()
	defer s.peerConnsMu.Unlock()

	p, ok := s.peerConns[pubKey]
	if !ok {
		return nil, false
	}
	delete(s.peerConns, pubKey)
	return p, true
}

func (s *Store) AllowedIPs(pubKey string) ([]netip.Prefix, bool) {
	s.peerConnsMu.RLock()
	defer s.peerConnsMu.RUnlock()

	p, ok := s.peerConns[pubKey]
	if !ok {
		return nil, false
	}
	return p.WgConfig().AllowedIps, true
}

func (s *Store) AllowedIP(pubKey string) (netip.Addr, bool) {
	s.peerConnsMu.RLock()
	defer s.peerConnsMu.RUnlock()

	p, ok := s.peerConns[pubKey]
	if !ok {
		return netip.Addr{}, false
	}
	return p.AllowedIP(), true
}

func (s *Store) PeerConn(pubKey string) (*peer.Conn, bool) {
	s.peerConnsMu.RLock()
	defer s.peerConnsMu.RUnlock()

	p, ok := s.peerConns[pubKey]
	if !ok {
		return nil, false
	}
	return p, true
}

func (s *Store) PeersPubKey() []string {
	s.peerConnsMu.RLock()
	defer s.peerConnsMu.RUnlock()

	return maps.Keys(s.peerConns)
}
