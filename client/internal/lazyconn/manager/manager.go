package manager

import (
	"context"
	"fmt"
	"sync"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/internal/lazyconn"
	"github.com/netbirdio/netbird/client/internal/lazyconn/listener"
)

// Manager manages lazy connections
// This is not a thread safe implementation, do not call exported functions concurrently
type Manager struct {
	listenerMgr    *listener.Manager
	managedPeers   map[string]lazyconn.PeerConfig
	managedPeersMu sync.Mutex
	closeChan      chan struct{}
}

func NewManager(wgIface lazyconn.WGIface) *Manager {
	m := &Manager{
		listenerMgr:  listener.NewManager(wgIface),
		managedPeers: make(map[string]lazyconn.PeerConfig),
	}
	return m
}

func (m *Manager) AddPeer(peer lazyconn.PeerConfig) error {
	m.managedPeersMu.Lock()
	defer m.managedPeersMu.Unlock()

	log.Debugf("adding lazy peer: %s", peer.PublicKey)

	if _, ok := m.managedPeers[peer.PublicKey]; ok {
		log.Warnf("peer already managed: %s", peer.PublicKey)
		return nil
	}

	if err := m.listenerMgr.CreatePeerListener(peer); err != nil {
		return err
	}

	m.managedPeers[peer.PublicKey] = peer
	return nil
}

func (m *Manager) RemovePeer(peerID string) bool {
	m.managedPeersMu.Lock()
	defer m.managedPeersMu.Unlock()

	if _, ok := m.managedPeers[peerID]; !ok {
		return false
	}

	log.Debugf("removing lazy peer: %s", peerID)

	m.listenerMgr.RemovePeer(peerID)
	delete(m.managedPeers, peerID)
	return true
}

// Close the manager and all the listeners
// block until all routine are done and cleanup the exported Channels
func (m *Manager) Close() {
	m.managedPeersMu.Lock()
	defer m.managedPeersMu.Unlock()

	// todo prevent double call
	close(m.closeChan)

	m.listenerMgr.Close()

	m.managedPeers = make(map[string]lazyconn.PeerConfig)
}

func (m *Manager) NextEvent(ctx context.Context) (string, error) {
	for {
		select {
		case <-m.closeChan:
			return "", fmt.Errorf("service closed")
		case <-ctx.Done():
			return "", ctx.Err()
		case e := <-m.listenerMgr.TrafficStartChan:
			m.managedPeersMu.Lock()
			// todo instead of peer ID check, check by the peer conn instance id
			pcfg, ok := m.managedPeers[e.PeerID]
			if !ok {
				m.managedPeersMu.Unlock()
				continue
			}

			if pcfg.PeerConnID != e.PeerConnId {
				m.managedPeersMu.Unlock()
				continue
			}

			m.managedPeersMu.Unlock()
			return e.PeerID, nil
		}
	}
}
