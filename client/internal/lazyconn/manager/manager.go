package manager

import (
	"context"
	"fmt"
	"sync"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/internal/lazyconn"
	"github.com/netbirdio/netbird/client/internal/lazyconn/listener"
	"github.com/netbirdio/netbird/client/internal/peer"
)

// Manager manages lazy connections
// This is not a thread safe implementation, do not call exported functions concurrently
type Manager struct {
	OnDemand chan string
	Idle     chan string

	listenerMgr  *listener.Manager
	managedPeers map[string]lazyconn.PeerConfig
	idleWatch    map[string]*IdleWatch

	excludes       map[string]struct{}
	managedPeersMu sync.Mutex
	closeChan      chan struct{}
}

func NewManager(wgIface lazyconn.WGIface, connStateDispatcher *peer.ConnectionDispatcher) *Manager {
	m := &Manager{
		OnDemand: make(chan string, 1),
		Idle:     make(chan string, 1),

		listenerMgr:  listener.NewManager(wgIface),
		managedPeers: make(map[string]lazyconn.PeerConfig),
		idleWatch:    make(map[string]*IdleWatch),
		excludes:     make(map[string]struct{}),
		closeChan:    make(chan struct{}),
	}

	connStateListener := &peer.ConnectionListener{
		OnConnected:    m.onPeerConnected,
		OnDisconnected: m.onPeerDisconnected,
	}

	connStateDispatcher.AddListener(connStateListener)
	e.connStateListener = connStateListener

	return m
}

func (m *Manager) AddPeer(peer lazyconn.PeerConfig) (bool, error) {
	m.managedPeersMu.Lock()
	defer m.managedPeersMu.Unlock()

	log.Debugf("adding lazy peer: %s", peer.PublicKey)

	_, exists := m.excludes[peer.PublicKey]
	if exists {
		return true, nil
	}

	if _, ok := m.managedPeers[peer.PublicKey]; ok {
		log.Warnf("peer already managed: %s", peer.PublicKey)
		return false, nil
	}

	if err := m.listenerMgr.CreatePeerListener(peer); err != nil {
		return false, err
	}

	m.managedPeers[peer.PublicKey] = peer
	return false, nil
}

func (m *Manager) RemovePeer(peerID string) bool {
	m.managedPeersMu.Lock()
	defer m.managedPeersMu.Unlock()

	if _, ok := m.managedPeers[peerID]; !ok {
		return false
	}

	log.Debugf("removing lazy peer: %s", peerID)

	if idleWatch, ok := m.idleWatch[peerID]; ok {
		idleWatch.Stop()
		delete(m.idleWatch, peerID)
	}

	m.listenerMgr.RemovePeer(peerID)
	delete(m.managedPeers, peerID)
	return true
}

func (m *Manager) ExcludePeer(peerID string) {
	m.managedPeersMu.Lock()
	defer m.managedPeersMu.Unlock()

	m.excludes[peerID] = struct{}{}
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

func (m *Manager) Start(ctx context.Context) (string, error) {
	for {
		select {
		case <-m.closeChan:
			return "", fmt.Errorf("service closed")
		case <-ctx.Done():
			return "", ctx.Err()
		case e := <-m.listenerMgr.TrafficStartChan:
			m.managedPeersMu.Lock()
			pcfg, ok := m.managedPeers[e.PeerID]
			if !ok {
				m.managedPeersMu.Unlock()
				continue
			}

			if pcfg.PeerConnID != e.PeerConnId {
				m.managedPeersMu.Unlock()
				continue
			}

			idleWatch := NewIdleWatch()
			idleWatch.Start(ctx)
			m.idleWatch[e.PeerID] = idleWatch

			m.managedPeersMu.Unlock()
			return e.PeerID, nil
		}
	}
}

/*
func (m *Manager) NextOpenEvent(ctx context.Context) (string, error) {
	for {
		select {
		case <-m.closeChan:
			return "", fmt.Errorf("service closed")
		case <-ctx.Done():
			return "", ctx.Err()
		case e := <-m.listenerMgr.TrafficStartChan:
			m.managedPeersMu.Lock()
			pcfg, ok := m.managedPeers[e.PeerID]
			if !ok {
				m.managedPeersMu.Unlock()
				continue
			}

			if pcfg.PeerConnID != e.PeerConnId {
				m.managedPeersMu.Unlock()
				continue
			}

			idleWatch := NewIdleWatch()
			idleWatch.Start(ctx)
			m.idleWatch[e.PeerID] = idleWatch

			m.managedPeersMu.Unlock()
			return e.PeerID, nil
		}
	}
}

*/

func (m *Manager) onPeerConnected(conn *peer.Conn) {
	m.managedPeersMu.Lock()
	defer m.managedPeersMu.Unlock()

	if _, ok := m.excludes[conn.GetKey()]; ok {
		return
	}

	iw, ok := m.idleWatch[conn.GetKey()]
	if !ok {
		conn.Log.Errorf("idle watch not found for peer")
	}

	iw.HangUp()
}

func (m *Manager) onPeerDisconnected(conn *peer.Conn) {
	m.managedPeersMu.Lock()
	defer m.managedPeersMu.Unlock()

	if _, ok := m.excludes[conn.GetKey()]; ok {
		return
	}

	iw, ok := m.idleWatch[conn.GetKey()]
	if !ok {
		conn.Log.Errorf("idle watch not found for peer")
	}

	iw.Reset()
}
