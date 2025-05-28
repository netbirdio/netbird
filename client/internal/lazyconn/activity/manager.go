package activity

import (
	"sync"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/internal/lazyconn"
	peerid "github.com/netbirdio/netbird/client/internal/peer/id"
)

type Manager struct {
	OnActivityChan chan peerid.ConnID

	wgIface lazyconn.WGIface

	peers map[peerid.ConnID]*Listener
	done  chan struct{}

	mu sync.Mutex
}

func NewManager(wgIface lazyconn.WGIface) *Manager {
	m := &Manager{
		OnActivityChan: make(chan peerid.ConnID, 1),
		wgIface:        wgIface,
		peers:          make(map[peerid.ConnID]*Listener),
		done:           make(chan struct{}),
	}
	return m
}

func (m *Manager) MonitorPeerActivity(peerCfg lazyconn.PeerConfig) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, ok := m.peers[peerCfg.PeerConnID]; ok {
		log.Warnf("activity listener already exists for: %s", peerCfg.PublicKey)
		return nil
	}

	listener, err := NewListener(m.wgIface, peerCfg)
	if err != nil {
		return err
	}
	m.peers[peerCfg.PeerConnID] = listener

	go m.waitForTraffic(listener, peerCfg.PeerConnID)
	return nil
}

func (m *Manager) RemovePeer(log *log.Entry, peerConnID peerid.ConnID) {
	m.mu.Lock()
	defer m.mu.Unlock()

	listener, ok := m.peers[peerConnID]
	if !ok {
		return
	}
	log.Debugf("removing activity listener")
	delete(m.peers, peerConnID)
	listener.Close()
}

func (m *Manager) Close() {
	m.mu.Lock()
	defer m.mu.Unlock()

	close(m.done)
	for peerID, listener := range m.peers {
		delete(m.peers, peerID)
		listener.Close()
	}
}

func (m *Manager) waitForTraffic(listener *Listener, peerConnID peerid.ConnID) {
	listener.ReadPackets()

	m.mu.Lock()
	if _, ok := m.peers[peerConnID]; !ok {
		m.mu.Unlock()
		return
	}
	delete(m.peers, peerConnID)
	m.mu.Unlock()

	m.notify(peerConnID)
}

func (m *Manager) notify(peerConnID peerid.ConnID) {
	select {
	case <-m.done:
	case m.OnActivityChan <- peerConnID:
	}
}
