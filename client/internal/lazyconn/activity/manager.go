package activity

import (
	"fmt"
	"sync"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/internal/lazyconn"
	peerid "github.com/netbirdio/netbird/client/internal/peer/id"
)

type OnAcitvityEvent struct {
	PeerID     string
	PeerConnId peerid.ConnID
}

type Manager struct {
	OnActivityChan chan OnAcitvityEvent

	wgIface lazyconn.WGIface

	portGenerator *portAllocator
	peers         map[string]*Listener
	done          chan struct{}

	mu sync.Mutex
}

func NewManager(wgIface lazyconn.WGIface) *Manager {
	m := &Manager{
		OnActivityChan: make(chan OnAcitvityEvent, 1),
		wgIface:        wgIface,
		portGenerator:  newPortAllocator(),
		peers:          make(map[string]*Listener),
		done:           make(chan struct{}),
	}
	return m
}

func (m *Manager) MonitorPeerActivity(peerCfg lazyconn.PeerConfig) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, ok := m.peers[peerCfg.PublicKey]; ok {
		log.Warnf("activity listener already exists for: %s", peerCfg.PublicKey)
		return nil
	}

	conn, addr, err := m.portGenerator.newConn()
	if err != nil {
		return fmt.Errorf("failed to bind activity listener: %v", err)
	}

	listener, err := NewListener(m.wgIface, peerCfg, conn, addr)
	if err != nil {
		return err
	}
	m.peers[peerCfg.PublicKey] = listener

	go m.waitForTraffic(listener, peerCfg.PublicKey, peerCfg.PeerConnID)
	return nil
}

func (m *Manager) RemovePeer(log *log.Entry, peerID string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	listener, ok := m.peers[peerID]
	if !ok {
		return
	}
	log.Debugf("removing activity listener")
	delete(m.peers, peerID)
	listener.Close()
}

func (m *Manager) Close() {
	m.mu.Lock()
	defer m.mu.Unlock()

	close(m.done)
	for peerID, listener := range m.peers {
		listener.Close()
		delete(m.peers, peerID)
	}
}

func (m *Manager) waitForTraffic(listener *Listener, peerID string, peerConnID peerid.ConnID) {
	listener.ReadPackets()

	m.mu.Lock()
	if _, ok := m.peers[peerID]; !ok {
		m.mu.Unlock()
		return
	}
	delete(m.peers, peerID)
	m.mu.Unlock()

	m.notify(OnAcitvityEvent{PeerID: peerID, PeerConnId: peerConnID})
}

func (m *Manager) notify(event OnAcitvityEvent) {
	log.Debugf("peer activity detected: %s", event.PeerID)
	select {
	case <-m.done:
	case m.OnActivityChan <- event:
	}
}
