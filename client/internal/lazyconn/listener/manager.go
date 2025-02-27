package listener

import (
	"fmt"
	"sync"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/internal/lazyconn"
)

type Manager struct {
	TrafficStartChan chan string

	wgIface lazyconn.WGIface

	portGenerator *portAllocator
	peers         map[string]*Listener
	done          chan struct{}

	mu sync.Mutex
}

func NewManager(wgIface lazyconn.WGIface) *Manager {
	m := &Manager{
		TrafficStartChan: make(chan string, 1),
		wgIface:          wgIface,
		portGenerator:    newPortAllocator(),
		peers:            make(map[string]*Listener),
		done:             make(chan struct{}),
	}
	return m
}

func (m *Manager) CreatePeerListener(peerCfg lazyconn.PeerConfig) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, ok := m.peers[peerCfg.PublicKey]; ok {
		return nil
	}

	conn, addr, err := m.portGenerator.newConn()
	if err != nil {
		return fmt.Errorf("failed to bind lazy connection: %v", err)
	}

	listener, err := NewListener(m.wgIface, peerCfg, conn, addr)
	if err != nil {
		return err
	}
	m.peers[peerCfg.PublicKey] = listener

	log.Infof("created on-demand listener: %s, for peer: %s", addr.String(), peerCfg.PublicKey)
	go m.waitForTraffic(listener, peerCfg.PublicKey)

	log.Debugf("created lazy connection listener for: %s", peerCfg.PublicKey)
	return nil
}

func (m *Manager) RemovePeer(peerID string) {
	m.mu.Lock()
	listener, ok := m.peers[peerID]
	if !ok {
		m.mu.Unlock()
		return
	}
	delete(m.peers, peerID)
	listener.Close()
	m.mu.Unlock()
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

func (m *Manager) waitForTraffic(listener *Listener, peerID string) {
	listener.ReadPackets()

	m.mu.Lock()
	if _, ok := m.peers[peerID]; !ok {
		return
	}
	delete(m.peers, peerID)
	m.mu.Unlock()

	m.notify(peerID)
}

// todo: cause issue in this scenario
// - notify peerID to TrafficStartChan
// - do not read the upper layer yet the event
// - RemovePeer(peerID string)
// at this moment we expect to never receive the event for peerID
// - read from TrafficStartChan and the event will be there
func (m *Manager) notify(peerID string) {
	log.Debugf("peer started to send traffic, remove lazy endpoint: %s", peerID)
	select {
	case <-m.done:
	case m.TrafficStartChan <- peerID:
	}
}
