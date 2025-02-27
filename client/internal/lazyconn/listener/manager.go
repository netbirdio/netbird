package listener

import (
	"fmt"
	"net"
	"sync"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/internal/lazyconn"
)

type Manager struct {
	TrafficStartChan chan string

	wgIface lazyconn.WGIface

	portGenerator *portAllocator
	// todo peers add/remove is not thread safe because of the callback function
	peers map[string]*Listener
	wg    sync.WaitGroup
	done  chan struct{}
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
	if _, ok := m.peers[peerCfg.PublicKey]; ok {
		return nil
	}

	if err := m.createPeerlistener(peerCfg); err != nil {
		return err
	}
	log.Debugf("created lazy connection listener for: %s", peerCfg.PublicKey)
	return nil
}

func (m *Manager) RemovePeer(peerID string) {
	listener, ok := m.peers[peerID]
	if !ok {
		return
	}

	listener.Close()

	m.removeEndpoint(peerID)

	delete(m.peers, peerID)
}

func (m *Manager) Close() {
	close(m.done)
	for peerID, listener := range m.peers {
		listener.Close()
		delete(m.peers, peerID)
	}
	m.wg.Wait()
}

func (m *Manager) createPeerlistener(peerCfg lazyconn.PeerConfig) error {
	conn, addr, err := m.portGenerator.newConn()
	if err != nil {
		return fmt.Errorf("failed to bind lazy connection: %v", err)
	}

	listener := NewListener(peerCfg.PublicKey, conn)

	if err := m.createEndpoint(peerCfg, addr); err != nil {
		log.Errorf("failed to create endpoint for %s: %v", peerCfg.PublicKey, err)
		listener.Close()
		return err
	}

	log.Infof("created on-demand listener: %s, for peer: %s", addr.String(), peerCfg.PublicKey)

	m.wg.Add(1)
	go func() {
		defer m.wg.Done()
		listener.ReadPackets(m.onTrigger)
	}()

	m.peers[peerCfg.PublicKey] = listener
	return nil
}

// todo: it is not thread safe, but it is ok if we protect from upper layer
func (m *Manager) onTrigger(peerID string) {
	log.Debugf("peer started to send traffic, remove lazy endpoint: %s", peerID)
	m.removeEndpoint(peerID)
	delete(m.peers, peerID)

	select {
	case <-m.done:
	case m.TrafficStartChan <- peerID:
	}
}

func (m *Manager) removeEndpoint(peerID string) {
	if err := m.wgIface.RemovePeer(peerID); err != nil {
		log.Warnf("failed to remove peer listener: %v", err)
	}
}

func (m *Manager) createEndpoint(peerCfg lazyconn.PeerConfig, endpoint *net.UDPAddr) error {
	return m.wgIface.UpdatePeer(peerCfg.PublicKey, peerCfg.AllowedIPs, 0, endpoint, nil)
}
