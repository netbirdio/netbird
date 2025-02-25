package listener

import (
	"fmt"
	"net"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/internal/lazyconn"
)

type portGenerator struct {
	nextFreePort uint16
}

func newPortGenerator() *portGenerator {
	return &portGenerator{
		nextFreePort: 65535,
	}
}

func (p *portGenerator) nextPort() int {
	port := p.nextFreePort
	p.nextFreePort--
	if p.nextFreePort == 0 {
		p.nextFreePort = 65535
	}
	return int(port)
}

type Manager struct {
	TrafficStartChan chan string

	wgIface lazyconn.WGIface

	portGenerator *portGenerator
	// todo peers add/remove is not thread safe because of the callback function
	peers map[string]*Listener
	done  chan struct{}
}

func NewManager(wgIface lazyconn.WGIface) *Manager {
	m := &Manager{
		TrafficStartChan: make(chan string, 1),
		wgIface:          wgIface,
		portGenerator:    newPortGenerator(),
		peers:            make(map[string]*Listener),
		done:             make(chan struct{}),
	}
	return m
}

func (m *Manager) CreateFakePeer(peerCfg lazyconn.PeerConfig) error {
	if _, ok := m.peers[peerCfg.PublicKey]; ok {
		return nil
	}

	if err := m.createFakePeer(peerCfg); err != nil {
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

	if err := m.wgIface.RemovePeer(peerID); err != nil {
		log.Warnf("failed to remove fake peer: %v", err)
	}

	delete(m.peers, peerID)
}

func (m *Manager) Close() {
	close(m.done)
	for peerID, listener := range m.peers {
		listener.Close()
		delete(m.peers, peerID)
	}
}

func (m *Manager) createFakePeer(peerCfg lazyconn.PeerConfig) error {
	var (
		listener *Listener
		err      error
		addr     *net.UDPAddr
	)
	for i := 0; i < 100; i++ {
		addr = &net.UDPAddr{
			Port: m.portGenerator.nextPort(),
			IP:   net.ParseIP("127.0.0.254"),
		}
		listener, err = NewListener(peerCfg.PublicKey, addr)
		if err != nil {
			log.Debugf("failed to allocate port: %d: %v", addr.Port, err)
			continue
		}
	}

	if listener == nil {
		return fmt.Errorf("failed to allocate lazy connection port for: %s", peerCfg.PublicKey)
	}

	if err := m.createEndpoint(peerCfg, addr); err != nil {
		log.Errorf("failed to create endpoint for %s: %v", peerCfg.PublicKey, err)
		listener.Close()
		return err
	}

	go listener.ReadPackets(m.onTrigger)

	m.peers[peerCfg.PublicKey] = listener
	return nil
}

// todo: it is not thread safe, but it is ok if we protect from upper layer
func (m *Manager) onTrigger(peerID string) {
	log.Debugf("peer started to send traffic, remove lazy endpoint: %s", peerID)
	if err := m.wgIface.RemovePeer(peerID); err != nil {
		log.Warnf("failed to remove fake peer: %v", err)
	}

	delete(m.peers, peerID)

	select {
	case <-m.done:
	case m.TrafficStartChan <- peerID:
	}
}

func (m *Manager) createEndpoint(peerCfg lazyconn.PeerConfig, endpoint *net.UDPAddr) error {
	return m.wgIface.UpdatePeer(peerCfg.PublicKey, peerCfg.AllowedIPs, 0, endpoint, nil)
}
