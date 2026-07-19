package activity

import (
	"errors"
	"net"
	"net/netip"
	"sync"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/iface/wgaddr"
	"github.com/netbirdio/netbird/client/internal/lazyconn"
	peerid "github.com/netbirdio/netbird/client/internal/peer/id"
)

// listener defines the contract for activity detection listeners.
type listener interface {
	ReadPackets()
	Close()
	CapturedPacket() []byte
}

// Event reports activity on a managed peer. FirstPacket is the bytes that triggered activation,
// captured for reinjection through the real transport.
type Event struct {
	PeerConnID  peerid.ConnID
	FirstPacket []byte
}

type WgInterface interface {
	IdlePeerEndpoint(peerKey string, allowedIPs []netip.Prefix, endpoint *net.UDPAddr) error
	IsUserspaceBind() bool
	Address() wgaddr.Address
	MTU() uint16
}

type Manager struct {
	OnActivityChan chan Event

	wgIface WgInterface

	peers map[peerid.ConnID]listener
	done  chan struct{}

	mu sync.Mutex
}

func NewManager(wgIface WgInterface) *Manager {
	m := &Manager{
		OnActivityChan: make(chan Event, 1),
		wgIface:        wgIface,
		peers:          make(map[peerid.ConnID]listener),
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

	listener, err := m.createListener(peerCfg)
	if err != nil {
		return err
	}

	m.peers[peerCfg.PeerConnID] = listener
	go m.waitForTraffic(listener, peerCfg.PeerConnID)
	return nil
}

func (m *Manager) createListener(peerCfg lazyconn.PeerConfig) (listener, error) {
	if !m.wgIface.IsUserspaceBind() {
		return NewUDPListener(m.wgIface, peerCfg)
	}

	provider, ok := m.wgIface.(bindProvider)
	if !ok {
		return nil, errors.New("interface claims userspace bind but doesn't implement bindProvider")
	}

	return NewBindListener(m.wgIface, provider.GetBind(), peerCfg)
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

func (m *Manager) waitForTraffic(l listener, peerConnID peerid.ConnID) {
	l.ReadPackets()

	m.mu.Lock()
	if _, ok := m.peers[peerConnID]; !ok {
		m.mu.Unlock()
		return
	}
	delete(m.peers, peerConnID)
	m.mu.Unlock()

	m.notify(Event{PeerConnID: peerConnID, FirstPacket: l.CapturedPacket()})
}

func (m *Manager) notify(ev Event) {
	select {
	case <-m.done:
	case m.OnActivityChan <- ev:
	}
}
