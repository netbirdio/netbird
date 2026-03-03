package activity

import (
	"errors"
	"net"
	"net/netip"
	"runtime"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/netbirdio/netbird/client/iface/netstack"
	"github.com/netbirdio/netbird/client/iface/wgaddr"
	"github.com/netbirdio/netbird/client/internal/lazyconn"
	peerid "github.com/netbirdio/netbird/client/internal/peer/id"
)

// listener defines the contract for activity detection listeners.
type listener interface {
	ReadPackets()
	Close()
}

type WgInterface interface {
	RemovePeer(peerKey string) error
	UpdatePeer(peerKey string, allowedIps []netip.Prefix, keepAlive time.Duration, endpoint *net.UDPAddr, preSharedKey *wgtypes.Key) error
	IsUserspaceBind() bool
	Address() wgaddr.Address
}

type Manager struct {
	OnActivityChan chan peerid.ConnID

	wgIface WgInterface

	peers map[peerid.ConnID]listener
	done  chan struct{}

	mu sync.Mutex
}

func NewManager(wgIface WgInterface) *Manager {
	m := &Manager{
		OnActivityChan: make(chan peerid.ConnID, 1),
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

	// BindListener is used on Windows, JS, and netstack platforms:
	// - JS: Cannot listen to UDP sockets
	// - Windows: IP_UNICAST_IF socket option forces packets out the interface the default
	//   gateway points to, preventing them from reaching the loopback interface.
	// - Netstack: Allows multiple instances on the same host without port conflicts.
	// BindListener bypasses these issues by passing data directly through the bind.
	if runtime.GOOS != "windows" && runtime.GOOS != "js" && !netstack.IsEnabled() {
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

	m.notify(peerConnID)
}

func (m *Manager) notify(peerConnID peerid.ConnID) {
	select {
	case <-m.done:
	case m.OnActivityChan <- peerConnID:
	}
}
