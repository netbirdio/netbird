package manager

import (
	"context"
	"sync"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/internal/lazyconn"
	"github.com/netbirdio/netbird/client/internal/lazyconn/listener"
)

// Manager manages lazy connections
// This is not a thread safe implementation, do not call exported functions concurrently
type Manager struct {
	PeerActivityChan chan string

	listenerMgr    *listener.Manager
	managedPeers   map[string]lazyconn.PeerConfig
	managedPeersMu sync.Mutex

	ctxCancel context.CancelFunc
	wg        sync.WaitGroup
}

func NewManager(wgIface lazyconn.WGIface) *Manager {
	m := &Manager{
		PeerActivityChan: make(chan string, 1),
		listenerMgr:      listener.NewManager(wgIface),
		managedPeers:     make(map[string]lazyconn.PeerConfig),
	}
	return m
}

// Start to listen for traffic start events
func (m *Manager) Start(parentCtx context.Context) {
	ctx, cancel := context.WithCancel(parentCtx)
	m.ctxCancel = cancel

	m.wg.Add(1)

	go func() {
		defer m.wg.Done()
		defer cancel()
		m.receiveLazyConnEvents(ctx)
	}()
}

func (m *Manager) AddPeer(peer lazyconn.PeerConfig) error {
	m.managedPeersMu.Lock()
	defer m.managedPeersMu.Unlock()

	log.Debugf("adding lazy peer: %s", peer.PublicKey)

	if _, ok := m.managedPeers[peer.PublicKey]; ok {
		log.Warnf("peer already managed: %s", peer.PublicKey)
		return nil
	}

	if err := m.listenerMgr.CreateFakePeer(peer); err != nil {
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

	m.ctxCancel()

	m.listenerMgr.Close()
	m.wg.Wait()
	m.managedPeers = make(map[string]lazyconn.PeerConfig)

	// clean up the channel for the future reuse
	m.drainPeerActivityChan()
}

func (m *Manager) receiveLazyConnEvents(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case peerID := <-m.listenerMgr.TrafficStartChan:
			m.notifyPeerAction(ctx, peerID)
		}
	}
}

func (m *Manager) notifyPeerAction(ctx context.Context, peerID string) {
	select {
	case <-ctx.Done():
	case m.PeerActivityChan <- peerID:
	}
}

func (m *Manager) drainPeerActivityChan() {
	for {
		select {
		case <-m.PeerActivityChan:
		default:
			return
		}
	}
}
