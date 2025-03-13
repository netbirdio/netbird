package manager

import (
	"context"
	"sync"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/internal/lazyconn"
	"github.com/netbirdio/netbird/client/internal/lazyconn/activity"
	"github.com/netbirdio/netbird/client/internal/lazyconn/inactivity"
	"github.com/netbirdio/netbird/client/internal/peer"
)

// Manager manages lazy connections
// This is not a thread safe implementation, do not call exported functions concurrently
type Manager struct {
	OnDemand chan string
	Idle     chan string

	connStateDispatcher *peer.ConnectionDispatcher
	managedPeers        map[string]lazyconn.PeerConfig
	activityManager     *activity.Manager
	inactivityMonitors  map[string]*inactivity.InactivityMonitor

	excludes          map[string]struct{}
	managedPeersMu    sync.Mutex
	cancel            context.CancelFunc
	connStateListener *peer.ConnectionListener
	onIdle            chan string
}

func NewManager(wgIface lazyconn.WGIface, connStateDispatcher *peer.ConnectionDispatcher) *Manager {
	m := &Manager{
		OnDemand: make(chan string, 1),
		Idle:     make(chan string, 1),

		connStateDispatcher: connStateDispatcher,
		managedPeers:        make(map[string]lazyconn.PeerConfig),
		activityManager:     activity.NewManager(wgIface),
		inactivityMonitors:  make(map[string]*inactivity.InactivityMonitor),
		excludes:            make(map[string]struct{}),
		onIdle:              make(chan string),
	}

	m.connStateListener = &peer.ConnectionListener{
		OnConnected:    m.onPeerConnected,
		OnDisconnected: m.onPeerDisconnected,
	}

	connStateDispatcher.AddListener(m.connStateListener)

	return m
}

func (m *Manager) AddPeer(peer lazyconn.PeerConfig) (bool, error) {
	m.managedPeersMu.Lock()
	defer m.managedPeersMu.Unlock()

	peer.Log.Debugf("adding peer to lazy connection manager")

	_, exists := m.excludes[peer.PublicKey]
	if exists {
		return true, nil
	}

	if _, ok := m.managedPeers[peer.PublicKey]; ok {
		peer.Log.Warnf("peer already managed")
		return false, nil
	}

	if err := m.activityManager.MonitorPeerActivity(peer); err != nil {
		return false, err
	}

	iw := inactivity.NewInactivityMonitor(peer.PublicKey)
	m.inactivityMonitors[peer.PublicKey] = iw

	m.managedPeers[peer.PublicKey] = peer
	return false, nil
}

func (m *Manager) RemovePeer(peerID string) {
	m.managedPeersMu.Lock()
	defer m.managedPeersMu.Unlock()

	cfg, ok := m.managedPeers[peerID]
	if !ok {
		return
	}

	cfg.Log.Infof("removing lazy peer")

	if idleWatch, ok := m.inactivityMonitors[peerID]; ok {
		idleWatch.Stop()
		delete(m.inactivityMonitors, peerID)
		cfg.Log.Debugf("idle watch stopped")
	}

	m.activityManager.RemovePeer(peerID)
	delete(m.managedPeers, peerID)
	cfg.Log.Debugf("on-demand listener removed")
}

func (m *Manager) RunIdleWatch(peerID string) (found bool) {
	m.managedPeersMu.Lock()
	defer m.managedPeersMu.Unlock()

	cfg, ok := m.managedPeers[peerID]
	if !ok {
		return false
	}

	if removed := m.activityManager.RemovePeer(peerID); !removed {
		return false
	}

	m.inactivityMonitors[peerID].PauseTimer()

	cfg.Log.Infof("stoped on-demand listener and idle watcher")
	return true
}

func (m *Manager) RunOnDemandListener(peerID string) {
	m.managedPeersMu.Lock()
	defer m.managedPeersMu.Unlock()

	cfg, ok := m.managedPeers[peerID]
	if !ok {
		return
	}

	cfg.Log.Infof("run on-demand listener")

	// just in case free up
	m.inactivityMonitors[peerID].PauseTimer()

	if err := m.activityManager.MonitorPeerActivity(cfg); err != nil {
		cfg.Log.Errorf("failed to create on-demand listener: %v", err)
		return
	}
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

	m.cancel()

	m.connStateDispatcher.RemoveListener(m.connStateListener)
	m.activityManager.Close()
	for _, iw := range m.inactivityMonitors {
		iw.Stop()
	}
	m.inactivityMonitors = make(map[string]*inactivity.InactivityMonitor)
	m.managedPeers = make(map[string]lazyconn.PeerConfig)
	log.Infof("lazy connection manager closed")
}

func (m *Manager) Start(ctx context.Context) {
	ctx, m.cancel = context.WithCancel(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case e := <-m.activityManager.OnActivityChan:
			m.onPeerDemand(ctx, e)
		case peerID := <-m.onIdle:
			m.onPeerIdleTimeout(ctx, peerID)
		}
	}
}

func (m *Manager) onPeerDemand(ctx context.Context, e activity.OnAcitvityEvent) {
	m.managedPeersMu.Lock()
	defer m.managedPeersMu.Unlock()

	pcfg, ok := m.managedPeers[e.PeerID]
	if !ok {
		return
	}

	pcfg.Log.Infof("detected traffic initiative")

	if pcfg.PeerConnID != e.PeerConnId {
		pcfg.Log.Debugf("peer conn instance id mismatch, doing nothing")
		return
	}

	pcfg.Log.Infof("starting idle watcher")
	go m.inactivityMonitors[e.PeerID].Start(ctx, m.Idle)

	select {
	case m.OnDemand <- e.PeerID:
	case <-ctx.Done():
		return
	}
}

func (m *Manager) onPeerIdleTimeout(ctx context.Context, peerID string) {
	m.managedPeersMu.Lock()
	defer m.managedPeersMu.Unlock()

	pcfg, ok := m.managedPeers[peerID]
	if !ok {
		return
	}

	pcfg.Log.Infof("connection timed out")

	/*
		if pcfg.PeerConnID != e.PeerConnId {
			pcfg.Log.Debugf("peer conn instance id mismatch, doing nothing")
			return
		}

	*/

	if _, ok := m.inactivityMonitors[peerID]; !ok {
		return
	}

	select {
	case m.Idle <- peerID:
	case <-ctx.Done():
		return
	}
}
func (m *Manager) onPeerConnected(conn *peer.Conn) {
	m.managedPeersMu.Lock()
	defer m.managedPeersMu.Unlock()

	if _, ok := m.excludes[conn.GetKey()]; ok {
		return
	}

	iw, ok := m.inactivityMonitors[conn.GetKey()]
	if !ok {
		conn.Log.Errorf("idle watch not found for peer")
		return
	}

	iw.PauseTimer()
}

func (m *Manager) onPeerDisconnected(conn *peer.Conn) {
	m.managedPeersMu.Lock()
	defer m.managedPeersMu.Unlock()

	if _, ok := m.excludes[conn.GetKey()]; ok {
		return
	}

	iw, ok := m.inactivityMonitors[conn.GetKey()]
	if !ok {
		return
	}

	iw.ResetTimer()
}
