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
	OnActive chan string
	Idle     chan string

	connStateDispatcher *peer.ConnectionDispatcher
	managedPeers        map[string]*lazyconn.PeerConfig
	managedByConnID     map[string]*lazyconn.PeerConfig

	activityManager    *activity.Manager
	inactivityMonitors map[string]*inactivity.InactivityMonitor

	excludes          map[string]struct{}
	managedPeersMu    sync.Mutex
	cancel            context.CancelFunc
	connStateListener *peer.ConnectionListener
	onInactive        chan string
}

func NewManager(wgIface lazyconn.WGIface, connStateDispatcher *peer.ConnectionDispatcher) *Manager {
	m := &Manager{
		OnActive: make(chan string, 1),
		Idle:     make(chan string, 1),

		connStateDispatcher: connStateDispatcher,
		managedPeers:        make(map[string]*lazyconn.PeerConfig),
		activityManager:     activity.NewManager(wgIface),
		inactivityMonitors:  make(map[string]*inactivity.InactivityMonitor),
		excludes:            make(map[string]struct{}),
		onInactive:          make(chan string),
	}

	m.connStateListener = &peer.ConnectionListener{
		OnConnected:    m.onPeerConnected,
		OnDisconnected: m.onPeerDisconnected,
	}

	connStateDispatcher.AddListener(m.connStateListener)

	return m
}

func (m *Manager) AddPeer(peerCfg lazyconn.PeerConfig) (bool, error) {
	m.managedPeersMu.Lock()
	defer m.managedPeersMu.Unlock()

	peerCfg.Log.Debugf("adding peer to lazy connection manager")

	_, exists := m.excludes[peerCfg.PublicKey]
	if exists {
		return true, nil
	}

	if _, ok := m.managedPeers[peerCfg.PublicKey]; ok {
		peerCfg.Log.Warnf("peer already managed")
		return false, nil
	}

	if err := m.activityManager.MonitorPeerActivity(peerCfg); err != nil {
		return false, err
	}

	iw := inactivity.NewInactivityMonitor(peerCfg.PublicKey)
	m.inactivityMonitors[peerCfg.PublicKey] = iw

	m.managedPeers[peerCfg.PublicKey] = &peerCfg
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

	if im, ok := m.inactivityMonitors[peerID]; ok {
		im.Stop()
		delete(m.inactivityMonitors, peerID)
		cfg.Log.Debugf("inactivity monitor stopped")
	}

	m.activityManager.RemovePeer(peerID)
	delete(m.managedPeers, peerID)
	cfg.Log.Debugf("activity listener removed")
}

func (m *Manager) RunInactivityMonitor(peerID string) (found bool) {
	m.managedPeersMu.Lock()
	defer m.managedPeersMu.Unlock()

	cfg, ok := m.managedPeers[peerID]
	if !ok {
		return false
	}

	if removed := m.activityManager.RemovePeer(peerID); !removed {
		return false
	}

	m.inactivityMonitors[peerID].ResetTimer()

	cfg.Log.Infof("stoped activity monitor and reset inactivity monitor")
	return true
}

func (m *Manager) RunActivityMonitor(peerID string) {
	m.managedPeersMu.Lock()
	defer m.managedPeersMu.Unlock()

	cfg, ok := m.managedPeers[peerID]
	if !ok {
		return
	}

	cfg.Log.Infof("start activity monitor")

	// just in case free up
	m.inactivityMonitors[peerID].PauseTimer()

	if err := m.activityManager.MonitorPeerActivity(*cfg); err != nil {
		cfg.Log.Errorf("failed to create activity monitor: %v", err)
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
	m.managedPeers = make(map[string]*lazyconn.PeerConfig)
	log.Infof("lazy connection manager closed")
}

func (m *Manager) Start(ctx context.Context) {
	ctx, m.cancel = context.WithCancel(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case e := <-m.activityManager.OnActivityChan:
			m.onPeerActivity(ctx, e)
		case peerID := <-m.onInactive:
			m.onPeerInactivityTimedOut(ctx, peerID)
		}
	}
}

func (m *Manager) onPeerActivity(ctx context.Context, e activity.OnAcitvityEvent) {
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

	pcfg.Log.Infof("starting inactivity monitor")
	go m.inactivityMonitors[e.PeerID].Start(ctx, m.Idle)

	select {
	case m.OnActive <- e.PeerID:
	case <-ctx.Done():
		return
	}
}

func (m *Manager) onPeerInactivityTimedOut(ctx context.Context, peerID string) {
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

	peerCfg, ok := m.managedPeers[conn.GetKey()]
	if !ok {
		return
	}

	iw, ok := m.inactivityMonitors[conn.GetKey()]
	if !ok {
		conn.Log.Errorf("inactivity monitor not found for peer")
		return
	}

	peerCfg.Log.Infof("pause inactivity monitor")
	iw.PauseTimer()
}

func (m *Manager) onPeerDisconnected(conn *peer.Conn) {
	m.managedPeersMu.Lock()
	defer m.managedPeersMu.Unlock()

	peerCfg, ok := m.managedPeers[conn.GetKey()]
	if !ok {
		return
	}

	iw, ok := m.inactivityMonitors[conn.GetKey()]
	if !ok {
		return
	}

	peerCfg.Log.Infof("reset inactivity monitor timer")
	iw.ResetTimer()
}
