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
	connStateDispatcher *peer.ConnectionDispatcher
	connStateListener   *peer.ConnectionListener

	managedPeers         map[string]*lazyconn.PeerConfig
	managedPeersByConnID map[peer.ConnID]*lazyconn.PeerConfig
	excludes             map[string]struct{}
	managedPeersMu       sync.Mutex

	activityManager    *activity.Manager
	inactivityMonitors map[peer.ConnID]*inactivity.InactivityMonitor

	cancel     context.CancelFunc
	onInactive chan peer.ConnID
}

func NewManager(wgIface lazyconn.WGIface, connStateDispatcher *peer.ConnectionDispatcher) *Manager {
	m := &Manager{
		connStateDispatcher:  connStateDispatcher,
		managedPeers:         make(map[string]*lazyconn.PeerConfig),
		managedPeersByConnID: make(map[peer.ConnID]*lazyconn.PeerConfig),
		excludes:             make(map[string]struct{}),
		activityManager:      activity.NewManager(wgIface),
		inactivityMonitors:   make(map[peer.ConnID]*inactivity.InactivityMonitor),
		onInactive:           make(chan peer.ConnID),
	}

	m.connStateListener = &peer.ConnectionListener{
		OnConnected:    m.onPeerConnected,
		OnDisconnected: m.onPeerDisconnected,
	}

	connStateDispatcher.AddListener(m.connStateListener)

	return m
}

func (m *Manager) Start(ctx context.Context, activeFn func(peerID string), inactiveFn func(peerID string)) {
	defer m.close()

	ctx, m.cancel = context.WithCancel(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case e := <-m.activityManager.OnActivityChan:
			m.onPeerActivity(ctx, e, activeFn)
		case peerConnID := <-m.onInactive:
			m.onPeerInactivityTimedOut(peerConnID, inactiveFn)
		}
	}
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

	im := inactivity.NewInactivityMonitor(peerCfg.PeerConnID)
	m.inactivityMonitors[peerCfg.PeerConnID] = im

	m.managedPeers[peerCfg.PublicKey] = &peerCfg
	m.managedPeersByConnID[peerCfg.PeerConnID] = &peerCfg
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

	if im, ok := m.inactivityMonitors[cfg.PeerConnID]; ok {
		im.Stop()
		delete(m.inactivityMonitors, cfg.PeerConnID)
		cfg.Log.Debugf("inactivity monitor stopped")
	}

	m.activityManager.RemovePeer(peerID)
	delete(m.managedPeers, peerID)
	delete(m.managedPeersByConnID, cfg.PeerConnID)
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

	m.inactivityMonitors[cfg.PeerConnID].ResetTimer()

	cfg.Log.Infof("stoped activity monitor and reset inactivity monitor")
	return true
}

func (m *Manager) ExcludePeer(peerID string) {
	m.managedPeersMu.Lock()
	defer m.managedPeersMu.Unlock()

	m.excludes[peerID] = struct{}{}
}

func (m *Manager) close() {
	m.managedPeersMu.Lock()
	defer m.managedPeersMu.Unlock()

	m.cancel()

	m.connStateDispatcher.RemoveListener(m.connStateListener)
	m.activityManager.Close()
	for _, iw := range m.inactivityMonitors {
		iw.Stop()
	}
	m.inactivityMonitors = make(map[peer.ConnID]*inactivity.InactivityMonitor)
	m.managedPeers = make(map[string]*lazyconn.PeerConfig)
	log.Infof("lazy connection manager closed")
}

func (m *Manager) onPeerActivity(ctx context.Context, e activity.OnAcitvityEvent, onActiveListenerFn func(peerID string)) {
	m.managedPeersMu.Lock()
	defer m.managedPeersMu.Unlock()

	pcfg, ok := m.managedPeersByConnID[e.PeerConnId]
	if !ok {
		return
	}

	pcfg.Log.Infof("detected peer activity")

	pcfg.Log.Infof("starting inactivity monitor")
	go m.inactivityMonitors[e.PeerConnId].Start(ctx, m.onInactive)

	onActiveListenerFn(e.PeerID)
}

func (m *Manager) onPeerInactivityTimedOut(peerConnID peer.ConnID, onInactiveListenerFn func(peerID string)) {
	m.managedPeersMu.Lock()
	defer m.managedPeersMu.Unlock()

	pcfg, ok := m.managedPeersByConnID[peerConnID]
	if !ok {
		return
	}

	pcfg.Log.Infof("connection timed out")

	if _, ok := m.inactivityMonitors[peerConnID]; !ok {
		return
	}

	onInactiveListenerFn(pcfg.PublicKey)

	pcfg.Log.Infof("start activity monitor")

	// just in case free up
	m.inactivityMonitors[pcfg.PeerConnID].PauseTimer()
	if err := m.activityManager.MonitorPeerActivity(*pcfg); err != nil {
		pcfg.Log.Errorf("failed to create activity monitor: %v", err)
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

	iw, ok := m.inactivityMonitors[conn.ConnID()]
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

	iw, ok := m.inactivityMonitors[conn.ConnID()]
	if !ok {
		return
	}

	peerCfg.Log.Infof("reset inactivity monitor timer")
	iw.ResetTimer()
}
