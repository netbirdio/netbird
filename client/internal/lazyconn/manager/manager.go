package manager

import (
	"context"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/internal/lazyconn"
	"github.com/netbirdio/netbird/client/internal/lazyconn/activity"
	"github.com/netbirdio/netbird/client/internal/lazyconn/inactivity"
	"github.com/netbirdio/netbird/client/internal/peer"
)

const (
	watcherActivity watcherType = iota
	watcherInactivity
)

type watcherType int

type managedPeer struct {
	peerCfg         *lazyconn.PeerConfig
	expectedWatcher watcherType
}

type Config struct {
	InactivityThreshold *time.Duration
}

// Manager manages lazy connections
// It is responsible for:
// - Managing lazy connections activated on-demand
// - Managing inactivity monitors for lazy connections (based on peer disconnection events)
// - Maintaining a list of excluded peers that should always have permanent connections
// - Handling connection establishment based on peer signaling
type Manager struct {
	connStateDispatcher *peer.ConnectionDispatcher
	inactivityThreshold time.Duration

	connStateListener    *peer.ConnectionListener
	managedPeers         map[string]*lazyconn.PeerConfig
	managedPeersByConnID map[peer.ConnID]*managedPeer
	excludes             map[string]struct{}
	managedPeersMu       sync.Mutex

	activityManager    *activity.Manager
	inactivityMonitors map[peer.ConnID]*inactivity.Monitor

	cancel     context.CancelFunc
	onInactive chan peer.ConnID
}

func NewManager(config Config, wgIface lazyconn.WGIface, connStateDispatcher *peer.ConnectionDispatcher) *Manager {
	m := &Manager{
		connStateDispatcher:  connStateDispatcher,
		inactivityThreshold:  inactivity.DefaultInactivityThreshold,
		managedPeers:         make(map[string]*lazyconn.PeerConfig),
		managedPeersByConnID: make(map[peer.ConnID]*managedPeer),
		excludes:             make(map[string]struct{}),
		activityManager:      activity.NewManager(wgIface),
		inactivityMonitors:   make(map[peer.ConnID]*inactivity.Monitor),
		onInactive:           make(chan peer.ConnID),
	}

	if config.InactivityThreshold != nil {
		m.inactivityThreshold = *config.InactivityThreshold
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

	im := inactivity.NewInactivityMonitor(peerCfg.PeerConnID, m.inactivityThreshold)
	m.inactivityMonitors[peerCfg.PeerConnID] = im

	m.managedPeers[peerCfg.PublicKey] = &peerCfg
	m.managedPeersByConnID[peerCfg.PeerConnID] = &managedPeer{
		peerCfg:         &peerCfg,
		expectedWatcher: watcherActivity,
	}
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

	m.activityManager.RemovePeer(cfg.Log, peerID)
	delete(m.managedPeers, peerID)
	delete(m.managedPeersByConnID, cfg.PeerConnID)
}

func (m *Manager) ActivatePeer(peerID string) (found bool) {
	m.managedPeersMu.Lock()
	defer m.managedPeersMu.Unlock()

	cfg, ok := m.managedPeers[peerID]
	if !ok {
		return false
	}

	mp, ok := m.managedPeersByConnID[cfg.PeerConnID]
	if !ok {
		return false
	}

	// signal messages coming continuously after success activation, with this avoid the multiple activation
	if mp.expectedWatcher != watcherActivity {
		return false
	}

	mp.expectedWatcher = watcherInactivity

	m.activityManager.RemovePeer(cfg.Log, peerID)

	cfg.Log.Debugf("reset inactivity monitor timer")
	m.inactivityMonitors[cfg.PeerConnID].ResetTimer()
	return true
}

// ExcludePeer marks peers for a permanent connection
func (m *Manager) ExcludePeer(peerIDs []string) {
	m.managedPeersMu.Lock()
	defer m.managedPeersMu.Unlock()
	log.Infof("excluding peers from lazy connection manager: %v", peerIDs)

	m.excludes = make(map[string]struct{})
	for _, peerID := range peerIDs {
		m.excludes[peerID] = struct{}{}
	}
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
	m.inactivityMonitors = make(map[peer.ConnID]*inactivity.Monitor)
	m.managedPeers = make(map[string]*lazyconn.PeerConfig)
	m.managedPeersByConnID = make(map[peer.ConnID]*managedPeer)
	log.Infof("lazy connection manager closed")
}

func (m *Manager) onPeerActivity(ctx context.Context, e activity.OnAcitvityEvent, onActiveListenerFn func(peerID string)) {
	m.managedPeersMu.Lock()
	defer m.managedPeersMu.Unlock()

	mp, ok := m.managedPeersByConnID[e.PeerConnId]
	if !ok {
		log.Errorf("peer not found by id: %v", e.PeerConnId)
		return
	}

	if mp.expectedWatcher != watcherActivity {
		mp.peerCfg.Log.Warnf("ignore activity event")
		return
	}

	mp.peerCfg.Log.Infof("detected peer activity")

	mp.expectedWatcher = watcherInactivity

	mp.peerCfg.Log.Infof("starting inactivity monitor")
	go m.inactivityMonitors[e.PeerConnId].Start(ctx, m.onInactive)

	onActiveListenerFn(e.PeerID)
}

func (m *Manager) onPeerInactivityTimedOut(peerConnID peer.ConnID, onInactiveListenerFn func(peerID string)) {
	m.managedPeersMu.Lock()
	defer m.managedPeersMu.Unlock()

	mp, ok := m.managedPeersByConnID[peerConnID]
	if !ok {
		log.Errorf("peer not found by id: %v", peerConnID)
		return
	}

	if mp.expectedWatcher != watcherInactivity {
		mp.peerCfg.Log.Warnf("ignore inactivity event")
		return
	}

	mp.peerCfg.Log.Infof("connection timed out")

	// this is blocking operation, potentially can be optimized
	onInactiveListenerFn(mp.peerCfg.PublicKey)

	mp.peerCfg.Log.Infof("start activity monitor")

	mp.expectedWatcher = watcherActivity

	// just in case free up
	m.inactivityMonitors[peerConnID].PauseTimer()

	if err := m.activityManager.MonitorPeerActivity(*mp.peerCfg); err != nil {
		mp.peerCfg.Log.Errorf("failed to create activity monitor: %v", err)
		return
	}
}

func (m *Manager) onPeerConnected(peerID string) {
	m.managedPeersMu.Lock()
	defer m.managedPeersMu.Unlock()

	peerCfg, ok := m.managedPeers[peerID]
	if !ok {
		return
	}

	mp, ok := m.managedPeersByConnID[peerCfg.PeerConnID]
	if !ok {
		return
	}

	if mp.expectedWatcher != watcherInactivity {
		return
	}

	iw, ok := m.inactivityMonitors[peerCfg.PeerConnID]
	if !ok {
		peerCfg.Log.Errorf("inactivity monitor not found for peer")
		return
	}

	peerCfg.Log.Infof("peer connected, pausing inactivity monitor while connection is not disconnected")
	iw.PauseTimer()
}

func (m *Manager) onPeerDisconnected(peerID string) {
	m.managedPeersMu.Lock()
	defer m.managedPeersMu.Unlock()

	peerCfg, ok := m.managedPeers[peerID]
	if !ok {
		return
	}

	mp, ok := m.managedPeersByConnID[peerCfg.PeerConnID]
	if !ok {
		return
	}

	if mp.expectedWatcher != watcherInactivity {
		return
	}

	iw, ok := m.inactivityMonitors[peerCfg.PeerConnID]
	if !ok {
		return
	}

	peerCfg.Log.Infof("reset inactivity monitor timer")
	iw.ResetTimer()
}
