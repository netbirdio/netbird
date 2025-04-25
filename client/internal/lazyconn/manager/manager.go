package manager

import (
	"context"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/internal/lazyconn"
	"github.com/netbirdio/netbird/client/internal/lazyconn/activity"
	"github.com/netbirdio/netbird/client/internal/lazyconn/inactivity"
	"github.com/netbirdio/netbird/client/internal/peer/dispatcher"
	peerid "github.com/netbirdio/netbird/client/internal/peer/id"
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
	connStateDispatcher *dispatcher.ConnectionDispatcher
	inactivityThreshold time.Duration

	connStateListener    *dispatcher.ConnectionListener
	managedPeers         map[string]*lazyconn.PeerConfig
	managedPeersByConnID map[peerid.ConnID]*managedPeer
	excludes             map[string]struct{}
	managedPeersMu       sync.Mutex

	activityManager    *activity.Manager
	inactivityMonitors map[peerid.ConnID]*inactivity.Monitor

	cancel     context.CancelFunc
	onInactive chan peerid.ConnID
}

func NewManager(config Config, wgIface lazyconn.WGIface, connStateDispatcher *dispatcher.ConnectionDispatcher) *Manager {
	log.Infof("setup lazy connection service")
	m := &Manager{
		connStateDispatcher:  connStateDispatcher,
		inactivityThreshold:  inactivity.DefaultInactivityThreshold,
		managedPeers:         make(map[string]*lazyconn.PeerConfig),
		managedPeersByConnID: make(map[peerid.ConnID]*managedPeer),
		excludes:             make(map[string]struct{}),
		activityManager:      activity.NewManager(wgIface),
		inactivityMonitors:   make(map[peerid.ConnID]*inactivity.Monitor),
		onInactive:           make(chan peerid.ConnID),
	}

	if config.InactivityThreshold != nil {
		m.inactivityThreshold = *config.InactivityThreshold
	}

	m.connStateListener = &dispatcher.ConnectionListener{
		OnConnected:    m.onPeerConnected,
		OnDisconnected: m.onPeerDisconnected,
	}

	connStateDispatcher.AddListener(m.connStateListener)

	return m
}

// Start starts the manager and listens for peer activity and inactivity events
func (m *Manager) Start(ctx context.Context, activeFn func(peerID string), inactiveFn func(peerID string)) {
	defer m.close()

	ctx, m.cancel = context.WithCancel(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case peerConnID := <-m.activityManager.OnActivityChan:
			m.onPeerActivity(ctx, peerConnID, activeFn)
		case peerConnID := <-m.onInactive:
			m.onPeerInactivityTimedOut(peerConnID, inactiveFn)
		}
	}
}

// ExcludePeer marks peers for a permanent connection
func (m *Manager) ExcludePeer(peerIDs []string) {
	m.managedPeersMu.Lock()
	defer m.managedPeersMu.Unlock()
	log.Infof("update excluded peers from lazy connection: %v", peerIDs)

	m.excludes = make(map[string]struct{})
	for _, peerID := range peerIDs {
		m.excludes[peerID] = struct{}{}
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

	m.activityManager.RemovePeer(cfg.Log, cfg.PeerConnID)
	delete(m.managedPeers, peerID)
	delete(m.managedPeersByConnID, cfg.PeerConnID)
}

// ActivatePeer activates a peer connection when a signal message is received
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

	m.activityManager.RemovePeer(cfg.Log, cfg.PeerConnID)

	cfg.Log.Debugf("reset inactivity monitor timer")
	m.inactivityMonitors[cfg.PeerConnID].ResetTimer()
	return true
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
	m.inactivityMonitors = make(map[peerid.ConnID]*inactivity.Monitor)
	m.managedPeers = make(map[string]*lazyconn.PeerConfig)
	m.managedPeersByConnID = make(map[peerid.ConnID]*managedPeer)
	log.Infof("lazy connection manager closed")
}

func (m *Manager) onPeerActivity(ctx context.Context, peerConnID peerid.ConnID, onActiveListenerFn func(peerID string)) {
	m.managedPeersMu.Lock()
	defer m.managedPeersMu.Unlock()

	mp, ok := m.managedPeersByConnID[peerConnID]
	if !ok {
		log.Errorf("peer not found by conn id: %v", peerConnID)
		return
	}

	if mp.expectedWatcher != watcherActivity {
		mp.peerCfg.Log.Warnf("ignore activity event")
		return
	}

	mp.peerCfg.Log.Infof("detected peer activity")

	mp.expectedWatcher = watcherInactivity

	mp.peerCfg.Log.Infof("starting inactivity monitor")
	go m.inactivityMonitors[peerConnID].Start(ctx, m.onInactive)

	onActiveListenerFn(mp.peerCfg.PublicKey)
}

func (m *Manager) onPeerInactivityTimedOut(peerConnID peerid.ConnID, onInactiveListenerFn func(peerID string)) {
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

func (m *Manager) onPeerConnected(peerConnID peerid.ConnID) {
	m.managedPeersMu.Lock()
	defer m.managedPeersMu.Unlock()

	mp, ok := m.managedPeersByConnID[peerConnID]
	if !ok {
		return
	}

	if mp.expectedWatcher != watcherInactivity {
		return
	}

	iw, ok := m.inactivityMonitors[mp.peerCfg.PeerConnID]
	if !ok {
		mp.peerCfg.Log.Errorf("inactivity monitor not found for peer")
		return
	}

	mp.peerCfg.Log.Infof("peer connected, pausing inactivity monitor while connection is not disconnected")
	iw.PauseTimer()
}

func (m *Manager) onPeerDisconnected(peerConnID peerid.ConnID) {
	m.managedPeersMu.Lock()
	defer m.managedPeersMu.Unlock()

	mp, ok := m.managedPeersByConnID[peerConnID]
	if !ok {
		return
	}

	if mp.expectedWatcher != watcherInactivity {
		return
	}

	iw, ok := m.inactivityMonitors[mp.peerCfg.PeerConnID]
	if !ok {
		return
	}

	mp.peerCfg.Log.Infof("reset inactivity monitor timer")
	iw.ResetTimer()
}
