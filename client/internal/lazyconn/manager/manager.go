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
	"github.com/netbirdio/netbird/client/internal/peerstore"
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
	peerStore           *peerstore.Store
	connStateDispatcher *dispatcher.ConnectionDispatcher
	inactivityThreshold time.Duration

	connStateListener    *dispatcher.ConnectionListener
	managedPeers         map[string]*lazyconn.PeerConfig
	managedPeersByConnID map[peerid.ConnID]*managedPeer
	excludes             map[string]lazyconn.PeerConfig
	managedPeersMu       sync.Mutex

	activityManager    *activity.Manager
	inactivityMonitors map[peerid.ConnID]*inactivity.Monitor

	cancel     context.CancelFunc
	onInactive chan peerid.ConnID
}

func NewManager(config Config, peerStore *peerstore.Store, wgIface lazyconn.WGIface, connStateDispatcher *dispatcher.ConnectionDispatcher) *Manager {
	log.Infof("setup lazy connection service")
	m := &Manager{
		peerStore:            peerStore,
		connStateDispatcher:  connStateDispatcher,
		inactivityThreshold:  inactivity.DefaultInactivityThreshold,
		managedPeers:         make(map[string]*lazyconn.PeerConfig),
		managedPeersByConnID: make(map[peerid.ConnID]*managedPeer),
		excludes:             make(map[string]lazyconn.PeerConfig),
		activityManager:      activity.NewManager(wgIface),
		inactivityMonitors:   make(map[peerid.ConnID]*inactivity.Monitor),
		onInactive:           make(chan peerid.ConnID),
	}

	if config.InactivityThreshold != nil {
		if *config.InactivityThreshold >= inactivity.MinimumInactivityThreshold {
			m.inactivityThreshold = *config.InactivityThreshold
		} else {
			log.Warnf("inactivity threshold is too low, using %v", m.inactivityThreshold)
		}
	}

	m.connStateListener = &dispatcher.ConnectionListener{
		OnConnected:    m.onPeerConnected,
		OnDisconnected: m.onPeerDisconnected,
	}

	connStateDispatcher.AddListener(m.connStateListener)

	return m
}

// Start starts the manager and listens for peer activity and inactivity events
func (m *Manager) Start(ctx context.Context) {
	defer m.close()

	ctx, m.cancel = context.WithCancel(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case peerConnID := <-m.activityManager.OnActivityChan:
			m.onPeerActivity(ctx, peerConnID)
		case peerConnID := <-m.onInactive:
			m.onPeerInactivityTimedOut(peerConnID)
		}
	}
}

// ExcludePeer marks peers for a permanent connection
// It removes peers from the managed list if they are added to the exclude list
// Adds them back to the managed list and start the inactivity listener if they are removed from the exclude list. In
// this case, we suppose that the connection status is connected or connecting.
// If the peer is not exists yet in the managed list then the responsibility is the upper layer to call the AddPeer function
func (m *Manager) ExcludePeer(ctx context.Context, peerConfigs []lazyconn.PeerConfig) []string {
	m.managedPeersMu.Lock()
	defer m.managedPeersMu.Unlock()

	added := make([]string, 0)
	excludes := make(map[string]lazyconn.PeerConfig, len(peerConfigs))

	for _, peerCfg := range peerConfigs {
		log.Infof("update excluded lazy connection list with peer: %s", peerCfg.PublicKey)
		excludes[peerCfg.PublicKey] = peerCfg
	}

	// if a peer is newly added to the exclude list, remove from the managed peers list
	for pubKey, peerCfg := range excludes {
		if _, wasExcluded := m.excludes[pubKey]; wasExcluded {
			continue
		}

		added = append(added, pubKey)
		peerCfg.Log.Infof("peer newly added to lazy connection exclude list")
		m.removePeer(pubKey)
	}

	// if a peer has been removed from exclude list then it should be added to the managed peers
	for pubKey, peerCfg := range m.excludes {
		if _, stillExcluded := excludes[pubKey]; stillExcluded {
			continue
		}

		peerCfg.Log.Infof("peer removed from lazy connection exclude list")

		if err := m.addActivePeer(ctx, peerCfg); err != nil {
			log.Errorf("failed to add peer to lazy connection manager: %s", err)
			continue
		}
	}

	m.excludes = excludes
	return added
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

// AddActivePeers adds a list of peers to the lazy connection manager
// suppose these peers was in connected or in connecting states
func (m *Manager) AddActivePeers(ctx context.Context, peerCfg []lazyconn.PeerConfig) error {
	m.managedPeersMu.Lock()
	defer m.managedPeersMu.Unlock()

	for _, cfg := range peerCfg {
		if _, ok := m.managedPeers[cfg.PublicKey]; ok {
			cfg.Log.Errorf("peer already managed")
			continue
		}

		if err := m.addActivePeer(ctx, cfg); err != nil {
			cfg.Log.Errorf("failed to add peer to lazy connection manager: %v", err)
			return err
		}
	}
	return nil
}

func (m *Manager) RemovePeer(peerID string) {
	m.managedPeersMu.Lock()
	defer m.managedPeersMu.Unlock()

	m.removePeer(peerID)
}

// ActivatePeer activates a peer connection when a signal message is received
func (m *Manager) ActivatePeer(ctx context.Context, peerID string) (found bool) {
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
	if mp.expectedWatcher == watcherInactivity {
		return false
	}

	mp.expectedWatcher = watcherInactivity

	m.activityManager.RemovePeer(cfg.Log, cfg.PeerConnID)

	im, ok := m.inactivityMonitors[cfg.PeerConnID]
	if !ok {
		cfg.Log.Errorf("inactivity monitor not found for peer")
		return false
	}

	mp.peerCfg.Log.Infof("starting inactivity monitor")
	go im.Start(ctx, m.onInactive)

	return true
}

func (m *Manager) addActivePeer(ctx context.Context, peerCfg lazyconn.PeerConfig) error {
	if _, ok := m.managedPeers[peerCfg.PublicKey]; ok {
		peerCfg.Log.Warnf("peer already managed")
		return nil
	}

	im := inactivity.NewInactivityMonitor(peerCfg.PeerConnID, m.inactivityThreshold)
	m.inactivityMonitors[peerCfg.PeerConnID] = im

	m.managedPeers[peerCfg.PublicKey] = &peerCfg
	m.managedPeersByConnID[peerCfg.PeerConnID] = &managedPeer{
		peerCfg:         &peerCfg,
		expectedWatcher: watcherInactivity,
	}

	peerCfg.Log.Infof("starting inactivity monitor on peer that has been removed from exclude list")
	go im.Start(ctx, m.onInactive)
	return nil
}

func (m *Manager) removePeer(peerID string) {
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

func (m *Manager) onPeerActivity(ctx context.Context, peerConnID peerid.ConnID) {
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

	m.peerStore.PeerConnOpen(ctx, mp.peerCfg.PublicKey)
}

func (m *Manager) onPeerInactivityTimedOut(peerConnID peerid.ConnID) {
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
	m.peerStore.PeerConnClose(mp.peerCfg.PublicKey)

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
