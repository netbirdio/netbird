package manager

import (
	"context"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
	"golang.org/x/exp/maps"

	"github.com/netbirdio/netbird/client/internal/lazyconn"
	"github.com/netbirdio/netbird/client/internal/lazyconn/activity"
	"github.com/netbirdio/netbird/client/internal/lazyconn/inactivity"
	"github.com/netbirdio/netbird/client/internal/peer/dispatcher"
	peerid "github.com/netbirdio/netbird/client/internal/peer/id"
	"github.com/netbirdio/netbird/client/internal/peerstore"
	"github.com/netbirdio/netbird/route"
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
// - Managing route HA groups and activating all peers in a group when one peer is activated
type Manager struct {
	engineCtx           context.Context
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

	// Route HA group management
	peerToHAGroups map[string][]route.HAUniqueID // peer ID -> HA groups they belong to
	haGroupToPeers map[route.HAUniqueID][]string // HA group -> peer IDs in the group
	routesMu       sync.RWMutex

	ctx        context.Context
	cancel     context.CancelFunc
	onInactive chan peerid.ConnID
}

// NewManager creates a new lazy connection manager
// engineCtx is the context for creating peer Connection
func NewManager(config Config, engineCtx context.Context, peerStore *peerstore.Store, wgIface lazyconn.WGIface, connStateDispatcher *dispatcher.ConnectionDispatcher) *Manager {
	log.Infof("setup lazy connection service")
	m := &Manager{
		engineCtx:            engineCtx,
		peerStore:            peerStore,
		connStateDispatcher:  connStateDispatcher,
		inactivityThreshold:  inactivity.DefaultInactivityThreshold,
		managedPeers:         make(map[string]*lazyconn.PeerConfig),
		managedPeersByConnID: make(map[peerid.ConnID]*managedPeer),
		excludes:             make(map[string]lazyconn.PeerConfig),
		activityManager:      activity.NewManager(wgIface),
		inactivityMonitors:   make(map[peerid.ConnID]*inactivity.Monitor),
		peerToHAGroups:       make(map[string][]route.HAUniqueID),
		haGroupToPeers:       make(map[route.HAUniqueID][]string),
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

// UpdateRouteHAMap updates the HA group mappings for routes
// This should be called when route configuration changes
func (m *Manager) UpdateRouteHAMap(haMap route.HAMap) {
	m.routesMu.Lock()
	defer m.routesMu.Unlock()

	maps.Clear(m.peerToHAGroups)
	maps.Clear(m.haGroupToPeers)

	for haUniqueID, routes := range haMap {
		var peers []string

		peerSet := make(map[string]bool)
		for _, r := range routes {
			if !peerSet[r.Peer] {
				peerSet[r.Peer] = true
				peers = append(peers, r.Peer)
			}
		}

		if len(peers) <= 1 {
			continue
		}

		m.haGroupToPeers[haUniqueID] = peers

		for _, peerID := range peers {
			m.peerToHAGroups[peerID] = append(m.peerToHAGroups[peerID], haUniqueID)
		}
	}

	log.Debugf("updated route HA mappings: %d HA groups, %d peers with routes",
		len(m.haGroupToPeers), len(m.peerToHAGroups))
}

// Start starts the manager and listens for peer activity and inactivity events
func (m *Manager) Start(ctx context.Context) {
	defer m.close()

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

func (m *Manager) AddPeer(ctx context.Context, peerCfg lazyconn.PeerConfig) (bool, error) {
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

	// Check if this peer should be activated because its HA group peers are active
	if group, ok := m.shouldActivateNewPeer(peerCfg.PublicKey); ok {
		peerCfg.Log.Debugf("peer belongs to active HA group %s, will activate immediately", group)
		m.activateNewPeerInActiveGroup(ctx, peerCfg)
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
// Also activates all peers in the same HA groups as this peer
func (m *Manager) ActivatePeer(ctx context.Context, peerID string) (found bool) {
	m.managedPeersMu.Lock()
	defer m.managedPeersMu.Unlock()
	cfg, mp := m.getPeerForActivation(peerID)
	if cfg == nil {
		return false
	}

	if !m.activateSinglePeer(ctx, cfg, mp) {
		return false
	}

	m.activateHAGroupPeers(ctx, peerID)

	return true
}

// getPeerForActivation checks if a peer can be activated and returns the necessary structs
// Returns nil values if the peer should be skipped
func (m *Manager) getPeerForActivation(peerID string) (*lazyconn.PeerConfig, *managedPeer) {
	cfg, ok := m.managedPeers[peerID]
	if !ok {
		return nil, nil
	}

	mp, ok := m.managedPeersByConnID[cfg.PeerConnID]
	if !ok {
		return nil, nil
	}

	// signal messages coming continuously after success activation, with this avoid the multiple activation
	if mp.expectedWatcher == watcherInactivity {
		return nil, nil
	}

	return cfg, mp
}

// activateSinglePeer activates a single peer (internal method)
func (m *Manager) activateSinglePeer(ctx context.Context, cfg *lazyconn.PeerConfig, mp *managedPeer) bool {
	mp.expectedWatcher = watcherInactivity

	m.activityManager.RemovePeer(cfg.Log, cfg.PeerConnID)

	im, ok := m.inactivityMonitors[cfg.PeerConnID]
	if !ok {
		cfg.Log.Errorf("inactivity monitor not found for peer")
		return false
	}

	cfg.Log.Infof("starting inactivity monitor")
	go im.Start(ctx, m.onInactive)

	return true
}

// activateHAGroupPeers activates all peers in HA groups that the given peer belongs to
func (m *Manager) activateHAGroupPeers(ctx context.Context, triggerPeerID string) {
	var peersToActivate []string

	m.routesMu.RLock()
	haGroups := m.peerToHAGroups[triggerPeerID]

	if len(haGroups) == 0 {
		m.routesMu.RUnlock()
		log.Debugf("peer %s is not part of any HA groups", triggerPeerID)
		return
	}

	for _, haGroup := range haGroups {
		peers := m.haGroupToPeers[haGroup]
		for _, peerID := range peers {
			if peerID != triggerPeerID {
				peersToActivate = append(peersToActivate, peerID)
			}
		}
	}
	m.routesMu.RUnlock()

	activatedCount := 0
	for _, peerID := range peersToActivate {
		cfg, mp := m.getPeerForActivation(peerID)
		if cfg == nil {
			continue
		}

		if m.activateSinglePeer(ctx, cfg, mp) {
			activatedCount++
			cfg.Log.Infof("activated peer as part of HA group (triggered by %s)", triggerPeerID)
			m.peerStore.PeerConnOpen(m.engineCtx, cfg.PublicKey)
		}
	}

	if activatedCount > 0 {
		log.Infof("activated %d additional peers in HA groups for peer %s (groups: %v)",
			activatedCount, triggerPeerID, haGroups)
	}
}

// shouldActivateNewPeer checks if a newly added peer should be activated
// because other peers in its HA groups are already active
func (m *Manager) shouldActivateNewPeer(peerID string) (route.HAUniqueID, bool) {
	m.routesMu.RLock()
	defer m.routesMu.RUnlock()

	haGroups := m.peerToHAGroups[peerID]
	if len(haGroups) == 0 {
		return "", false
	}

	for _, haGroup := range haGroups {
		peers := m.haGroupToPeers[haGroup]
		for _, groupPeerID := range peers {
			if groupPeerID == peerID {
				continue
			}

			cfg, ok := m.managedPeers[groupPeerID]
			if !ok {
				continue
			}
			if mp, ok := m.managedPeersByConnID[cfg.PeerConnID]; ok && mp.expectedWatcher == watcherInactivity {
				return haGroup, true
			}
		}
	}
	return "", false
}

// activateNewPeerInActiveGroup activates a newly added peer that should be active due to HA group
func (m *Manager) activateNewPeerInActiveGroup(ctx context.Context, peerCfg lazyconn.PeerConfig) {
	mp, ok := m.managedPeersByConnID[peerCfg.PeerConnID]
	if !ok {
		return
	}

	if !m.activateSinglePeer(ctx, &peerCfg, mp) {
		return
	}

	peerCfg.Log.Infof("activated newly added peer due to active HA group peers")
	m.peerStore.PeerConnOpen(m.engineCtx, peerCfg.PublicKey)
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

	m.connStateDispatcher.RemoveListener(m.connStateListener)
	m.activityManager.Close()
	for _, iw := range m.inactivityMonitors {
		iw.Stop()
	}
	m.inactivityMonitors = make(map[peerid.ConnID]*inactivity.Monitor)
	m.managedPeers = make(map[string]*lazyconn.PeerConfig)
	m.managedPeersByConnID = make(map[peerid.ConnID]*managedPeer)

	// Clear route mappings
	m.routesMu.Lock()
	m.peerToHAGroups = make(map[string][]route.HAUniqueID)
	m.haGroupToPeers = make(map[route.HAUniqueID][]string)
	m.routesMu.Unlock()

	log.Infof("lazy connection manager closed")
}

// shouldDeferIdleForHA checks if peer should stay connected due to HA group requirements
func (m *Manager) shouldDeferIdleForHA(peerID string) bool {
	m.routesMu.RLock()
	defer m.routesMu.RUnlock()

	haGroups := m.peerToHAGroups[peerID]
	if len(haGroups) == 0 {
		return false
	}

	for _, haGroup := range haGroups {
		groupPeers := m.haGroupToPeers[haGroup]

		for _, groupPeerID := range groupPeers {
			if groupPeerID == peerID {
				continue
			}

			cfg, ok := m.managedPeers[groupPeerID]
			if !ok {
				continue
			}

			groupMp, ok := m.managedPeersByConnID[cfg.PeerConnID]
			if !ok {
				continue
			}

			if groupMp.expectedWatcher != watcherInactivity {
				continue
			}

			// Other member is still connected, defer idle
			if peer, ok := m.peerStore.PeerConn(groupPeerID); ok && peer.IsConnected() {
				return true
			}
		}
	}

	return false
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

	if !m.activateSinglePeer(ctx, mp.peerCfg, mp) {
		return
	}

	m.activateHAGroupPeers(ctx, mp.peerCfg.PublicKey)

	m.peerStore.PeerConnOpen(m.engineCtx, mp.peerCfg.PublicKey)
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

	if m.shouldDeferIdleForHA(mp.peerCfg.PublicKey) {
		iw, ok := m.inactivityMonitors[peerConnID]
		if ok {
			mp.peerCfg.Log.Debugf("resetting inactivity timer due to HA group requirements")
			iw.ResetMonitor(m.ctx, m.onInactive)
		} else {
			mp.peerCfg.Log.Errorf("inactivity monitor not found for HA defer reset")
		}
		return
	}

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
		mp.peerCfg.Log.Warnf("inactivity monitor not found for peer")
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
