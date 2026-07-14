package manager

import (
	"context"
	"net/netip"
	"sort"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/internal/lazyconn"
	"github.com/netbirdio/netbird/client/internal/lazyconn/activity"
	"github.com/netbirdio/netbird/client/internal/lazyconn/inactivity"
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
	inactivityThreshold time.Duration

	managedPeers         map[string]*lazyconn.PeerConfig
	managedPeersByConnID map[peerid.ConnID]*managedPeer
	excludes             map[string]lazyconn.PeerConfig
	managedPeersMu       sync.Mutex

	activityManager   *activity.Manager
	inactivityManager *inactivity.Manager

	// Route HA group management
	// If any peer in the same HA group is active, all peers in that group should prevent going idle
	peerToHAGroups map[string][]route.HAUniqueID // peer ID -> HA groups they belong to
	haGroupToPeers map[route.HAUniqueID][]string // HA group -> peer IDs in the group
	// peerToRoutePrefixes holds the routed subnets each routing peer serves
	// (from the management route sync via UpdateRouteHAMap). The activity
	// listener installs a peer's wake endpoint via WgInterface.UpdatePeer,
	// and WireGuard only routes a destination to that endpoint when it falls
	// inside the peer's AllowedIPs. Merging these routed prefixes into the
	// lazy PeerConfig.AllowedIPs ensures traffic to a routed subnet wakes the
	// idle routing peer instead of being black-holed.
	peerToRoutePrefixes map[string][]netip.Prefix // peer ID -> routed prefixes from route sync
	routesMu            sync.RWMutex
}

// NewManager creates a new lazy connection manager
// engineCtx is the context for creating peer Connection
func NewManager(config Config, engineCtx context.Context, peerStore *peerstore.Store, wgIface lazyconn.WGIface) *Manager {
	log.Infof("setup lazy connection service")

	m := &Manager{
		engineCtx:            engineCtx,
		peerStore:            peerStore,
		inactivityThreshold:  inactivity.DefaultInactivityThreshold,
		managedPeers:         make(map[string]*lazyconn.PeerConfig),
		managedPeersByConnID: make(map[peerid.ConnID]*managedPeer),
		excludes:             make(map[string]lazyconn.PeerConfig),
		activityManager:      activity.NewManager(wgIface),
		peerToHAGroups:       make(map[string][]route.HAUniqueID),
		haGroupToPeers:       make(map[route.HAUniqueID][]string),
		peerToRoutePrefixes:  make(map[string][]netip.Prefix),
	}

	if wgIface.IsUserspaceBind() {
		m.inactivityManager = inactivity.NewManager(wgIface, config.InactivityThreshold)
	} else {
		log.Warnf("inactivity manager not supported for kernel mode, wait for remote peer to close the connection")
	}

	return m
}

// UpdateRouteHAMap updates the HA group mappings for routes.
// This should be called when route configuration changes.
//
// It also rebuilds peerToRoutePrefixes: the routed subnets each routing
// peer serves are captured so the activity listener can wake the peer on
// traffic into those subnets. The prefix capture runs for every route,
// including single-peer (non-HA) routes that the HA-group builder skips,
// because a lone routing peer still needs its subnet to trigger a wakeup.
//
// The captured prefixes are merged into a peer's AllowedIPs only at listener
// arm time (see armActivityListener), never written back into the stored
// PeerConfig. Keeping the stored base pristine (overlay-only) ensures a later
// route change or removal drops the stale prefix instead of accumulating it,
// which would otherwise let an idle routing peer re-claim a subnet that has
// since moved to another HA peer.
func (m *Manager) UpdateRouteHAMap(haMap route.HAMap) {
	m.routesMu.Lock()
	defer m.routesMu.Unlock()

	clear(m.peerToHAGroups)
	clear(m.haGroupToPeers)
	clear(m.peerToRoutePrefixes)

	routePrefixes := make(map[string]map[netip.Prefix]struct{})

	for haUniqueID, routes := range haMap {
		var peers []string

		peerSet := make(map[string]bool)
		for _, r := range routes {
			if r == nil {
				continue
			}

			if prefix, ok := routePrefixForLazyPeer(r); ok {
				if routePrefixes[r.Peer] == nil {
					routePrefixes[r.Peer] = make(map[netip.Prefix]struct{})
				}
				routePrefixes[r.Peer][prefix] = struct{}{}
			}

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

	for peerID, prefixes := range routePrefixes {
		m.peerToRoutePrefixes[peerID] = sortedPrefixes(prefixes)
	}

	log.Debugf("updated route HA mappings: %d HA groups, %d peers with routes, %d peers with route prefixes",
		len(m.haGroupToPeers), len(m.peerToHAGroups), len(m.peerToRoutePrefixes))
}

// routePrefixForLazyPeer returns the masked network prefix of a static
// (non-dynamic) route so it can be merged into the routing peer's
// AllowedIPs. Dynamic (domain) routes and invalid networks are skipped:
// they have no fixed subnet the client can pre-install for wakeups.
func routePrefixForLazyPeer(r *route.Route) (netip.Prefix, bool) {
	if r.IsDynamic() || !r.Network.IsValid() {
		return netip.Prefix{}, false
	}
	return r.Network.Masked(), true
}

// sortedPrefixes returns the set's prefixes in a deterministic order (by
// address, then prefix length) so AllowedIPs assembly is stable.
func sortedPrefixes(prefixes map[netip.Prefix]struct{}) []netip.Prefix {
	out := make([]netip.Prefix, 0, len(prefixes))
	for prefix := range prefixes {
		out = append(out, prefix)
	}
	sort.Slice(out, func(i, j int) bool {
		if cmp := out[i].Addr().Compare(out[j].Addr()); cmp != 0 {
			return cmp < 0
		}
		return out[i].Bits() < out[j].Bits()
	})
	return out
}

// allowedIPsForPeer merges the peer's base AllowedIPs (overlay /32 from the
// WireGuard config) with its currently routed prefixes (from the route sync).
// The result is the AllowedIPs the activity listener installs via UpdatePeer
// so WireGuard routes both overlay- and subnet-bound traffic to the peer's
// wake endpoint. It is idempotent (masked deduplication) and always computed
// from the pristine base, so a route change is reflected on the next arm
// without stale prefixes lingering.
func (m *Manager) allowedIPsForPeer(peerID string, base []netip.Prefix) []netip.Prefix {
	m.routesMu.RLock()
	defer m.routesMu.RUnlock()

	set := make(map[netip.Prefix]struct{}, len(base)+len(m.peerToRoutePrefixes[peerID]))
	for _, prefix := range base {
		set[prefix.Masked()] = struct{}{}
	}
	for _, prefix := range m.peerToRoutePrefixes[peerID] {
		set[prefix.Masked()] = struct{}{}
	}
	return sortedPrefixes(set)
}

// armActivityListener starts the activity listener for a peer, merging its
// routed prefixes into the wake endpoint's AllowedIPs at arm time. The stored
// PeerConfig is left untouched (pristine overlay-only base): the merge is
// applied to a copy so successive arms always reflect the current routes and
// never accumulate stale prefixes.
func (m *Manager) armActivityListener(peerCfg lazyconn.PeerConfig) error {
	armCfg := peerCfg
	armCfg.AllowedIPs = m.allowedIPsForPeer(peerCfg.PublicKey, peerCfg.AllowedIPs)
	return m.activityManager.MonitorPeerActivity(armCfg)
}

// Start starts the manager and listens for peer activity and inactivity events
func (m *Manager) Start(ctx context.Context) {
	defer m.close()

	if m.inactivityManager != nil {
		go m.inactivityManager.Start(ctx)
	}

	for {
		select {
		case <-ctx.Done():
			return
		case ev := <-m.activityManager.OnActivityChan:
			m.onPeerActivity(ev)
		case peerIDs := <-m.inactivityManager.InactivePeersChan():
			m.onPeerInactivityTimedOut(peerIDs)
		}
	}

}

// ExcludePeer marks peers for a permanent connection
// It removes peers from the managed list if they are added to the exclude list
// Adds them back to the managed list and start the inactivity listener if they are removed from the exclude list. In
// this case, we suppose that the connection status is connected or connecting.
// If the peer is not exists yet in the managed list then the responsibility is the upper layer to call the AddPeer function
func (m *Manager) ExcludePeer(peerConfigs []lazyconn.PeerConfig) []string {
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

		if err := m.addActivePeer(&peerCfg); err != nil {
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

	// Arm the activity listener with routed subnets merged into the wake
	// endpoint's AllowedIPs. The stored PeerConfig keeps its pristine
	// overlay-only base (see armActivityListener).
	if err := m.armActivityListener(peerCfg); err != nil {
		return false, err
	}

	m.managedPeers[peerCfg.PublicKey] = &peerCfg
	m.managedPeersByConnID[peerCfg.PeerConnID] = &managedPeer{
		peerCfg:         &peerCfg,
		expectedWatcher: watcherActivity,
	}

	// Check if this peer should be activated because its HA group peers are active
	if group, ok := m.shouldActivateNewPeer(peerCfg.PublicKey); ok {
		peerCfg.Log.Debugf("peer belongs to active HA group %s, will activate immediately", group)
		m.activateNewPeerInActiveGroup(peerCfg)
	}

	return false, nil
}

// AddActivePeers adds a list of peers to the lazy connection manager
// suppose these peers was in connected or in connecting states
func (m *Manager) AddActivePeers(peerCfg []lazyconn.PeerConfig) error {
	m.managedPeersMu.Lock()
	defer m.managedPeersMu.Unlock()

	for _, cfg := range peerCfg {
		if _, ok := m.managedPeers[cfg.PublicKey]; ok {
			cfg.Log.Errorf("peer already managed")
			continue
		}

		if err := m.addActivePeer(&cfg); err != nil {
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
func (m *Manager) ActivatePeer(peerID string) (found bool) {
	m.managedPeersMu.Lock()
	defer m.managedPeersMu.Unlock()
	cfg, mp := m.getPeerForActivation(peerID)
	if cfg == nil {
		return false
	}

	cfg.Log.Infof("activate peer from inactive state by remote signal message")

	if !m.activateSinglePeer(cfg, mp) {
		return false
	}

	m.activateHAGroupPeers(cfg)
	return true
}

func (m *Manager) DeactivatePeer(peerID peerid.ConnID) {
	m.managedPeersMu.Lock()
	defer m.managedPeersMu.Unlock()

	mp, ok := m.managedPeersByConnID[peerID]
	if !ok {
		return
	}

	if mp.expectedWatcher != watcherInactivity {
		return
	}

	m.peerStore.PeerConnClose(mp.peerCfg.PublicKey)

	mp.peerCfg.Log.Infof("start activity monitor")

	mp.expectedWatcher = watcherActivity

	m.inactivityManager.RemovePeer(mp.peerCfg.PublicKey)

	if err := m.armActivityListener(*mp.peerCfg); err != nil {
		mp.peerCfg.Log.Errorf("failed to create activity monitor: %v", err)
		return
	}
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

// activateSinglePeer activates a single peer
// return true if the peer was activated, false if it was already active
func (m *Manager) activateSinglePeer(cfg *lazyconn.PeerConfig, mp *managedPeer) bool {
	if mp.expectedWatcher == watcherInactivity {
		return false
	}

	mp.expectedWatcher = watcherInactivity
	m.activityManager.RemovePeer(cfg.Log, cfg.PeerConnID)
	m.inactivityManager.AddPeer(cfg)
	return true
}

// activateHAGroupPeers activates all peers in HA groups that the given peer belongs to
func (m *Manager) activateHAGroupPeers(triggeredPeerCfg *lazyconn.PeerConfig) {
	var peersToActivate []string

	m.routesMu.RLock()
	haGroups := m.peerToHAGroups[triggeredPeerCfg.PublicKey]

	if len(haGroups) == 0 {
		m.routesMu.RUnlock()
		triggeredPeerCfg.Log.Debugf("peer is not part of any HA groups")
		return
	}

	for _, haGroup := range haGroups {
		peers := m.haGroupToPeers[haGroup]
		for _, peerID := range peers {
			if peerID != triggeredPeerCfg.PublicKey {
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

		if m.activateSinglePeer(cfg, mp) {
			activatedCount++
			cfg.Log.Infof("activated peer as part of HA group (triggered by %s)", triggeredPeerCfg.PublicKey)
			m.peerStore.PeerConnOpen(m.engineCtx, cfg.PublicKey)
		}
	}

	if activatedCount > 0 {
		log.Infof("activated %d additional peers in HA groups for peer %s (groups: %v)",
			activatedCount, triggeredPeerCfg.PublicKey, haGroups)
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
func (m *Manager) activateNewPeerInActiveGroup(peerCfg lazyconn.PeerConfig) {
	mp, ok := m.managedPeersByConnID[peerCfg.PeerConnID]
	if !ok {
		return
	}

	if !m.activateSinglePeer(&peerCfg, mp) {
		return
	}

	peerCfg.Log.Infof("activated newly added peer due to active HA group peers")
	m.peerStore.PeerConnOpen(m.engineCtx, peerCfg.PublicKey)
}

func (m *Manager) addActivePeer(peerCfg *lazyconn.PeerConfig) error {
	if _, ok := m.managedPeers[peerCfg.PublicKey]; ok {
		peerCfg.Log.Warnf("peer already managed")
		return nil
	}

	m.managedPeers[peerCfg.PublicKey] = peerCfg
	m.managedPeersByConnID[peerCfg.PeerConnID] = &managedPeer{
		peerCfg:         peerCfg,
		expectedWatcher: watcherInactivity,
	}

	m.inactivityManager.AddPeer(peerCfg)
	return nil
}

func (m *Manager) removePeer(peerID string) {
	cfg, ok := m.managedPeers[peerID]
	if !ok {
		return
	}

	cfg.Log.Infof("removing lazy peer")

	m.inactivityManager.RemovePeer(cfg.PublicKey)
	m.activityManager.RemovePeer(cfg.Log, cfg.PeerConnID)
	delete(m.managedPeers, peerID)
	delete(m.managedPeersByConnID, cfg.PeerConnID)

	// Drop routed-prefix bookkeeping to avoid a map leak. Lock ordering:
	// managedPeersMu (held by callers) -> routesMu.
	m.routesMu.Lock()
	delete(m.peerToRoutePrefixes, peerID)
	m.routesMu.Unlock()
}

func (m *Manager) close() {
	m.managedPeersMu.Lock()
	defer m.managedPeersMu.Unlock()

	m.activityManager.Close()

	m.managedPeers = make(map[string]*lazyconn.PeerConfig)
	m.managedPeersByConnID = make(map[peerid.ConnID]*managedPeer)

	// Clear route mappings
	m.routesMu.Lock()
	m.peerToHAGroups = make(map[string][]route.HAUniqueID)
	m.haGroupToPeers = make(map[route.HAUniqueID][]string)
	m.peerToRoutePrefixes = make(map[string][]netip.Prefix)
	m.routesMu.Unlock()

	log.Infof("lazy connection manager closed")
}

// shouldDeferIdleForHA checks if peer should stay connected due to HA group requirements
func (m *Manager) shouldDeferIdleForHA(inactivePeers map[string]struct{}, peerID string) bool {
	m.routesMu.RLock()
	defer m.routesMu.RUnlock()

	haGroups := m.peerToHAGroups[peerID]
	if len(haGroups) == 0 {
		return false
	}

	for _, haGroup := range haGroups {
		if active := m.checkHaGroupActivity(haGroup, peerID, inactivePeers); active {
			return true
		}
	}

	return false
}

func (m *Manager) checkHaGroupActivity(haGroup route.HAUniqueID, peerID string, inactivePeers map[string]struct{}) bool {
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

		// If any peer in the group is active, do defer idle
		if _, isInactive := inactivePeers[groupPeerID]; !isInactive {
			return true
		}
	}
	return false
}

func (m *Manager) onPeerActivity(ev activity.Event) {
	m.managedPeersMu.Lock()
	defer m.managedPeersMu.Unlock()

	mp, ok := m.managedPeersByConnID[ev.PeerConnID]
	if !ok {
		log.Errorf("peer not found by conn id: %v", ev.PeerConnID)
		return
	}

	if mp.expectedWatcher != watcherActivity {
		mp.peerCfg.Log.Warnf("ignore activity event")
		return
	}

	mp.peerCfg.Log.Infof("detected peer activity")

	if !m.activateSinglePeer(mp.peerCfg, mp) {
		return
	}

	m.activateHAGroupPeers(mp.peerCfg)

	m.peerStore.PeerConnOpenWithFirstPacket(m.engineCtx, mp.peerCfg.PublicKey, ev.FirstPacket)
}

func (m *Manager) onPeerInactivityTimedOut(peerIDs map[string]struct{}) {
	m.managedPeersMu.Lock()
	defer m.managedPeersMu.Unlock()

	for peerID := range peerIDs {
		peerCfg, ok := m.managedPeers[peerID]
		if !ok {
			log.Errorf("peer not found by peerId: %v", peerID)
			continue
		}

		mp, ok := m.managedPeersByConnID[peerCfg.PeerConnID]
		if !ok {
			log.Errorf("peer not found by conn id: %v", peerCfg.PeerConnID)
			continue
		}

		if mp.expectedWatcher != watcherInactivity {
			mp.peerCfg.Log.Warnf("ignore inactivity event")
			continue
		}

		if m.shouldDeferIdleForHA(peerIDs, mp.peerCfg.PublicKey) {
			mp.peerCfg.Log.Infof("defer inactivity due to active HA group peers")
			continue
		}

		mp.peerCfg.Log.Infof("connection timed out")

		// this is blocking operation, potentially can be optimized
		m.peerStore.PeerConnIdle(mp.peerCfg.PublicKey)

		mp.expectedWatcher = watcherActivity

		m.inactivityManager.RemovePeer(mp.peerCfg.PublicKey)

		mp.peerCfg.Log.Infof("start activity monitor")

		if err := m.armActivityListener(*mp.peerCfg); err != nil {
			mp.peerCfg.Log.Errorf("failed to create activity monitor: %v", err)
			continue
		}
	}
}
