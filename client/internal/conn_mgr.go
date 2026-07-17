package internal

import (
	"context"
	"maps"
	"os"
	"strconv"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/internal/lazyconn"
	"github.com/netbirdio/netbird/client/internal/lazyconn/manager"
	"github.com/netbirdio/netbird/client/internal/peer"
	"github.com/netbirdio/netbird/client/internal/peerstore"
	"github.com/netbirdio/netbird/route"
	mgmProto "github.com/netbirdio/netbird/shared/management/proto"
)

// lazyForce is the resolved local decision for lazy connections, layered above the
// management feature flag. lazyForceNone defers to management.
type lazyForce int

const (
	lazyForceNone lazyForce = iota
	lazyForceOn
	lazyForceOff
)

// ConnMgr coordinates both lazy connections (established on-demand) and permanent peer connections.
//
// The connection manager is responsible for:
// - Managing lazy connections via the lazyConnManager
// - Maintaining a list of excluded peers that should always have permanent connections
// - Handling connection establishment based on peer signaling
//
// The implementation is not thread-safe; it is protected by engine.syncMsgMux.
type ConnMgr struct {
	peerStore        *peerstore.Store
	statusRecorder   *peer.Status
	iface            lazyconn.WGIface
	force            lazyForce
	rosenpassEnabled bool
	// remoteLazyEnabled caches the account-wide lazy feature flag from management.
	// It is the default for peers that do not carry a per-peer lazy hint.
	remoteLazyEnabled bool

	lazyConnMgr *manager.Manager
	// appliedExcludeList is the exclude set last handed to the lazy manager, kept so an
	// unchanged set on the next sync skips the O(n) reconciliation.
	appliedExcludeList map[string]bool

	wg            sync.WaitGroup
	lazyCtx       context.Context
	lazyCtxCancel context.CancelFunc
}

func NewConnMgr(engineConfig *EngineConfig, statusRecorder *peer.Status, peerStore *peerstore.Store, iface lazyconn.WGIface) *ConnMgr {
	e := &ConnMgr{
		peerStore:        peerStore,
		statusRecorder:   statusRecorder,
		iface:            iface,
		force:            resolveLazyForce(engineConfig.LazyConnection),
		rosenpassEnabled: engineConfig.RosenpassEnabled,
	}
	return e
}

// Start initializes the connection manager. The lazy connection manager always runs so that
// per-peer lazy defaults (e.g. proxy peers) work even when the account flag is off; the
// account flag and the local override decide the default lazy state per peer (see
// PeerLazyDefault). Rosenpass is the only condition that disables it.
func (e *ConnMgr) Start(ctx context.Context) {
	if e.lazyConnMgr != nil {
		log.Errorf("lazy connection manager is already started")
		return
	}

	if e.rosenpassEnabled {
		log.Warnf("rosenpass is enabled, lazy connection manager will not be started")
		e.statusRecorder.UpdateLazyConnection(false)
		return
	}

	e.initLazyManager(ctx)
	e.statusRecorder.UpdateLazyConnection(e.PeerLazyDefault(mgmProto.LazyState_LazyStateDefault))
}

// UpdatedRemoteFeatureFlag caches the account-wide lazy feature flag. The manager itself is
// not started or stopped here; the per-sync exclude-list reconciliation moves normal peers
// between the lazy and always-active sets when the flag flips.
func (e *ConnMgr) UpdatedRemoteFeatureFlag(_ context.Context, enabled bool) error {
	e.remoteLazyEnabled = enabled
	if e.isStartedWithLazyMgr() {
		e.statusRecorder.UpdateLazyConnection(e.PeerLazyDefault(mgmProto.LazyState_LazyStateDefault))
	}
	return nil
}

// PeerLazyDefault reports whether a peer should be lazy. The local override
// (NB_LAZY_CONN/MDM) wins over everything; without a local override the
// management per-peer state applies (LazyStateLazy/Eager force the decision),
// and LazyStateDefault follows the account-wide flag.
func (e *ConnMgr) PeerLazyDefault(state mgmProto.LazyState) bool {
	switch e.force {
	case lazyForceOn:
		return true
	case lazyForceOff:
		return false
	}

	switch state {
	case mgmProto.LazyState_LazyStateLazy:
		return true
	case mgmProto.LazyState_LazyStateEager:
		return false
	default:
		return e.remoteLazyEnabled
	}
}

// UpdateRouteHAMap updates the route HA mappings in the lazy connection manager
func (e *ConnMgr) UpdateRouteHAMap(haMap route.HAMap) {
	if !e.isStartedWithLazyMgr() {
		log.Debugf("lazy connection manager is not started, skipping UpdateRouteHAMap")
		return
	}

	e.lazyConnMgr.UpdateRouteHAMap(haMap)
}

// SetExcludeList sets the list of peer IDs that should always have permanent connections.
func (e *ConnMgr) SetExcludeList(ctx context.Context, peerIDs map[string]bool) {
	if e.lazyConnMgr == nil {
		return
	}

	// The exclude set is recomputed every sync but rarely changes; skip the O(n)
	// store lookups and reconciliation when it matches what was already applied.
	if maps.Equal(peerIDs, e.appliedExcludeList) {
		return
	}
	e.appliedExcludeList = maps.Clone(peerIDs)

	excludedPeers := make([]lazyconn.PeerConfig, 0, len(peerIDs))

	for peerID := range peerIDs {
		var peerConn *peer.Conn
		var exists bool
		if peerConn, exists = e.peerStore.PeerConn(peerID); !exists {
			log.Warnf("failed to find peer conn for peerID: %s", peerID)
			continue
		}

		lazyPeerCfg := lazyconn.PeerConfig{
			PublicKey:  peerID,
			AllowedIPs: peerConn.WgConfig().AllowedIps,
			PeerConnID: peerConn.ConnID(),
			Log:        peerConn.Log,
		}
		excludedPeers = append(excludedPeers, lazyPeerCfg)
	}

	added := e.lazyConnMgr.ExcludePeer(excludedPeers)
	for _, peerID := range added {
		var peerConn *peer.Conn
		var exists bool
		if peerConn, exists = e.peerStore.PeerConn(peerID); !exists {
			// if the peer not exist in the store, it means that the engine will call the AddPeerConn in next step
			continue
		}

		peerConn.Log.Infof("peer has been added to lazy connection exclude list, opening permanent connection")
		if err := peerConn.Open(ctx); err != nil {
			peerConn.Log.Errorf("failed to open connection: %v", err)
		}
	}
}

// AddPeerConn registers a peer connection. permanent requests an always-active connection
// (the peer belongs to the exclude set: a forwarder, or a peer that is not lazy by policy).
// Non-permanent peers are handed to the lazy manager. The subsequent SetExcludeList call
// reconciles membership for existing peers across flag flips.
func (e *ConnMgr) AddPeerConn(ctx context.Context, peerKey string, conn *peer.Conn, permanent bool) (exists bool) {
	if success := e.peerStore.AddPeerConn(peerKey, conn); !success {
		return true
	}

	if !e.isStartedWithLazyMgr() || permanent {
		if err := conn.Open(ctx); err != nil {
			conn.Log.Errorf("failed to open connection: %v", err)
		}
		return
	}

	if !lazyconn.IsSupported(conn.AgentVersionString()) {
		conn.Log.Warnf("peer does not support lazy connection (%s), open permanent connection", conn.AgentVersionString())
		if err := conn.Open(ctx); err != nil {
			conn.Log.Errorf("failed to open connection: %v", err)
		}
		return
	}

	lazyPeerCfg := lazyconn.PeerConfig{
		PublicKey:  peerKey,
		AllowedIPs: conn.WgConfig().AllowedIps,
		PeerConnID: conn.ConnID(),
		Log:        conn.Log,
	}
	excluded, err := e.lazyConnMgr.AddPeer(lazyPeerCfg)
	if err != nil {
		conn.Log.Errorf("failed to add peer to lazyconn manager: %v", err)
		if err := conn.Open(ctx); err != nil {
			conn.Log.Errorf("failed to open connection: %v", err)
		}
		return
	}

	if excluded {
		conn.Log.Infof("peer is on lazy conn manager exclude list, opening connection")
		if err := conn.Open(ctx); err != nil {
			conn.Log.Errorf("failed to open connection: %v", err)
		}
		return
	}

	conn.Log.Infof("peer added to lazy conn manager")
	return
}

func (e *ConnMgr) RemovePeerConn(peerKey string) {
	conn, ok := e.peerStore.Remove(peerKey)
	if !ok {
		return
	}
	defer conn.Close(false)

	if !e.isStartedWithLazyMgr() {
		return
	}

	e.lazyConnMgr.RemovePeer(peerKey)
	conn.Log.Infof("removed peer from lazy conn manager")
}

func (e *ConnMgr) ActivatePeer(ctx context.Context, conn *peer.Conn) {
	if !e.isStartedWithLazyMgr() {
		return
	}

	if found := e.lazyConnMgr.ActivatePeer(conn.GetKey()); found {
		if err := conn.Open(ctx); err != nil {
			conn.Log.Errorf("failed to open connection: %v", err)
		}
	}
}

// DeactivatePeer deactivates a peer connection in the lazy connection manager.
// If locally the lazy connection is disabled, we force the peer connection open.
func (e *ConnMgr) DeactivatePeer(conn *peer.Conn) {
	if !e.isStartedWithLazyMgr() {
		return
	}

	conn.Log.Infof("closing peer connection: remote peer initiated inactive, idle lazy state and sent GOAWAY")
	e.lazyConnMgr.DeactivatePeer(conn.ConnID())
}

func (e *ConnMgr) Close() {
	if !e.isStartedWithLazyMgr() {
		return
	}

	e.lazyCtxCancel()
	e.wg.Wait()
	e.lazyConnMgr = nil
	e.appliedExcludeList = nil
}

func (e *ConnMgr) initLazyManager(engineCtx context.Context) {
	cfg := manager.Config{
		InactivityThreshold: inactivityThresholdEnv(),
	}
	e.lazyConnMgr = manager.NewManager(cfg, engineCtx, e.peerStore, e.iface)
	e.appliedExcludeList = nil

	e.lazyCtx, e.lazyCtxCancel = context.WithCancel(engineCtx)

	e.wg.Add(1)
	go func() {
		defer e.wg.Done()
		e.lazyConnMgr.Start(e.lazyCtx)
	}()
}

func (e *ConnMgr) isStartedWithLazyMgr() bool {
	return e.lazyConnMgr != nil && e.lazyCtxCancel != nil
}

// resolveLazyForce determines the local override. NB_LAZY_CONN takes precedence; when it
// is unset the MDM policy override (mdmState) applies. Either wins in both directions over
// the management feature flag; StateUnset for both defers to management.
func resolveLazyForce(mdmState lazyconn.State) lazyForce {
	state := lazyconn.EnvState()
	if state == lazyconn.StateUnset {
		state = mdmState
	}

	switch state {
	case lazyconn.StateOn:
		return lazyForceOn
	case lazyconn.StateOff:
		return lazyForceOff
	default:
		return lazyForceNone
	}
}

func inactivityThresholdEnv() *time.Duration {
	envValue := os.Getenv(lazyconn.EnvInactivityThreshold)
	if envValue == "" {
		return nil
	}

	parsedMinutes, err := strconv.Atoi(envValue)
	if err != nil || parsedMinutes <= 0 {
		return nil
	}

	d := time.Duration(parsedMinutes) * time.Minute
	return &d
}
