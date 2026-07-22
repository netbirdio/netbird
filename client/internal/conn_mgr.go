package internal

import (
	"context"
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
// The only exception is ActivatePeer, which is safe for concurrent use so the
// DNS warm-up path can call it without contending on the engine mutex.
type ConnMgr struct {
	peerStore        *peerstore.Store
	statusRecorder   *peer.Status
	iface            lazyconn.WGIface
	force            lazyForce
	rosenpassEnabled bool

	lazyConnMgr *manager.Manager
	// lazyConnMgrMu guards the lazyConnMgr pointer for readers outside the
	// engine loop (ActivatePeer). Writers hold it in addition to
	// engine.syncMsgMux; all other reads stay under engine.syncMsgMux only.
	lazyConnMgrMu sync.RWMutex

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

// Start initializes the connection manager. It starts the lazy connection manager when a
// local override forces it on; with no local override it waits for the management feature flag.
func (e *ConnMgr) Start(ctx context.Context) {
	if e.lazyConnMgr != nil {
		log.Errorf("lazy connection manager is already started")
		return
	}

	switch e.force {
	case lazyForceOff:
		log.Infof("lazy connection manager is disabled by local override (%s or MDM policy)", lazyconn.EnvLazyConn)
		e.statusRecorder.UpdateLazyConnection(false)
		return
	case lazyForceNone:
		log.Infof("lazy connection manager is managed by the management feature flag")
		e.statusRecorder.UpdateLazyConnection(false)
		return
	}

	if e.rosenpassEnabled {
		log.Warnf("rosenpass connection manager is enabled, lazy connection manager will not be started")
		e.statusRecorder.UpdateLazyConnection(false)
		return
	}

	e.initLazyManager(ctx)
	e.statusRecorder.UpdateLazyConnection(true)
}

// UpdatedRemoteFeatureFlag is called when the remote feature flag is updated.
// If enabled, it initializes the lazy connection manager and start it. Do not need to call Start() again.
// If disabled, then it closes the lazy connection manager and open the connections to all peers.
func (e *ConnMgr) UpdatedRemoteFeatureFlag(ctx context.Context, enabled bool) error {
	// a local override (NB_LAZY_CONN or local config) takes precedence over management
	if e.force != lazyForceNone {
		return nil
	}

	if enabled {
		// if the lazy connection manager is already started, do not start it again
		if e.lazyConnMgr != nil {
			return nil
		}

		if e.rosenpassEnabled {
			log.Infof("rosenpass connection manager is enabled, lazy connection manager will not be started")
			e.statusRecorder.UpdateLazyConnection(false)
			return nil
		}

		log.Infof("lazy connection manager is enabled by the management feature flag")
		e.initLazyManager(ctx)
		e.statusRecorder.UpdateLazyConnection(true)
		return e.addPeersToLazyConnManager()
	} else {
		if e.lazyConnMgr == nil {
			e.statusRecorder.UpdateLazyConnection(false)
			return nil
		}
		log.Infof("lazy connection manager is disabled by management feature flag")
		e.closeManager(ctx)
		e.statusRecorder.UpdateLazyConnection(false)
		return nil
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

func (e *ConnMgr) AddPeerConn(ctx context.Context, peerKey string, conn *peer.Conn) (exists bool) {
	if success := e.peerStore.AddPeerConn(peerKey, conn); !success {
		return true
	}

	if !e.isStartedWithLazyMgr() {
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
	// Permanent removal: drop the WG peer entry too. The peer is gone for
	// good and the route-manager's refcounter teardown will release any
	// AllowedIPs it had appended along the same path.
	defer conn.Close(false, false)

	if !e.isStartedWithLazyMgr() {
		return
	}

	e.lazyConnMgr.RemovePeer(peerKey)
	conn.Log.Infof("removed peer from lazy conn manager")
}

// ActivatePeer wakes an idle lazy connection. Unlike the rest of ConnMgr it is
// safe for concurrent use: the lazy manager pointer is read under lazyConnMgrMu
// and the manager itself is internally synchronized, so callers outside the
// engine loop (DNS warm-up) do not need engine.syncMsgMux.
func (e *ConnMgr) ActivatePeer(ctx context.Context, conn *peer.Conn) {
	e.lazyConnMgrMu.RLock()
	lazyConnMgr := e.lazyConnMgr
	started := lazyConnMgr != nil && e.lazyCtxCancel != nil
	e.lazyConnMgrMu.RUnlock()
	if !started {
		return
	}

	if found := lazyConnMgr.ActivatePeer(conn.GetKey()); found {
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

	e.lazyConnMgrMu.Lock()
	e.lazyConnMgr = nil
	e.lazyConnMgrMu.Unlock()
}

func (e *ConnMgr) initLazyManager(engineCtx context.Context) {
	cfg := manager.Config{
		InactivityThreshold: inactivityThresholdEnv(),
	}

	e.lazyConnMgrMu.Lock()
	e.lazyConnMgr = manager.NewManager(cfg, engineCtx, e.peerStore, e.iface)
	e.lazyCtx, e.lazyCtxCancel = context.WithCancel(engineCtx)
	e.lazyConnMgrMu.Unlock()

	e.wg.Add(1)
	go func() {
		defer e.wg.Done()
		e.lazyConnMgr.Start(e.lazyCtx)
	}()
}

func (e *ConnMgr) addPeersToLazyConnManager() error {
	peers := e.peerStore.PeersPubKey()
	lazyPeerCfgs := make([]lazyconn.PeerConfig, 0, len(peers))
	for _, peerID := range peers {
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
		lazyPeerCfgs = append(lazyPeerCfgs, lazyPeerCfg)
	}

	return e.lazyConnMgr.AddActivePeers(lazyPeerCfgs)
}

func (e *ConnMgr) closeManager(ctx context.Context) {
	if e.lazyConnMgr == nil {
		return
	}

	e.lazyCtxCancel()
	e.wg.Wait()

	e.lazyConnMgrMu.Lock()
	e.lazyConnMgr = nil
	e.lazyConnMgrMu.Unlock()

	for _, peerID := range e.peerStore.PeersPubKey() {
		e.peerStore.PeerConnOpen(ctx, peerID)
	}
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
