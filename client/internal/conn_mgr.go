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
	"github.com/netbirdio/netbird/shared/connectionmode"
	"github.com/netbirdio/netbird/client/internal/peerstore"
	"github.com/netbirdio/netbird/route"
	mgmProto "github.com/netbirdio/netbird/shared/management/proto"
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
	rosenpassEnabled bool

	// Resolved values used to drive lifecycle decisions. Updated when
	// the management server pushes a new PeerConfig.
	mode             connectionmode.Mode
	relayTimeoutSecs uint32

	// Raw inputs kept so we can re-resolve when server-pushed value changes.
	envMode         connectionmode.Mode
	envRelayTimeout uint32
	cfgMode         connectionmode.Mode
	cfgRelayTimeout uint32

	lazyConnMgr *manager.Manager

	wg            sync.WaitGroup
	lazyCtx       context.Context
	lazyCtxCancel context.CancelFunc
}

func NewConnMgr(engineConfig *EngineConfig, statusRecorder *peer.Status, peerStore *peerstore.Store, iface lazyconn.WGIface) *ConnMgr {
	envMode, envRelayTimeout := peer.ResolveModeFromEnv()

	// First-pass resolution without server input -- updated later when
	// the first NetworkMap arrives via UpdatedRemotePeerConfig.
	mode, relayTimeout := resolveConnectionMode(
		envMode, envRelayTimeout,
		engineConfig.ConnectionMode, engineConfig.RelayTimeoutSeconds,
		nil,
	)

	return &ConnMgr{
		peerStore:        peerStore,
		statusRecorder:   statusRecorder,
		iface:            iface,
		rosenpassEnabled: engineConfig.RosenpassEnabled,
		mode:             mode,
		relayTimeoutSecs: relayTimeout,
		envMode:          envMode,
		envRelayTimeout:  envRelayTimeout,
		cfgMode:          engineConfig.ConnectionMode,
		cfgRelayTimeout:  engineConfig.RelayTimeoutSeconds,
	}
}

// resolveConnectionMode applies the spec-section-4.1 precedence chain:
//  1. client env (already resolved by caller via peer.ResolveModeFromEnv)
//  2. client config (from profile, including the FollowServer sentinel)
//  3. server-pushed PeerConfig.ConnectionMode (with UNSPECIFIED ->
//     legacy LazyConnectionEnabled fallback)
//
// Returns the resolved Mode and the resolved relay-timeout in seconds
// (0 = use built-in default at the call site).
func resolveConnectionMode(
	envMode connectionmode.Mode,
	envRelayTimeout uint32,
	cfgMode connectionmode.Mode,
	cfgRelayTimeout uint32,
	serverPC *mgmProto.PeerConfig,
) (connectionmode.Mode, uint32) {
	mode := envMode
	if mode == connectionmode.ModeUnspecified {
		if cfgMode != connectionmode.ModeUnspecified && cfgMode != connectionmode.ModeFollowServer {
			mode = cfgMode
		}
	}
	if mode == connectionmode.ModeUnspecified {
		if serverPC != nil {
			serverMode := connectionmode.FromProto(serverPC.GetConnectionMode())
			if serverMode != connectionmode.ModeUnspecified {
				mode = serverMode
			} else {
				mode = connectionmode.ResolveLegacyLazyBool(serverPC.GetLazyConnectionEnabled())
			}
		} else {
			mode = connectionmode.ModeP2P // safe default when nothing at all is known
		}
	}

	// Relay-timeout precedence (analog).
	relay := envRelayTimeout
	if relay == 0 {
		relay = cfgRelayTimeout
	}
	if relay == 0 && serverPC != nil {
		relay = serverPC.GetRelayTimeoutSeconds()
	}

	return mode, relay
}

// Start initializes the connection manager. If the resolved Mode at
// daemon startup is ModeP2PLazy, the lazy connection manager is brought
// up immediately; otherwise it stays dormant until UpdatedRemotePeerConfig
// transitions into lazy mode.
func (e *ConnMgr) Start(ctx context.Context) {
	if e.lazyConnMgr != nil {
		log.Errorf("lazy connection manager is already started")
		return
	}
	if e.mode != connectionmode.ModeP2PLazy {
		log.Infof("lazy connection manager is disabled (mode=%s)", e.mode)
		return
	}
	if e.rosenpassEnabled {
		log.Warnf("rosenpass enabled, lazy connection manager will not be started")
		return
	}
	e.initLazyManager(ctx)
	e.statusRecorder.UpdateLazyConnection(true)
}

// UpdatedRemotePeerConfig is called when the management server pushes a
// new PeerConfig. Re-resolves the effective mode through the precedence
// chain and starts/stops the lazy manager accordingly.
func (e *ConnMgr) UpdatedRemotePeerConfig(ctx context.Context, pc *mgmProto.PeerConfig) error {
	newMode, newRelay := resolveConnectionMode(e.envMode, e.envRelayTimeout, e.cfgMode, e.cfgRelayTimeout, pc)

	if newMode == e.mode && newRelay == e.relayTimeoutSecs {
		return nil
	}
	prev := e.mode
	e.mode = newMode
	e.relayTimeoutSecs = newRelay

	wasLazy := prev == connectionmode.ModeP2PLazy
	isLazy := newMode == connectionmode.ModeP2PLazy
	switch {
	case !wasLazy && isLazy:
		if e.rosenpassEnabled {
			log.Warnf("rosenpass enabled, ignoring lazy mode push")
			return nil
		}
		if e.lazyConnMgr == nil {
			log.Infof("lazy connection manager enabled by management push (mode=%s)", newMode)
			e.initLazyManager(ctx)
		}
		e.statusRecorder.UpdateLazyConnection(true)
		return e.addPeersToLazyConnManager()
	case wasLazy && !isLazy:
		log.Infof("lazy connection manager disabled by management push (mode=%s)", newMode)
		e.closeManager(ctx)
		e.statusRecorder.UpdateLazyConnection(false)
	}
	return nil
}

// UpdatedRemoteFeatureFlag is the legacy entry point that only knows the
// boolean LazyConnectionEnabled field. Kept as a thin shim that builds a
// synthetic PeerConfig and delegates to UpdatedRemotePeerConfig.
//
// Deprecated: callers should switch to UpdatedRemotePeerConfig and pass
// the real PeerConfig so the new ConnectionMode + timeouts propagate.
func (e *ConnMgr) UpdatedRemoteFeatureFlag(ctx context.Context, enabled bool) error {
	return e.UpdatedRemotePeerConfig(ctx, &mgmProto.PeerConfig{LazyConnectionEnabled: enabled})
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
}

func (e *ConnMgr) initLazyManager(engineCtx context.Context) {
	cfg := manager.Config{
		InactivityThreshold: inactivityThresholdEnv(),
	}
	e.lazyConnMgr = manager.NewManager(cfg, engineCtx, e.peerStore, e.iface)

	e.lazyCtx, e.lazyCtxCancel = context.WithCancel(engineCtx)

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
	e.lazyConnMgr = nil

	for _, peerID := range e.peerStore.PeersPubKey() {
		e.peerStore.PeerConnOpen(ctx, peerID)
	}
}

func (e *ConnMgr) isStartedWithLazyMgr() bool {
	return e.lazyConnMgr != nil && e.lazyCtxCancel != nil
}

// Mode returns the currently resolved connection mode. Used by the engine
// when constructing per-peer connections (Phase 1 forwards it into
// peer.ConnConfig in a follow-up commit).
func (e *ConnMgr) Mode() connectionmode.Mode {
	return e.mode
}

// RelayTimeout returns the resolved relay-worker idle timeout in seconds.
func (e *ConnMgr) RelayTimeout() uint32 {
	return e.relayTimeoutSecs
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
