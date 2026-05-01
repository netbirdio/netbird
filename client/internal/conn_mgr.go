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
	// Phase 2 (#5989): ICE-only inactivity timeout (seconds). Used in
	// ModeP2PDynamic to teardown the ICE worker without affecting the
	// relay tunnel. 0 = ICE never times out.
	p2pTimeoutSecs uint32

	// Raw inputs kept so we can re-resolve when server-pushed value changes.
	envMode         connectionmode.Mode
	envRelayTimeout uint32
	cfgMode         connectionmode.Mode
	cfgRelayTimeout uint32
	cfgP2pTimeout   uint32

	lazyConnMgr *manager.Manager

	wg            sync.WaitGroup
	lazyCtx       context.Context
	lazyCtxCancel context.CancelFunc
}

func NewConnMgr(engineConfig *EngineConfig, statusRecorder *peer.Status, peerStore *peerstore.Store, iface lazyconn.WGIface) *ConnMgr {
	envMode, envRelayTimeout := peer.ResolveModeFromEnv()

	// First-pass resolution without server input -- updated later when
	// the first NetworkMap arrives via UpdatedRemotePeerConfig.
	mode, relayTimeout, p2pTimeout := resolveConnectionMode(
		envMode, envRelayTimeout,
		engineConfig.ConnectionMode, engineConfig.RelayTimeoutSeconds,
		engineConfig.P2pTimeoutSeconds,
		nil,
	)

	return &ConnMgr{
		peerStore:        peerStore,
		statusRecorder:   statusRecorder,
		iface:            iface,
		rosenpassEnabled: engineConfig.RosenpassEnabled,
		mode:             mode,
		relayTimeoutSecs: relayTimeout,
		p2pTimeoutSecs:   p2pTimeout,
		envMode:          envMode,
		envRelayTimeout:  envRelayTimeout,
		cfgMode:          engineConfig.ConnectionMode,
		cfgRelayTimeout: engineConfig.RelayTimeoutSeconds,
		cfgP2pTimeout:   engineConfig.P2pTimeoutSeconds,
	}
}

// resolveConnectionMode applies the spec-section-4.1 precedence chain:
//  1. client env (already resolved by caller via peer.ResolveModeFromEnv)
//  2. client config (from profile, including the FollowServer sentinel)
//  3. server-pushed PeerConfig.ConnectionMode (with UNSPECIFIED ->
//     legacy LazyConnectionEnabled fallback)
//
// Returns the resolved Mode, the resolved relay-timeout in seconds, and
// the resolved p2p-timeout in seconds. 0 for either timeout means the
// caller should use its built-in default.
func resolveConnectionMode(
	envMode connectionmode.Mode,
	envRelayTimeout uint32,
	cfgMode connectionmode.Mode,
	cfgRelayTimeout uint32,
	cfgP2pTimeout uint32,
	serverPC *mgmProto.PeerConfig,
) (connectionmode.Mode, uint32, uint32) {
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

	// P2P-timeout precedence: client config wins over server push. No env
	// var in Phase 2; reserved for Phase 3.
	p2p := cfgP2pTimeout
	if p2p == 0 && serverPC != nil {
		p2p = serverPC.GetP2PTimeoutSeconds()
	}

	return mode, relay, p2p
}

// Start initializes the connection manager. The lazy/dynamic connection
// manager is brought up immediately when the resolved Mode is P2PLazy
// or P2PDynamic. Other modes keep the manager dormant; it can still be
// activated later via UpdatedRemotePeerConfig.
func (e *ConnMgr) Start(ctx context.Context) {
	if e.lazyConnMgr != nil {
		log.Errorf("lazy/dynamic connection manager is already started")
		return
	}
	if !modeUsesLazyMgr(e.mode) {
		log.Infof("lazy/dynamic connection manager is disabled (mode=%s)", e.mode)
		return
	}
	if e.rosenpassEnabled {
		log.Warnf("rosenpass enabled, lazy/dynamic connection manager will not be started")
		return
	}
	e.initLazyManager(ctx)
	e.startModeSideEffects()
}

// modeUsesLazyMgr is true for the modes whose lifecycle is driven by the
// lazyconn.Manager (which now hosts the two-timer inactivity manager
// since Phase 2). Eager modes (p2p, relay-forced) do not need it.
func modeUsesLazyMgr(m connectionmode.Mode) bool {
	return m == connectionmode.ModeP2PLazy || m == connectionmode.ModeP2PDynamic
}

// startModeSideEffects flips the per-mode goroutines and status flags
// that need to follow a successful initLazyManager. Called by Start()
// and by the management-push transition path.
func (e *ConnMgr) startModeSideEffects() {
	if e.mode == connectionmode.ModeP2PLazy {
		e.statusRecorder.UpdateLazyConnection(true)
	}
	if e.mode == connectionmode.ModeP2PDynamic {
		e.wg.Add(1)
		go func() {
			defer e.wg.Done()
			e.runDynamicInactivityLoop(e.lazyCtx)
		}()
	}
}

// runDynamicInactivityLoop reads from the two-timer inactivity channels
// exposed by the inactivity.Manager and dispatches per-peer teardown.
//
// ICEInactiveChan: detach the ICE worker for each listed peer; the
// relay tunnel is left running so traffic still flows.
//
// RelayInactiveChan: close the whole connection. The activity-detector
// will reopen it when the next outbound packet arrives.
//
// Only meaningful in p2p-dynamic mode; in p2p-lazy the iceTimeout is 0
// and ICEInactiveChan never fires, so the loop is a passthrough.
func (e *ConnMgr) runDynamicInactivityLoop(ctx context.Context) {
	if e.lazyConnMgr == nil {
		return
	}
	im := e.lazyConnMgr.InactivityManager()
	if im == nil {
		return
	}
	log.Infof("p2p-dynamic inactivity loop started (iceTimeout=%ds, relayTimeout=%ds)", e.p2pTimeoutSecs, e.relayTimeoutSecs)
	defer log.Infof("p2p-dynamic inactivity loop stopped")
	for {
		select {
		case <-ctx.Done():
			return
		case peers := <-im.ICEInactiveChan():
			for peerKey := range peers {
				if err := e.DetachICEForPeer(peerKey); err != nil {
					log.Warnf("DetachICEForPeer(%s): %v", peerKey, err)
				}
			}
		case peers := <-im.RelayInactiveChan():
			for peerKey := range peers {
				if conn, ok := e.peerStore.PeerConn(peerKey); ok {
					conn.Log.Infof("relay-inactivity timeout, closing peer connection")
					conn.Close(false)
				}
			}
		}
	}
}

// UpdatedRemotePeerConfig is called when the management server pushes a
// new PeerConfig. Re-resolves the effective mode through the precedence
// chain and starts/stops the lazy manager accordingly.
func (e *ConnMgr) UpdatedRemotePeerConfig(ctx context.Context, pc *mgmProto.PeerConfig) error {
	newMode, newRelay, newP2P := resolveConnectionMode(e.envMode, e.envRelayTimeout, e.cfgMode, e.cfgRelayTimeout, e.cfgP2pTimeout, pc)

	if newMode == e.mode && newRelay == e.relayTimeoutSecs && newP2P == e.p2pTimeoutSecs {
		return nil
	}
	prev := e.mode
	e.mode = newMode
	e.relayTimeoutSecs = newRelay
	e.p2pTimeoutSecs = newP2P

	wasManaged := modeUsesLazyMgr(prev)
	isManaged := modeUsesLazyMgr(newMode)
	modeChanged := prev != newMode

	if modeChanged && wasManaged && !isManaged {
		log.Infof("lazy/dynamic connection manager disabled by management push (mode=%s)", newMode)
		e.closeManager(ctx)
		e.statusRecorder.UpdateLazyConnection(false)
		return nil
	}

	if modeChanged && wasManaged && isManaged {
		// Switching between lazy and dynamic at runtime: tear down the
		// existing manager so initLazyManager picks up the new timeouts.
		log.Infof("lazy/dynamic mode change %s -> %s, restarting manager", prev, newMode)
		e.closeManager(ctx)
		e.statusRecorder.UpdateLazyConnection(false)
	}

	if isManaged && e.lazyConnMgr == nil {
		if e.rosenpassEnabled {
			log.Warnf("rosenpass enabled, ignoring lazy/dynamic mode push")
			return nil
		}
		log.Infof("lazy/dynamic connection manager enabled by management push (mode=%s)", newMode)
		e.initLazyManager(ctx)
		e.startModeSideEffects()
		return e.addPeersToLazyConnManager()
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

// deactivateAction selects what DeactivatePeer should do when the remote
// peer signals GO_IDLE. The dispatch is a pure function of the locally
// resolved connection mode.
type deactivateAction int

const (
	deactivateNoop deactivateAction = iota
	deactivateLazy
	deactivateICE
)

// deactivatePeerAction returns the per-mode deactivation rule. Eager
// modes (p2p, relay-forced, unspecified) ignore GO_IDLE because they
// are meant to keep tunnels always-on. p2p-lazy delegates to the lazy
// connection manager so the whole tunnel is torn down. p2p-dynamic
// detaches only the ICE worker so the relay tunnel stays up.
func (e *ConnMgr) deactivatePeerAction() deactivateAction {
	switch e.mode {
	case connectionmode.ModeP2PLazy:
		return deactivateLazy
	case connectionmode.ModeP2PDynamic:
		return deactivateICE
	default:
		return deactivateNoop
	}
}

// DeactivatePeer is invoked when the remote peer signals GO_IDLE. The
// behavior is per-mode (see deactivatePeerAction). Phase 2 fix for the
// lazy/eager mismatch in #5989: previously this method silently no-op'd
// whenever the local manager was not in lazy mode, so a remote lazy
// peer's GO_IDLE was effectively dropped and the eager local end kept
// the peer awake.
func (e *ConnMgr) DeactivatePeer(conn *peer.Conn) {
	switch e.deactivatePeerAction() {
	case deactivateLazy:
		if !e.isStartedWithLazyMgr() {
			return
		}
		conn.Log.Infof("closing peer connection: remote peer initiated inactive, idle lazy state and sent GOAWAY")
		e.lazyConnMgr.DeactivatePeer(conn.ConnID())
	case deactivateICE:
		conn.Log.Infof("detaching ICE worker: remote peer signaled GO_IDLE (p2p-dynamic)")
		if err := e.DetachICEForPeer(conn.GetKey()); err != nil {
			conn.Log.Warnf("DetachICEForPeer failed: %v", err)
		}
	case deactivateNoop:
		// Eager modes keep the tunnel up unconditionally.
		return
	}
}

// DetachICEForPeer looks up the Conn for peerKey and tears down its
// ICE worker without touching the relay tunnel. Used by:
//   - DeactivatePeer when the remote peer sends GO_IDLE (p2p-dynamic)
//   - the inactivity manager when the iceTimeout elapses (wired in
//     engine.go runDynamicInactivityLoop)
//
// Missing peers are not an error; they may have been removed concurrently.
func (e *ConnMgr) DetachICEForPeer(peerKey string) error {
	conn, ok := e.peerStore.PeerConn(peerKey)
	if !ok {
		return nil
	}
	return conn.DetachICE()
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
	if e.relayTimeoutSecs > 0 {
		cfg.RelayInactivityThreshold = time.Duration(e.relayTimeoutSecs) * time.Second
	}
	if e.mode == connectionmode.ModeP2PDynamic && e.p2pTimeoutSecs > 0 {
		cfg.ICEInactivityThreshold = time.Duration(e.p2pTimeoutSecs) * time.Second
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
