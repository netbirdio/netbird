package peer

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pion/ice/v4"
	log "github.com/sirupsen/logrus"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/netbirdio/netbird/client/iface/configurer"
	"github.com/netbirdio/netbird/client/iface/wgproxy"
	"github.com/netbirdio/netbird/client/internal/metrics"
	"github.com/netbirdio/netbird/shared/connectionmode"
	"github.com/netbirdio/netbird/client/internal/peer/conntype"
	"github.com/netbirdio/netbird/client/internal/peer/dispatcher"
	"github.com/netbirdio/netbird/client/internal/peer/guard"
	icemaker "github.com/netbirdio/netbird/client/internal/peer/ice"
	"github.com/netbirdio/netbird/client/internal/peer/id"
	"github.com/netbirdio/netbird/client/internal/peer/worker"
	"github.com/netbirdio/netbird/client/internal/portforward"
	"github.com/netbirdio/netbird/client/internal/stdnet"
	"github.com/netbirdio/netbird/route"
	relayClient "github.com/netbirdio/netbird/shared/relay/client"
)

// MetricsRecorder is an interface for recording peer connection metrics
type MetricsRecorder interface {
	RecordConnectionStages(
		ctx context.Context,
		remotePubKey string,
		connectionType metrics.ConnectionType,
		isReconnection bool,
		timestamps metrics.ConnectionStageTimestamps,
	)
}

type ServiceDependencies struct {
	StatusRecorder     *Status
	Signaler           *Signaler
	IFaceDiscover      stdnet.ExternalIFaceDiscover
	RelayManager       *relayClient.Manager
	SrWatcher          *guard.SRWatcher
	PeerConnDispatcher *dispatcher.ConnectionDispatcher
	PortForwardManager *portforward.Manager
	MetricsRecorder    MetricsRecorder
}

type WgConfig struct {
	WgListenPort int
	RemoteKey    string
	WgInterface  WGIface
	AllowedIps   []netip.Prefix
	PreSharedKey *wgtypes.Key
}

type RosenpassConfig struct {
	// RosenpassPubKey is this peer's Rosenpass public key
	PubKey []byte
	// RosenpassPubKey is this peer's RosenpassAddr server address (IP:port)
	Addr string

	PermissiveMode bool
}

// ConnConfig is a peer Connection configuration
type ConnConfig struct {
	// Key is a public key of a remote peer
	Key string
	// LocalKey is a public key of a local peer
	LocalKey string

	AgentVersion string

	Timeout time.Duration

	WgConfig WgConfig

	LocalWgPort int

	RosenpassConfig RosenpassConfig

	// ICEConfig ICE protocol configuration
	ICEConfig icemaker.Config

	// Mode is the resolved connection mode for this peer (forwarded
	// from the engine, which got it from the conn_mgr precedence chain).
	// Phase 1 uses it to pick the skip-ICE branch when ModeRelayForced.
	Mode connectionmode.Mode

	// P2pRetryMaxSeconds is the cap for the ICE-failure backoff schedule
	// in p2p-dynamic mode. 0 = use built-in default (DefaultP2PRetryMax).
	// Wire-format sentinel uint32-max (= ^uint32(0)) means "user-explicit
	// disable", which the resolver translates to time.Duration(0) at
	// engine.go before passing it here. Phase 3 of #5989.
	P2pRetryMaxSeconds uint32
}

type Conn struct {
	Log                *log.Entry
	mu                 sync.Mutex
	iceBackoff         *iceBackoffState
	ctx                context.Context
	ctxCancel          context.CancelFunc
	config             ConnConfig
	statusRecorder     *Status
	signaler           *Signaler
	iFaceDiscover      stdnet.ExternalIFaceDiscover
	relayManager       *relayClient.Manager
	srWatcher          *guard.SRWatcher
	portForwardManager *portforward.Manager

	onConnected                               func(remoteWireGuardKey string, remoteRosenpassPubKey []byte, wireGuardIP string, remoteRosenpassAddr string)
	onDisconnected                            func(remotePeer string)
	rosenpassInitializedPresharedKeyValidator func(peerKey string) bool

	statusRelay         *worker.AtomicWorkerStatus
	statusICE           *worker.AtomicWorkerStatus
	currentConnPriority conntype.ConnPriority
	opened              bool // this flag is used to prevent close in case of not opened connection
	// everConnected is set to true the first time configureConnection
	// or relay-only setup transitions this peer into a non-None
	// priority. Codex follow-up: distinguishes the "ICE detached for
	// inactivity" case (skip guard offer to avoid spam) from the
	// "never connected yet" case (must send the bootstrap offer).
	// Without this, the guard's first fire after lazy-mgr activity
	// would incorrectly skip the initial offer because no ICE
	// listener is attached YET.
	everConnected atomic.Bool

	workerICE   *WorkerICE
	workerRelay *WorkerRelay

	wgWatcher       *WGWatcher
	wgWatcherWg     sync.WaitGroup
	wgWatcherCancel context.CancelFunc

	// used to store the remote Rosenpass key for Relayed connection in case of connection update from ice
	rosenpassRemoteKey []byte

	wgProxyICE   wgproxy.Proxy
	wgProxyRelay wgproxy.Proxy
	handshaker   *Handshaker

	guard *guard.Guard
	wg    sync.WaitGroup

	// debug purpose
	dumpState *stateDump

	endpointUpdater *EndpointUpdater

	// Connection stage timestamps for metrics
	metricsRecorder MetricsRecorder
	metricsStages   *MetricsStages
}

// NewConn creates a new not opened Conn to the remote peer.
// To establish a connection run Conn.Open
func NewConn(config ConnConfig, services ServiceDependencies) (*Conn, error) {
	if len(config.WgConfig.AllowedIps) == 0 {
		return nil, fmt.Errorf("allowed IPs is empty")
	}

	connLog := log.WithField("peer", config.Key)

	dumpState := newStateDump(config.Key, connLog, services.StatusRecorder)
	var conn = &Conn{
		Log:                connLog,
		config:             config,
		statusRecorder:     services.StatusRecorder,
		signaler:           services.Signaler,
		iFaceDiscover:      services.IFaceDiscover,
		relayManager:       services.RelayManager,
		srWatcher:          services.SrWatcher,
		portForwardManager: services.PortForwardManager,
		statusRelay:        worker.NewAtomicStatus(),
		statusICE:          worker.NewAtomicStatus(),
		dumpState:          dumpState,
		endpointUpdater:    NewEndpointUpdater(connLog, config.WgConfig, isController(config)),
		wgWatcher:          NewWGWatcher(connLog, config.WgConfig.WgInterface, config.Key, dumpState),
		metricsRecorder:    services.MetricsRecorder,
	}

	return conn, nil
}

// Open opens connection to the remote peer
// It will try to establish a connection using ICE and in parallel with relay. The higher priority connection type will
// be used.
func (conn *Conn) Open(engineCtx context.Context) error {
	conn.mu.Lock()
	defer conn.mu.Unlock()

	if conn.opened {
		return nil
	}

	// Allocate new metrics stages so old goroutines don't corrupt new state
	conn.metricsStages = &MetricsStages{}

	conn.ctx, conn.ctxCancel = context.WithCancel(engineCtx)

	conn.workerRelay = NewWorkerRelay(conn.ctx, conn.Log, isController(conn.config), conn.config, conn, conn.relayManager)

	// Phase 3: initialize per-peer ICE-failure backoff. The cap comes
	// from the resolved P2pRetryMaxSeconds. 0 means "use built-in default".
	backoffCap := time.Duration(conn.config.P2pRetryMaxSeconds) * time.Second
	if backoffCap == 0 {
		backoffCap = DefaultP2PRetryMax
	}
	if conn.iceBackoff == nil {
		conn.iceBackoff = newIceBackoff(backoffCap)
	} else {
		conn.iceBackoff.SetMaxBackoff(backoffCap)
	}

	// Mode-driven branching. ModeRelayForced skips ICE entirely; all
	// other modes (P2P, P2PLazy, P2PDynamic) construct workerICE
	// eagerly in Phase 1. Phase 2 will branch P2PDynamic separately
	// to defer the OnNewOffer registration.
	skipICE := conn.config.Mode == connectionmode.ModeRelayForced
	if !skipICE {
		relayIsSupportedLocally := conn.workerRelay.RelayIsSupportedLocally()
		workerICE, err := NewWorkerICE(conn.ctx, conn.Log, conn.config, conn, conn.signaler, conn.iFaceDiscover, conn.statusRecorder, relayIsSupportedLocally)
		if err != nil {
			return err
		}
		conn.workerICE = workerICE
	}

	conn.handshaker = NewHandshaker(conn.Log, conn.config, conn.signaler, conn.workerICE, conn.workerRelay, conn.metricsStages)

	conn.handshaker.AddRelayListener(conn.workerRelay.OnNewOffer)

	// ICE-listener registration depends on mode:
	// - ModeRelayForced: skipICE=true, no workerICE, no listener.
	// - ModeP2P, ModeP2PLazy: workerICE constructed, listener registered eagerly.
	//   P2PLazy's whole-tunnel deferral happens at the conn_mgr level, not here.
	// - ModeP2PDynamic: workerICE constructed eagerly so it's ready, but the
	//   listener registration is deferred. The inactivity manager calls
	//   Conn.AttachICE() once activity is observed on the relay tunnel.
	deferICEListener := conn.config.Mode == connectionmode.ModeP2PDynamic
	if !skipICE && !deferICEListener {
		conn.handshaker.AddICEListener(conn.workerICE.OnNewOffer)
	}

	conn.guard = guard.NewGuard(conn.Log, conn.isConnectedOnAllWay, conn.config.Timeout, conn.srWatcher)
	// Phase 3.5 (#5989): reset ICE backoff + recreate workerICE on network change.
	// Set before Start() is called so the goroutine sees it without races.
	if !skipICE {
		conn.guard.SetOnNetworkChange(conn.onNetworkChange)
	}

	conn.wg.Add(1)
	go func() {
		defer conn.wg.Done()
		conn.handshaker.Listen(conn.ctx)
	}()
	go conn.dumpState.Start(conn.ctx)

	peerState := State{
		PubKey:           conn.config.Key,
		ConnStatusUpdate: time.Now(),
		ConnStatus:       StatusConnecting,
		Mux:              new(sync.RWMutex),
	}
	if err := conn.statusRecorder.UpdatePeerState(peerState); err != nil {
		conn.Log.Warnf("error while updating the state err: %v", err)
	}

	conn.wg.Add(1)
	go func() {
		defer conn.wg.Done()
		conn.guard.Start(conn.ctx, conn.onGuardEvent)
	}()
	conn.opened = true
	return nil
}

// Close closes this peer Conn issuing a close event to the Conn closeCh
func (conn *Conn) Close(signalToRemote bool) {
	conn.mu.Lock()
	defer conn.wgWatcherWg.Wait()
	defer conn.mu.Unlock()

	if !conn.opened {
		conn.Log.Debugf("ignore close connection to peer")
		return
	}

	if signalToRemote {
		if err := conn.signaler.SignalIdle(conn.config.Key); err != nil {
			conn.Log.Errorf("failed to signal idle state to peer: %v", err)
		}
	}

	conn.Log.Infof("close peer connection")
	conn.ctxCancel()

	if conn.wgWatcherCancel != nil {
		conn.wgWatcherCancel()
	}
	conn.workerRelay.CloseConn()
	if conn.workerICE != nil {
		conn.workerICE.Close()
	}

	if conn.wgProxyRelay != nil {
		err := conn.wgProxyRelay.CloseConn()
		if err != nil {
			conn.Log.Errorf("failed to close wg proxy for relay: %v", err)
		}
		conn.wgProxyRelay = nil
	}

	if conn.wgProxyICE != nil {
		err := conn.wgProxyICE.CloseConn()
		if err != nil {
			conn.Log.Errorf("failed to close wg proxy for ice: %v", err)
		}
		conn.wgProxyICE = nil
	}

	if err := conn.endpointUpdater.RemoveWgPeer(); err != nil {
		conn.Log.Errorf("failed to remove wg endpoint: %v", err)
	}

	if conn.evalStatus() == StatusConnected && conn.onDisconnected != nil {
		conn.onDisconnected(conn.config.WgConfig.RemoteKey)
	}

	conn.setStatusToDisconnected()
	conn.opened = false
	conn.wg.Wait()
	conn.Log.Infof("peer connection closed")
}

// OnRemoteAnswer handles an offer from the remote peer and returns true if the message was accepted, false otherwise
// doesn't block, discards the message if connection wasn't ready
func (conn *Conn) OnRemoteAnswer(answer OfferAnswer) {
	conn.dumpState.RemoteAnswer()
	conn.Log.Infof("OnRemoteAnswer, priority: %s, status ICE: %s, status relay: %s", conn.currentConnPriority, conn.statusICE, conn.statusRelay)
	conn.handshaker.OnRemoteAnswer(answer)
}

// OnRemoteCandidate Handles ICE connection Candidate provided by the remote peer.
func (conn *Conn) OnRemoteCandidate(candidate ice.Candidate, haRoutes route.HAMap) {
	conn.dumpState.RemoteCandidate()
	if conn.workerICE != nil {
		conn.workerICE.OnRemoteCandidate(candidate, haRoutes)
	}
}

// SetOnConnected sets a handler function to be triggered by Conn when a new connection to a remote peer established
func (conn *Conn) SetOnConnected(handler func(remoteWireGuardKey string, remoteRosenpassPubKey []byte, wireGuardIP string, remoteRosenpassAddr string)) {
	conn.onConnected = handler
}

// SetOnDisconnected sets a handler function to be triggered by Conn when a connection to a remote disconnected
func (conn *Conn) SetOnDisconnected(handler func(remotePeer string)) {
	conn.onDisconnected = handler
}

// SetRosenpassInitializedPresharedKeyValidator sets a function to check if Rosenpass has taken over
// PSK management for a peer. When this returns true, presharedKey() returns nil
// to prevent UpdatePeer from overwriting the Rosenpass-managed PSK.
func (conn *Conn) SetRosenpassInitializedPresharedKeyValidator(handler func(peerKey string) bool) {
	conn.rosenpassInitializedPresharedKeyValidator = handler
}

func (conn *Conn) OnRemoteOffer(offer OfferAnswer) {
	conn.dumpState.RemoteOffer()
	conn.Log.Infof("OnRemoteOffer, on status ICE: %s, status Relay: %s", conn.statusICE, conn.statusRelay)
	conn.handshaker.OnRemoteOffer(offer)
}

// WgConfig returns the WireGuard config
func (conn *Conn) WgConfig() WgConfig {
	return conn.config.WgConfig
}

// IsConnected returns true if the peer is connected
func (conn *Conn) IsConnected() bool {
	conn.mu.Lock()
	defer conn.mu.Unlock()

	return conn.evalStatus() == StatusConnected
}

func (conn *Conn) GetKey() string {
	return conn.config.Key
}

func (conn *Conn) ConnID() id.ConnID {
	return id.ConnID(conn)
}

// configureConnection starts proxying traffic from/to local Wireguard and sets connection status to StatusConnected
func (conn *Conn) onICEConnectionIsReady(priority conntype.ConnPriority, iceConnInfo ICEConnInfo) {
	conn.mu.Lock()
	defer conn.mu.Unlock()

	if conn.ctx.Err() != nil {
		return
	}

	if remoteConnNil(conn.Log, iceConnInfo.RemoteConn) {
		conn.Log.Errorf("remote ICE connection is nil")
		return
	}

	// this never should happen, because Relay is the lower priority and ICE always close the deprecated connection before upgrade
	// todo consider to remove this check
	if conn.currentConnPriority > priority {
		conn.Log.Infof("current connection priority (%s) is higher than the new one (%s), do not upgrade connection", conn.currentConnPriority, priority)
		conn.statusICE.SetConnected()
		conn.updateIceState(iceConnInfo, time.Now())
		return
	}

	conn.Log.Infof("set ICE to active connection")
	conn.dumpState.P2PConnected()

	var (
		ep      *net.UDPAddr
		wgProxy wgproxy.Proxy
		err     error
	)
	if iceConnInfo.RelayedOnLocal {
		conn.dumpState.NewLocalProxy()
		wgProxy, err = conn.newProxy(iceConnInfo.RemoteConn)
		if err != nil {
			conn.Log.Errorf("failed to add turn net.Conn to local proxy: %v", err)
			return
		}
		ep = wgProxy.EndpointAddr()
		conn.wgProxyICE = wgProxy
	} else {
		directEp, err := net.ResolveUDPAddr("udp", iceConnInfo.RemoteConn.RemoteAddr().String())
		if err != nil {
			log.Errorf("failed to resolveUDPaddr")
			conn.handleConfigurationFailure(err, nil)
			return
		}
		ep = directEp
	}

	// Bring the new ICE proxy up FIRST so the destination is ready to
	// receive packets. Then update WG to use it. Only after WG has
	// committed to the new endpoint do we pause the relay -- otherwise
	// there is a 1-2 s window where relay is suspended but WG still
	// points at it, dropping every packet in that window.
	if wgProxy != nil {
		wgProxy.Work()
	}

	conn.Log.Infof("configure WireGuard endpoint to: %s", ep.String())
	updateTime := time.Now()
	conn.enableWgWatcherIfNeeded(updateTime)

	presharedKey := conn.presharedKey(iceConnInfo.RosenpassPubKey)
	if err = conn.endpointUpdater.ConfigureWGEndpoint(ep, presharedKey); err != nil {
		conn.handleConfigurationFailure(err, wgProxy)
		return
	}
	wgConfigWorkaround()

	if conn.wgProxyRelay != nil {
		conn.Log.Debugf("redirect packets from relayed conn to WireGuard")
		conn.wgProxyRelay.RedirectAs(ep)
		// Pause AFTER the redirect is wired up so any in-flight packet
		// from the relay end has a forwarding path while WG converges
		// onto the direct endpoint.
		conn.wgProxyRelay.Pause()
	}

	conn.currentConnPriority = priority
	conn.everConnected.Store(true)
	conn.statusICE.SetConnected()
	conn.updateIceState(iceConnInfo, updateTime)
	conn.doOnConnected(iceConnInfo.RosenpassPubKey, iceConnInfo.RosenpassAddr, updateTime)
}

func (conn *Conn) onICEStateDisconnected(sessionChanged bool) {
	conn.mu.Lock()
	defer conn.mu.Unlock()

	if conn.ctx.Err() != nil {
		return
	}

	conn.Log.Tracef("ICE connection state changed to disconnected")

	if conn.wgProxyICE != nil {
		if err := conn.wgProxyICE.CloseConn(); err != nil {
			conn.Log.Warnf("failed to close deprecated wg proxy conn: %v", err)
		}
	}

	// switch back to relay connection
	if conn.isReadyToUpgrade() {
		conn.Log.Infof("ICE disconnected, set Relay to active connection")
		conn.dumpState.SwitchToRelay()
		if sessionChanged {
			conn.resetEndpoint()
		}

		// todo consider to move after the ConfigureWGEndpoint
		conn.wgProxyRelay.Work()

		presharedKey := conn.presharedKey(conn.rosenpassRemoteKey)
		if err := conn.endpointUpdater.SwitchWGEndpoint(conn.wgProxyRelay.EndpointAddr(), presharedKey); err != nil {
			conn.Log.Errorf("failed to switch to relay conn: %v", err)
		}

		conn.currentConnPriority = conntype.Relay
	} else {
		conn.Log.Infof("ICE disconnected, do not switch to Relay. Reset priority to: %s", conntype.None.String())
		conn.currentConnPriority = conntype.None
		// Intentionally NOT calling RemoveEndpointAddress here: a brief
		// ICE flap (NAT rebind, signal hiccup) is followed within 1-2 s
		// by a fresh ICE-connected callback that re-configures the WG
		// endpoint. Actively removing the endpoint creates a no-endpoint
		// window in which WG drops every packet rather than queuing on
		// a slightly-stale address that the next ConfigureWGEndpoint
		// will replace anyway. If the disconnect is permanent, WG's own
		// keepalive timeout will surface the dead peer.
	}

	changed := conn.statusICE.Get() != worker.StatusDisconnected
	if changed {
		conn.guard.SetICEConnDisconnected()
	}
	conn.statusICE.SetDisconnected()

	conn.disableWgWatcherIfNeeded()

	if conn.currentConnPriority == conntype.None {
		conn.metricsStages.Disconnected()
	}

	peerState := State{
		PubKey:           conn.config.Key,
		ConnStatus:       conn.evalStatus(),
		Relayed:          conn.isRelayed(),
		ConnStatusUpdate: time.Now(),
	}
	if err := conn.statusRecorder.UpdatePeerICEStateToDisconnected(peerState); err != nil {
		conn.Log.Warnf("unable to set peer's state to disconnected ice, got error: %v", err)
	}
}

func (conn *Conn) onRelayConnectionIsReady(rci RelayConnInfo) {
	conn.mu.Lock()
	defer conn.mu.Unlock()

	if conn.ctx.Err() != nil {
		if err := rci.relayedConn.Close(); err != nil {
			conn.Log.Warnf("failed to close unnecessary relayed connection: %v", err)
		}
		return
	}

	conn.dumpState.RelayConnected()
	conn.Log.Debugf("Relay connection has been established, setup the WireGuard")

	wgProxy, err := conn.newProxy(rci.relayedConn)
	if err != nil {
		conn.Log.Errorf("failed to add relayed net.Conn to local proxy: %v", err)
		return
	}
	wgProxy.SetDisconnectListener(conn.onRelayDisconnected)

	conn.dumpState.NewLocalProxy()

	conn.Log.Infof("created new wgProxy for relay connection: %s", wgProxy.EndpointAddr().String())

	if conn.isICEActive() {
		conn.Log.Debugf("do not switch to relay because current priority is: %s", conn.currentConnPriority.String())
		conn.setRelayedProxy(wgProxy)
		conn.statusRelay.SetConnected()
		conn.updateRelayStatus(rci.relayedConn.RemoteAddr().String(), rci.rosenpassPubKey, time.Now())
		return
	}

	controller := isController(conn.config)

	if controller {
		wgProxy.Work()
	}
	updateTime := time.Now()
	conn.enableWgWatcherIfNeeded(updateTime)
	if err := conn.endpointUpdater.ConfigureWGEndpoint(wgProxy.EndpointAddr(), conn.presharedKey(rci.rosenpassPubKey)); err != nil {
		if err := wgProxy.CloseConn(); err != nil {
			conn.Log.Warnf("Failed to close relay connection: %v", err)
		}
		conn.Log.Errorf("Failed to update WireGuard peer configuration: %v", err)
		return
	}
	if !controller {
		wgProxy.Work()
	}

	wgConfigWorkaround()

	conn.rosenpassRemoteKey = rci.rosenpassPubKey
	conn.currentConnPriority = conntype.Relay
	conn.everConnected.Store(true)
	conn.statusRelay.SetConnected()
	conn.setRelayedProxy(wgProxy)
	conn.updateRelayStatus(rci.relayedConn.RemoteAddr().String(), rci.rosenpassPubKey, updateTime)
	conn.Log.Infof("start to communicate with peer via relay")
	conn.doOnConnected(rci.rosenpassPubKey, rci.rosenpassAddr, updateTime)
}

func (conn *Conn) onRelayDisconnected() {
	conn.mu.Lock()
	defer conn.mu.Unlock()
	conn.handleRelayDisconnectedLocked()
}

// handleRelayDisconnectedLocked handles relay disconnection. Caller must hold conn.mu.
func (conn *Conn) handleRelayDisconnectedLocked() {
	if conn.ctx.Err() != nil {
		return
	}

	conn.Log.Debugf("relay connection is disconnected")

	if conn.currentConnPriority == conntype.Relay {
		conn.Log.Debugf("clean up WireGuard config")
		conn.currentConnPriority = conntype.None
		if err := conn.config.WgConfig.WgInterface.RemoveEndpointAddress(conn.config.WgConfig.RemoteKey); err != nil {
			conn.Log.Errorf("failed to remove wg endpoint: %v", err)
		}
	}

	if conn.wgProxyRelay != nil {
		_ = conn.wgProxyRelay.CloseConn()
		conn.wgProxyRelay = nil
	}

	changed := conn.statusRelay.Get() != worker.StatusDisconnected
	if changed {
		conn.guard.SetRelayedConnDisconnected()
	}
	conn.statusRelay.SetDisconnected()

	conn.disableWgWatcherIfNeeded()

	if conn.currentConnPriority == conntype.None {
		conn.metricsStages.Disconnected()
	}

	peerState := State{
		PubKey:           conn.config.Key,
		ConnStatus:       conn.evalStatus(),
		Relayed:          conn.isRelayed(),
		ConnStatusUpdate: time.Now(),
	}
	if err := conn.statusRecorder.UpdatePeerRelayedStateToDisconnected(peerState); err != nil {
		conn.Log.Warnf("unable to save peer's state to Relay disconnected, got error: %v", err)
	}
}

func (conn *Conn) onGuardEvent() {
	// Suppress reconnect-offers under p2p-dynamic when the management
	// server reports the remote peer as offline (live_online=false). The
	// guard otherwise spams an offer every 5-30 s for up to relay_timeout
	// minutes after the remote disappeared, and each offer that survives
	// (when the remote reconnects) immediately wakes the lazy manager on
	// the remote side -- defeating the user-visible "idle until traffic"
	// promise of p2p-dynamic. Eager modes (p2p, relay-forced) keep the
	// always-on behaviour because that's what those modes are for.
	if conn.config.Mode == connectionmode.ModeP2PDynamic {
		if state, err := conn.statusRecorder.GetPeer(conn.config.Key); err == nil {
			if state.RemoteServerLivenessKnown && !state.RemoteLiveOnline {
				conn.Log.Tracef("guard: skip offer (remote peer offline, p2p-dynamic)")
				return
			}
		}
		// Codex hardening audit: also skip when the guard is firing
		// for "PartiallyConnected" (relay up, ICE detached) AND the
		// detach was due to ICE-inactivity (the dynamic inactivity
		// manager called DetachICEForPeer because no payload traffic
		// for iceTimeout). Re-firing offers in that state wastes
		// signal traffic and can wake the remote's lazy manager just
		// to re-attach ICE that we'll detach again on the next idle
		// cycle. The next REAL outbound packet on this peer will go
		// through ConnMgr.ActivatePeer -> conn.AttachICE which DOES
		// respect iceBackoff and is the correct path to re-engage ICE.
		//
		// Detection requires THREE conditions:
		//   1. ICE worker exists but is detached (no listener),
		//   2. no recorded ICE-failure-backoff (else the existing
		//      3-tries-then-hourly retry policy handles it),
		//   3. this Conn has been connected at least ONCE before (the
		//      everConnected flag). Without #3 we'd skip the very
		//      first bootstrap offer for a brand-new peer because
		//      its ICE listener is also nil before initial setup —
		//      regression caught during 6-host hardware test on
		//      4998e5a58.
		if conn.everConnected.Load() &&
			conn.handshaker != nil && conn.handshaker.readICEListener() == nil {
			if state, err := conn.statusRecorder.GetPeer(conn.config.Key); err == nil {
				if !state.IceBackoffSuspended && state.IceBackoffFailures == 0 {
					conn.Log.Tracef("guard: skip offer (ICE detached for inactivity, p2p-dynamic; will re-attach on real traffic)")
					return
				}
			}
		}
	}
	conn.dumpState.SendOffer()
	if err := conn.handshaker.SendOffer(); err != nil {
		conn.Log.Errorf("failed to send offer: %v", err)
	}
}

func (conn *Conn) onWGDisconnected() {
	conn.mu.Lock()
	defer conn.mu.Unlock()

	if conn.ctx.Err() != nil {
		return
	}

	conn.Log.Warnf("WireGuard handshake timeout detected, closing current connection")

	// Close the active connection based on current priority
	switch conn.currentConnPriority {
	case conntype.Relay:
		conn.workerRelay.CloseConn()
		conn.handleRelayDisconnectedLocked()
	case conntype.ICEP2P, conntype.ICETurn:
		conn.workerICE.Close()
	default:
		conn.Log.Debugf("No active connection to close on WG timeout")
	}
}

func (conn *Conn) updateRelayStatus(relayServerAddr string, rosenpassPubKey []byte, updateTime time.Time) {
	peerState := State{
		PubKey:             conn.config.Key,
		ConnStatusUpdate:   updateTime,
		ConnStatus:         conn.evalStatus(),
		Relayed:            conn.isRelayed(),
		RelayServerAddress: relayServerAddr,
		RosenpassEnabled:   isRosenpassEnabled(rosenpassPubKey),
	}

	err := conn.statusRecorder.UpdatePeerRelayedState(peerState)
	if err != nil {
		conn.Log.Warnf("unable to save peer's Relay state, got error: %v", err)
	}
}

func (conn *Conn) updateIceState(iceConnInfo ICEConnInfo, updateTime time.Time) {
	peerState := State{
		PubKey:                     conn.config.Key,
		ConnStatusUpdate:           updateTime,
		ConnStatus:                 conn.evalStatus(),
		Relayed:                    iceConnInfo.Relayed,
		LocalIceCandidateType:      iceConnInfo.LocalIceCandidateType,
		RemoteIceCandidateType:     iceConnInfo.RemoteIceCandidateType,
		LocalIceCandidateEndpoint:  iceConnInfo.LocalIceCandidateEndpoint,
		RemoteIceCandidateEndpoint: iceConnInfo.RemoteIceCandidateEndpoint,
		RosenpassEnabled:           isRosenpassEnabled(iceConnInfo.RosenpassPubKey),
	}

	err := conn.statusRecorder.UpdatePeerICEState(peerState)
	if err != nil {
		conn.Log.Warnf("unable to save peer's ICE state, got error: %v", err)
	}
}

func (conn *Conn) setStatusToDisconnected() {
	conn.statusRelay.SetDisconnected()
	conn.statusICE.SetDisconnected()
	conn.currentConnPriority = conntype.None

	peerState := State{
		PubKey:           conn.config.Key,
		ConnStatus:       StatusIdle,
		ConnStatusUpdate: time.Now(),
		Mux:              new(sync.RWMutex),
	}
	err := conn.statusRecorder.UpdatePeerState(peerState)
	if err != nil {
		// pretty common error because by that time Engine can already remove the peer and status won't be available.
		// todo rethink status updates
		conn.Log.Debugf("error while updating peer's state, err: %v", err)
	}
	if err := conn.statusRecorder.UpdateWireGuardPeerState(conn.config.Key, configurer.WGStats{}); err != nil {
		conn.Log.Debugf("failed to reset wireguard stats for peer: %s", err)
	}
}

func (conn *Conn) doOnConnected(remoteRosenpassPubKey []byte, remoteRosenpassAddr string, updateTime time.Time) {
	if runtime.GOOS == "ios" {
		runtime.GC()
	}

	conn.metricsStages.RecordConnectionReady(updateTime)

	if conn.onConnected != nil {
		conn.onConnected(conn.config.Key, remoteRosenpassPubKey, conn.config.WgConfig.AllowedIps[0].Addr().String(), remoteRosenpassAddr)
	}
}

func (conn *Conn) isRelayed() bool {
	switch conn.currentConnPriority {
	case conntype.Relay, conntype.ICETurn:
		return true
	default:
		return false
	}
}

func (conn *Conn) evalStatus() ConnStatus {
	if conn.statusRelay.Get() == worker.StatusConnected || conn.statusICE.Get() == worker.StatusConnected {
		return StatusConnected
	}

	return StatusConnecting
}

// isConnectedOnAllWay evaluates the overall connection status based on ICE and Relay transports.
//
// The result is a tri-state:
//   - ConnStatusConnected:          all available transports are up
//   - ConnStatusPartiallyConnected: relay is up but ICE is still pending/reconnecting
//   - ConnStatusDisconnected:       no working transport
func (conn *Conn) isConnectedOnAllWay() (status guard.ConnStatus) {
	defer func() {
		if status == guard.ConnStatusDisconnected {
			conn.logTraceConnState()
		}
	}()

	iceWorkerCreated := conn.workerICE != nil

	var iceInProgress bool
	if iceWorkerCreated {
		iceInProgress = conn.workerICE.InProgress()
	}

	return evalConnStatus(connStatusInputs{
		forceRelay:          conn.config.Mode == connectionmode.ModeRelayForced,
		peerUsesRelay:       conn.workerRelay.IsRelayConnectionSupportedWithPeer(),
		relayConnected:      conn.statusRelay.Get() == worker.StatusConnected,
		remoteSupportsICE:   conn.handshaker.RemoteICESupported(),
		iceWorkerCreated:    iceWorkerCreated,
		iceStatusConnecting: conn.statusICE.Get() != worker.StatusDisconnected,
		iceInProgress:       iceInProgress,
	})
}

func (conn *Conn) enableWgWatcherIfNeeded(enabledTime time.Time) {
	if !conn.wgWatcher.IsEnabled() {
		wgWatcherCtx, wgWatcherCancel := context.WithCancel(conn.ctx)
		conn.wgWatcherCancel = wgWatcherCancel
		conn.wgWatcherWg.Add(1)
		go func() {
			defer conn.wgWatcherWg.Done()
			conn.wgWatcher.EnableWgWatcher(wgWatcherCtx, enabledTime, conn.onWGDisconnected, conn.onWGHandshakeSuccess)
		}()
	}
}

func (conn *Conn) disableWgWatcherIfNeeded() {
	if conn.currentConnPriority == conntype.None && conn.wgWatcherCancel != nil {
		conn.wgWatcherCancel()
		conn.wgWatcherCancel = nil
	}
}

func (conn *Conn) newProxy(remoteConn net.Conn) (wgproxy.Proxy, error) {
	conn.Log.Debugf("setup proxied WireGuard connection")
	udpAddr := &net.UDPAddr{
		IP:   conn.config.WgConfig.AllowedIps[0].Addr().AsSlice(),
		Port: conn.config.WgConfig.WgListenPort,
	}

	wgProxy := conn.config.WgConfig.WgInterface.GetProxy()
	if err := wgProxy.AddTurnConn(conn.ctx, udpAddr, remoteConn); err != nil {
		conn.Log.Errorf("failed to add turn net.Conn to local proxy: %v", err)
		return nil, err
	}
	return wgProxy, nil
}

func (conn *Conn) resetEndpoint() {
	if !isController(conn.config) {
		return
	}
	conn.Log.Infof("reset wg endpoint")
	conn.wgWatcher.Reset()
	if err := conn.endpointUpdater.RemoveEndpointAddress(); err != nil {
		conn.Log.Warnf("failed to remove endpoint address before update: %v", err)
	}
}

func (conn *Conn) isReadyToUpgrade() bool {
	return conn.wgProxyRelay != nil && conn.currentConnPriority != conntype.Relay
}

func (conn *Conn) isICEActive() bool {
	return (conn.currentConnPriority == conntype.ICEP2P || conn.currentConnPriority == conntype.ICETurn) && conn.statusICE.Get() == worker.StatusConnected
}

func (conn *Conn) handleConfigurationFailure(err error, wgProxy wgproxy.Proxy) {
	conn.Log.Warnf("Failed to update wg peer configuration: %v", err)
	if wgProxy != nil {
		if ierr := wgProxy.CloseConn(); ierr != nil {
			conn.Log.Warnf("Failed to close wg proxy: %v", ierr)
		}
	}
	if conn.wgProxyRelay != nil {
		conn.wgProxyRelay.Work()
	}
}

func (conn *Conn) logTraceConnState() {
	if conn.workerRelay.IsRelayConnectionSupportedWithPeer() {
		conn.Log.Tracef("connectivity guard check, relay state: %s, ice state: %s", conn.statusRelay, conn.statusICE)
	} else {
		conn.Log.Tracef("connectivity guard check, ice state: %s", conn.statusICE)
	}
}

func (conn *Conn) setRelayedProxy(proxy wgproxy.Proxy) {
	if conn.wgProxyRelay != nil {
		if err := conn.wgProxyRelay.CloseConn(); err != nil {
			conn.Log.Warnf("failed to close deprecated wg proxy conn: %v", err)
		}
	}
	conn.wgProxyRelay = proxy
}

// onWGHandshakeSuccess is called when the first WireGuard handshake is detected
func (conn *Conn) onWGHandshakeSuccess(when time.Time) {
	conn.metricsStages.RecordWGHandshakeSuccess(when)
	conn.recordConnectionMetrics()
}

// recordConnectionMetrics records connection stage timestamps as metrics
func (conn *Conn) recordConnectionMetrics() {
	if conn.metricsRecorder == nil {
		return
	}

	// Determine connection type based on current priority
	conn.mu.Lock()
	priority := conn.currentConnPriority
	conn.mu.Unlock()

	var connType metrics.ConnectionType
	switch priority {
	case conntype.Relay:
		connType = metrics.ConnectionTypeRelay
	default:
		connType = metrics.ConnectionTypeICE
	}

	// Record metrics with timestamps - duration calculation happens in metrics package
	conn.metricsRecorder.RecordConnectionStages(
		context.Background(),
		conn.config.Key,
		connType,
		conn.metricsStages.IsReconnection(),
		conn.metricsStages.GetTimestamps(),
	)
}

// AllowedIP returns the allowed IP of the remote peer
func (conn *Conn) AllowedIP() netip.Addr {
	return conn.config.WgConfig.AllowedIps[0].Addr()
}

func (conn *Conn) AgentVersionString() string {
	return conn.config.AgentVersion
}

func (conn *Conn) presharedKey(remoteRosenpassKey []byte) *wgtypes.Key {
	if conn.config.RosenpassConfig.PubKey == nil {
		return conn.config.WgConfig.PreSharedKey
	}

	if remoteRosenpassKey == nil && conn.config.RosenpassConfig.PermissiveMode {
		return conn.config.WgConfig.PreSharedKey
	}

	// If Rosenpass has already set a PSK for this peer, return nil to prevent
	// UpdatePeer from overwriting the Rosenpass-managed key.
	if conn.rosenpassInitializedPresharedKeyValidator != nil && conn.rosenpassInitializedPresharedKeyValidator(conn.config.Key) {
		return nil
	}

	// Use NetBird PSK as the seed for Rosenpass. This same PSK is passed to
	// Rosenpass as PeerConfig.PresharedKey, ensuring the derived post-quantum
	// key is cryptographically bound to the original secret.
	if conn.config.WgConfig.PreSharedKey != nil {
		return conn.config.WgConfig.PreSharedKey
	}

	// Fallback to deterministic key if no NetBird PSK is configured
	determKey, err := conn.rosenpassDetermKey()
	if err != nil {
		conn.Log.Errorf("failed to generate Rosenpass initial key: %v", err)
		return nil
	}

	return determKey
}

// todo: move this logic into Rosenpass package
func (conn *Conn) rosenpassDetermKey() (*wgtypes.Key, error) {
	lk := []byte(conn.config.LocalKey)
	rk := []byte(conn.config.Key) // remote key
	var keyInput []byte
	if string(lk) > string(rk) {
		//nolint:gocritic
		keyInput = append(lk[:16], rk[:16]...)
	} else {
		//nolint:gocritic
		keyInput = append(rk[:16], lk[:16]...)
	}

	key, err := wgtypes.NewKey(keyInput)
	if err != nil {
		return nil, err
	}
	return &key, nil
}

func isController(config ConnConfig) bool {
	return config.LocalKey > config.Key
}

func isRosenpassEnabled(remoteRosenpassPubKey []byte) bool {
	return remoteRosenpassPubKey != nil
}

func evalConnStatus(in connStatusInputs) guard.ConnStatus {
	// "Relay up and needed" — the peer uses relay and the transport is connected.
	relayUsedAndUp := in.peerUsesRelay && in.relayConnected

	// Force-relay mode: ICE never runs. Relay is the only transport and must be up.
	if in.forceRelay {
		return boolToConnStatus(relayUsedAndUp)
	}

	// Remote peer doesn't support ICE, or we haven't created the worker yet:
	// relay is the only possible transport.
	if !in.remoteSupportsICE || !in.iceWorkerCreated {
		return boolToConnStatus(relayUsedAndUp)
	}

	// ICE counts as "up" when the status is anything other than Disconnected, OR
	// when a negotiation is currently in progress (so we don't spam offers while one is in flight).
	iceUp := in.iceStatusConnecting || in.iceInProgress

	// Relay side is acceptable if the peer doesn't rely on relay, or relay is connected.
	relayOK := !in.peerUsesRelay || in.relayConnected

	switch {
	case iceUp && relayOK:
		return guard.ConnStatusConnected
	case relayUsedAndUp:
		// Relay is up but ICE is down — partially connected.
		return guard.ConnStatusPartiallyConnected
	default:
		return guard.ConnStatusDisconnected
	}
}

func boolToConnStatus(connected bool) guard.ConnStatus {
	if connected {
		return guard.ConnStatusConnected
	}
	return guard.ConnStatusDisconnected
}

// AttachICE registers the ICE-offer listener on the handshaker after the
// activity-detector observes traffic on the relay tunnel. Idempotent: if
// the listener is already attached, it is a no-op. Triggers a fresh offer
// so the remote side learns we are now ICE-capable.
//
// Used by p2p-dynamic mode: workerICE is created in Open() but the
// handshaker dispatch is deferred until traffic activity is seen.
func (conn *Conn) AttachICE() error {
	conn.mu.Lock()
	defer conn.mu.Unlock()

	if conn.iceBackoff != nil && conn.iceBackoff.IsSuspended() {
		snap := conn.iceBackoff.Snapshot()
		conn.Log.Debugf("ICE backoff active (failure #%d, retry at %s), staying on relay",
			snap.Failures,
			snap.NextRetry.Format("15:04:05"))
		return nil
	}
	if conn.handshaker == nil {
		return fmt.Errorf("AttachICE: handshaker not initialized (Open not called)")
	}
	if conn.workerICE == nil {
		return fmt.Errorf("AttachICE: workerICE is nil (relay-forced mode)")
	}

	if !conn.attachICEListenerLocked() {
		return nil
	}

	if err := conn.handshaker.SendOffer(); err != nil {
		conn.Log.Warnf("AttachICE: SendOffer failed: %v", err)
	}
	return nil
}

// attachICEListenerLocked attaches the ICE listener to the handshaker if it
// is not already attached. Returns true when a new attachment was made,
// false when the call was a no-op (already attached, ICE backoff suspended,
// handshaker not initialised, or workerICE not present).
//
// Caller MUST hold conn.mu. Used by:
//   - AttachICE (signal-trigger path), which then issues SendOffer.
//   - onNetworkChange (Phase 3.7e, #5989), which deliberately does NOT call
//     SendOffer because the Guard reconnect-loop handles that.
//
// Honours iceBackoff.IsSuspended() so the failure-backoff is not bypassed.
func (conn *Conn) attachICEListenerLocked() bool {
	if conn.iceBackoff != nil && conn.iceBackoff.IsSuspended() {
		snap := conn.iceBackoff.Snapshot()
		conn.Log.Debugf("ICE backoff active (failure #%d, retry at %s), staying on relay",
			snap.Failures,
			snap.NextRetry.Format("15:04:05"))
		return false
	}
	if conn.handshaker == nil || conn.workerICE == nil {
		return false
	}
	if conn.handshaker.readICEListener() != nil {
		return false
	}

	conn.handshaker.AddICEListener(conn.workerICE.OnNewOffer)
	conn.Log.Debugf("ICE listener attached (locked path)")
	return true
}

// DetachICE removes the ICE-offer listener and tears down the ICE worker.
// Idempotent: if no listener is attached, it is a no-op. Used by
// p2p-dynamic mode when the inactivity manager fires the iceTimeout but
// the relay tunnel should stay up.
func (conn *Conn) DetachICE() error {
	conn.mu.Lock()
	defer conn.mu.Unlock()

	if conn.handshaker == nil {
		return nil
	}
	if conn.handshaker.readICEListener() == nil {
		return nil
	}

	conn.handshaker.RemoveICEListener()
	if conn.workerICE != nil {
		conn.workerICE.Close()
	}
	conn.Log.Debugf("ICE listener detached (p2p-dynamic teardown)")
	return nil
}

// onICEFailed is invoked when pion's ICE agent reports
// ConnectionStateFailed. Increments the backoff counter and tears
// down the ICE worker. Phase 3 of #5989.
func (conn *Conn) onICEFailed() {
	if conn.iceBackoff == nil {
		return
	}
	delay := conn.iceBackoff.markFailure()
	snap := conn.iceBackoff.Snapshot()
	if delay > 0 {
		conn.Log.Infof("ICE failure #%d, suspending for %s, next retry at %s",
			snap.Failures,
			delay.Round(time.Second),
			snap.NextRetry.Format("15:04:05"))
	}
	if conn.statusRecorder != nil {
		conn.statusRecorder.UpdatePeerIceBackoff(conn.config.Key, snap)
	}
	// Tear down ICE. Idempotent. Conn stays on relay.
	if err := conn.DetachICE(); err != nil {
		conn.Log.Warnf("DetachICE after onICEFailed: %v", err)
	}
}

// onICEConnected is invoked when pion's ICE agent reports
// ConnectionStateConnected. Resets the backoff. Phase 3 of #5989.
func (conn *Conn) onICEConnected() {
	if conn.iceBackoff == nil {
		return
	}
	if conn.iceBackoff.Snapshot().Failures > 0 {
		conn.Log.Infof("ICE success, resetting backoff (was %d failures)",
			conn.iceBackoff.Snapshot().Failures)
	}
	conn.iceBackoff.markSuccess()
	if conn.statusRecorder != nil {
		conn.statusRecorder.UpdatePeerIceBackoff(conn.config.Key, conn.iceBackoff.Snapshot())
	}
}

// SetIceBackoffMax updates the per-peer backoff cap. Called by ConnMgr
// when the server pushes a new p2p_retry_max_seconds value. If the
// iceBackoff is not yet initialized (Conn not opened yet), the value
// is stored in config so Open() picks it up. Phase 3 of #5989.
func (conn *Conn) SetIceBackoffMax(d time.Duration) {
	conn.mu.Lock()
	defer conn.mu.Unlock()
	conn.config.P2pRetryMaxSeconds = uint32(d / time.Second)
	if conn.iceBackoff != nil {
		conn.iceBackoff.SetMaxBackoff(d)
	}
}

// IceBackoffSnapshot exposes the read-only backoff state for the
// status output (Task E1). Returns zero-value snapshot if no backoff
// is active. Phase 3 of #5989.
func (conn *Conn) IceBackoffSnapshot() BackoffSnapshot {
	conn.mu.Lock()
	defer conn.mu.Unlock()
	if conn.iceBackoff == nil {
		return BackoffSnapshot{}
	}
	return conn.iceBackoff.Snapshot()
}

// onNetworkChange is invoked by Guard when the signal/relay layer
// reconnects after a network change (LTE-modem replug, WiFi roaming, etc.).
// Phase 3.5 of #5989.
//
// Resets the per-peer ICE-failure backoff (because the NAT topology may
// have changed -- previous failures do not predict future ones) AND
// recreates the workerICE wrapper so the next AttachICE/offer has a
// fresh pion-agent rather than one closed by a previous DetachICE call.
//
// Called from Guard's goroutine; acquires conn.mu, so it must not be
// invoked from a path that already holds conn.mu.
func (conn *Conn) onNetworkChange() {
	conn.mu.Lock()
	defer conn.mu.Unlock()

	if conn.ctx.Err() != nil {
		return
	}

	if conn.iceBackoff != nil {
		snap := conn.iceBackoff.Snapshot()
		if snap.Failures > 0 {
			conn.Log.Infof("network change detected, resetting ICE backoff (was %d failures)",
				snap.Failures)
		}
		conn.iceBackoff.Reset()
		if conn.statusRecorder != nil {
			conn.statusRecorder.UpdatePeerIceBackoff(conn.config.Key, conn.iceBackoff.Snapshot())
		}
	}

	// We deliberately do NOT replace the workerICE wrapper here. Replacing
	// it leaks underlying socket/iface bindings between the old and new
	// instance, which empirically causes ICE to fail with a 13s pair-check
	// timeout instead of converging in <1s like a fresh daemon-start does.
	//
	// We also deliberately do NOT call handshaker.SendOffer() here even
	// though that was an earlier attempt. The Guard's reconnect-loop
	// already issues sendOffer via its newReconnectTicker (800ms initial,
	// up to ~4 retries in the first ~6s) right after the same srReconnect
	// event that fires this callback. Adding our own SendOffer just creates
	// a sending-offer storm: 5 offers per peer in 6 seconds, which on the
	// remote side triggers repeated tear-down + reCreateAgent cycles in
	// quick succession (each new sessionID forces it). That prevents ICE
	// from ever completing its pair-checks.
	//
	// All we do here: close the current pion agent (sets w.agent = nil).
	// The Guard's natural reconnect-loop then drives the next sendOffer,
	// the remote responds with a fresh offer, and our existing OnNewOffer
	// path (still attached to the unchanged workerICE wrapper) goes
	// through the well-tested "agent==nil + new offer -> reCreateAgent"
	// branch in worker_ice.go.
	//
	// Phase 3.7g (#5989): only tear down the workerICE agent when ICE is
	// actually broken. If pion's lastKnownState is still Connected the
	// peer-to-peer UDP path is alive end-to-end (typical for a brief
	// signal-server outage where WG keepalives between peers continued
	// to flow); closing the agent here would force a 15-25 s ICE
	// renegotiation cycle plus a Relay→ICE handover gap that the user
	// would observe as a ping dropout for no good reason.
	//
	// If ICE actually went Disconnected/Failed during the network event,
	// pion has already cleared w.agent via onConnectionStateChange and
	// the Close call below is a no-op anyway. Either way, a fresh remote
	// OFFER will recreate the agent through the existing OnNewOffer path.
	//
	// In ModeRelayForced workerICE is nil; nothing to close.
	if conn.workerICE != nil && !conn.workerICE.IsConnected() {
		conn.workerICE.Close()
	} else if conn.workerICE != nil {
		conn.Log.Debugf("network change: skipping workerICE.Close (ICE still Connected, soft-fallback)")
	}

	// Phase 3.7e (#5989): force the ICE listener back on after a network
	// change. Empirically, after an LTE-modem replug the iceListener can
	// end up detached for some peers (paths via onICEFailed → DetachICE
	// after a Failed transition that we did not log because of timing,
	// or via concurrent state changes during the bounce). Re-attaching
	// on every signal in ConnMgr.ActivatePeer (Phase 3.7d) is necessary
	// but not sufficient: by the time the next signal arrives, several
	// remote OFFERs and the Guard's first sendOffer may already have
	// been silently dropped at handshaker.Listen() because no listener
	// was present. Re-attaching here closes that window deterministically.
	//
	// We do NOT call SendOffer from this path. The Guard's natural
	// reconnect-ticker (newReconnectTicker, 800 ms initial) issues the
	// next offer right after the same srReconnect event that drove this
	// callback; sending an extra one creates the offer-storm that
	// Phase 3.7b removed.
	conn.attachICEListenerLocked()

	conn.Log.Debugf("ICE state reset on network change (agent closed; listener re-armed; Guard will resend offer)")
}
