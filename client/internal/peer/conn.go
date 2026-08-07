package peer

import (
	"context"
	"fmt"
	"math"
	"net"
	"net/netip"
	"runtime"
	"slices"
	"sync"
	"time"

	"github.com/pion/ice/v4"
	log "github.com/sirupsen/logrus"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/netbirdio/netbird/client/iface/configurer"
	"github.com/netbirdio/netbird/client/iface/wgproxy"
	"github.com/netbirdio/netbird/client/internal/metrics"
	"github.com/netbirdio/netbird/client/internal/peer/conntype"
	"github.com/netbirdio/netbird/client/internal/peer/dispatcher"
	"github.com/netbirdio/netbird/client/internal/peer/guard"
	icemaker "github.com/netbirdio/netbird/client/internal/peer/ice"
	"github.com/netbirdio/netbird/client/internal/peer/id"
	"github.com/netbirdio/netbird/client/internal/peer/worker"
	"github.com/netbirdio/netbird/client/internal/portforward"
	"github.com/netbirdio/netbird/client/internal/rosenpass"
	"github.com/netbirdio/netbird/client/internal/stdnet"
	"github.com/netbirdio/netbird/client/netevents"
	"github.com/netbirdio/netbird/monotime"
	"github.com/netbirdio/netbird/route"
	relayClient "github.com/netbirdio/netbird/shared/relay/client"
)

// wgTimeoutEscalationThreshold is the number of consecutive WireGuard
// handshake timeouts after which the rosenpass state for the peer is
// considered desynced and gets reset.
const wgTimeoutEscalationThreshold = 3

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

// PQHandshaker attaches post-quantum ML-KEM material to signalling offers/answers and
// feeds received material back. It is implemented by the engine over the pqkem
// manager and is nil when the PQ exchange is disabled. remoteKey is the peer's
// WireGuard public key.
type PQHandshaker interface {
	// OfferPayload returns the KEM offer to embed in an outgoing offer (nil if this
	// peer is not the KEM initiator) and the local PQ data-path port to announce.
	OfferPayload(remoteKey string) (payload []byte, port int)
	// ShouldSendBootstrapOffer reports whether, as the controller, we should reply to a
	// received responder offer with our own KEM offer (true only when no exchange is
	// already in flight — so we kick the KEM once and ignore further offers).
	ShouldSendBootstrapOffer(remoteKey string) bool
	// AnswerPayload processes a received KEM offer (nil if absent) and returns the KEM
	// answer to embed in the outgoing answer (nil if none) and the local PQ port.
	AnswerPayload(remoteKey string, recvOffer []byte) (payload []byte, port int)
	// OnAnswer feeds a received KEM answer (nil if absent).
	OnAnswer(remoteKey string, recvAnswer []byte)
	// PSK returns the peer's latest derived post-quantum PSK to program at WG
	// peer-config time (the pull path). ok is false until one has been derived.
	PSK(remoteKey string) (wgtypes.Key, bool)
	// SetRemoteAddr registers the peer's data-path endpoint learned from signalling:
	// its WG overlay IP with the announced pq UDP port (port 0 means the peer omitted
	// it and is on the default port).
	SetRemoteAddr(remoteKey string, addr netip.AddrPort)
	// OnDataPathRekeyed signals a fresh WireGuard handshake for the peer; it clocks the
	// next chained PSK rotation pushed over the data path. sinceActivity is how long
	// ago the peer last exchanged real user data, so the rotation can be skipped for
	// idle tunnels.
	OnDataPathRekeyed(remoteKey string, sinceActivity time.Duration)
	// OnDataPathDown signals the peer's tunnel went down.
	OnDataPathDown(remoteKey string)
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

	// PQ carries post-quantum ML-KEM material on offers/answers; nil when disabled.
	PQ PQHandshaker
	// PQStrict fails closed: block peer traffic until the ML-KEM PSK is established,
	// instead of letting the tunnel come up classically and upgrading to PQ later.
	PQStrict bool

	// ICEConfig ICE protocol configuration
	ICEConfig icemaker.Config

	// NetMgr gates the reconnection guard on OS-reported network
	// availability; nil disables gating.
	NetMgr *netevents.Manager
}

type Conn struct {
	Log                *log.Entry
	mu                 sync.Mutex
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

	workerICE   *WorkerICE
	workerRelay *WorkerRelay

	wgWatcher       *WGWatcher
	wgWatcherWg     sync.WaitGroup
	wgWatcherCancel context.CancelFunc
	// wgTimeouts counts consecutive WireGuard handshake timeouts without a
	// successful handshake in between. Guarded by mu.
	wgTimeouts int

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

	// pendingFirstPacket is the lazyconn-captured handshake init, replayed once the real
	// transport is up.
	pendingFirstPacket []byte

	// pqStrictSentinelKey is a per-conn random sentinel PSK used in PQ strict mode to
	// fail closed: it is programmed until the real ML-KEM PSK is derived, so no session
	// can form on a non-PQ key. Per-conn random so two strict peers never match by chance.
	pqStrictSentinelKey *wgtypes.Key
}

// injectPendingFirstPacket replays the captured handshake through the proxy if present, else
// directly through the ICE conn. The packet is cleared only after a successful write, so a failed
// or transport-less attempt leaves it available for a later reinjection. Caller must hold conn.mu.
func (conn *Conn) injectPendingFirstPacket(proxy wgproxy.Proxy, directConn net.Conn) {
	pkt := conn.pendingFirstPacket
	if len(pkt) == 0 {
		return
	}

	switch {
	case proxy != nil:
		if err := proxy.InjectPacket(pkt); err != nil {
			conn.Log.Debugf("failed to reinject captured first packet via proxy: %v", err)
			return
		}
	case directConn != nil:
		if _, err := directConn.Write(pkt); err != nil {
			conn.Log.Debugf("failed to reinject captured first packet via direct conn: %v", err)
			return
		}
	default:
		conn.Log.Debugf("no transport available to reinject captured first packet")
		return
	}

	conn.pendingFirstPacket = nil
	conn.Log.Debugf("reinjected captured first packet (%d bytes)", len(pkt))
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
		metricsRecorder:    services.MetricsRecorder,
	}

	if config.PQ != nil && config.PQStrict {
		// The sentinel is what makes strict mode fail closed; if we cannot generate it we
		// must not fall back to a usable key, so fail creating the conn instead.
		k, err := wgtypes.GenerateKey()
		if err != nil {
			return nil, fmt.Errorf("generate pqkem strict-mode sentinel key: %w", err)
		}
		conn.pqStrictSentinelKey = &k
	}

	return conn, nil
}

// Open opens connection to the remote peer
// It will try to establish a connection using ICE and in parallel with relay. The higher priority connection type will
// be used.
func (conn *Conn) Open(engineCtx context.Context) error {
	return conn.open(engineCtx, nil)
}

// OpenWithFirstPacket opens the connection like Open and stashes firstPacket to be replayed once
// the real transport is established. The packet is retained only on a successful open.
func (conn *Conn) OpenWithFirstPacket(engineCtx context.Context, firstPacket []byte) error {
	return conn.open(engineCtx, firstPacket)
}

func (conn *Conn) open(engineCtx context.Context, firstPacket []byte) error {
	conn.mu.Lock()
	defer conn.mu.Unlock()

	if conn.opened {
		return nil
	}

	// Allocate new metrics stages so old goroutines don't corrupt new state
	conn.metricsStages = &MetricsStages{}

	conn.ctx, conn.ctxCancel = context.WithCancel(engineCtx)

	conn.workerRelay = NewWorkerRelay(conn.ctx, conn.Log, isController(conn.config), conn.config, conn, conn.relayManager)

	forceRelay := IsForceRelayed()
	if !forceRelay {
		relayIsSupportedLocally := conn.workerRelay.RelayIsSupportedLocally()
		workerICE, err := NewWorkerICE(conn.ctx, conn.Log, conn.config, conn, conn.signaler, conn.iFaceDiscover, conn.statusRecorder, relayIsSupportedLocally)
		if err != nil {
			return err
		}
		conn.workerICE = workerICE
	}

	conn.handshaker = NewHandshaker(conn.Log, conn.config, conn.signaler, conn.workerICE, conn.workerRelay, conn.metricsStages)

	conn.handshaker.AddRelayListener(conn.workerRelay.OnNewOffer)
	if !forceRelay {
		conn.handshaker.AddICEListener(conn.workerICE.OnNewOffer)
	}

	conn.guard = guard.NewGuard(conn.Log, conn.isConnectedOnAllWay, conn.config.Timeout, conn.srWatcher, conn.config.NetMgr)

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
	if len(firstPacket) > 0 {
		conn.pendingFirstPacket = slices.Clone(firstPacket)
	}
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
		conn.wgWatcher = nil
		conn.wgWatcherCancel = nil
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
			conn.Log.Errorf("failed to add relayed net.Conn to local proxy: %v", err)
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

	if conn.wgProxyRelay != nil {
		conn.wgProxyRelay.Pause()
	}

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
	}

	conn.injectPendingFirstPacket(wgProxy, iceConnInfo.RemoteConn)

	conn.currentConnPriority = priority
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
		if err := conn.config.WgConfig.WgInterface.RemoveEndpointAddress(conn.config.WgConfig.RemoteKey); err != nil {
			conn.Log.Errorf("failed to remove wg endpoint: %v", err)
		}
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

	conn.injectPendingFirstPacket(wgProxy, nil)

	conn.rosenpassRemoteKey = rci.rosenpassPubKey
	conn.currentConnPriority = conntype.Relay
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
	conn.dumpState.SendOffer()
	if err := conn.handshaker.SendOffer(); err != nil {
		conn.Log.Errorf("failed to send offer: %v", err)
	}
}

// RequestReoffer sends a fresh signalling offer for the peer, re-running the
// post-quantum bootstrap over Signal. Used to recover from a persistent data-path
// rekey failure: a new exchange overwrites the stalled PSK on both sides. No-op if the
// connection is not open yet.
func (conn *Conn) RequestReoffer() {
	conn.mu.Lock()
	h := conn.handshaker
	conn.mu.Unlock()
	if h == nil {
		return
	}
	if err := h.SendOffer(); err != nil {
		conn.Log.Debugf("pqkem: recovery re-offer failed: %v", err)
	}
}

func (conn *Conn) onWGDisconnected(watcherCtx context.Context) {
	conn.mu.Lock()
	defer conn.mu.Unlock()

	// watcherCtx guards against a stale watcher tearing down a connection that already superseded it.
	if conn.ctx.Err() != nil || watcherCtx.Err() != nil {
		return
	}

	conn.Log.Warnf("WireGuard handshake timeout detected, closing current connection")

	if conn.config.PQ != nil {
		conn.config.PQ.OnDataPathDown(conn.config.Key)
	}

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

	conn.escalateWGTimeoutLocked()
}

// escalateWGTimeoutLocked resets the peer's rosenpass state after repeated
// handshake timeouts. With rosenpass enabled, persistent timeouts mean the
// preshared keys have desynced; the renewal exchange runs over the dead
// tunnel and cannot resync them. Reporting the peer disconnected drops its
// rosenpass state, so the next connection configuration programs the
// rendezvous key and the tunnel can bootstrap again. Callers must hold mu.
func (conn *Conn) escalateWGTimeoutLocked() {
	if conn.config.RosenpassConfig.PubKey == nil {
		return
	}

	conn.wgTimeouts++
	if conn.wgTimeouts < wgTimeoutEscalationThreshold || conn.onDisconnected == nil {
		return
	}
	conn.wgTimeouts = 0

	conn.Log.Warnf("%d consecutive WireGuard handshake timeouts, resetting rosenpass state for peer", wgTimeoutEscalationThreshold)
	conn.onDisconnected(conn.config.WgConfig.RemoteKey)
}

func (conn *Conn) updateRelayStatus(relayServerAddr string, rosenpassPubKey []byte, updateTime time.Time) {
	peerState := State{
		PubKey:             conn.config.Key,
		ConnStatusUpdate:   updateTime,
		ConnStatus:         conn.evalStatus(),
		Relayed:            conn.isRelayed(),
		RelayServerAddress: relayServerAddr,
		RosenpassEnabled:   conn.quantumResistant(rosenpassPubKey),
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
		RosenpassEnabled:           conn.quantumResistant(iceConnInfo.RosenpassPubKey),
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
		forceRelay:          IsForceRelayed(),
		peerUsesRelay:       conn.workerRelay.IsRelayConnectionSupportedWithPeer(),
		relayConnected:      conn.statusRelay.Get() == worker.StatusConnected,
		remoteSupportsICE:   conn.handshaker.RemoteICESupported(),
		iceWorkerCreated:    iceWorkerCreated,
		iceStatusConnecting: conn.statusICE.Get() != worker.StatusDisconnected,
		iceInProgress:       iceInProgress,
	})
}

// enableWgWatcherIfNeeded starts a fresh watcher instance per connection attempt, so its
// lifecycle stays bound to conn.mu and enable/disable can't race an old goroutine's shutdown.
// Caller must hold conn.mu.
func (conn *Conn) enableWgWatcherIfNeeded(enabledTime time.Time) {
	if conn.wgWatcher != nil {
		return
	}

	watcher := NewWGWatcher(conn.Log, conn.config.WgConfig.WgInterface, conn.config.Key, conn.dumpState)
	watcher.PrepareInitialHandshake()

	wgWatcherCtx, wgWatcherCancel := context.WithCancel(conn.ctx)
	conn.wgWatcher = watcher
	conn.wgWatcherCancel = wgWatcherCancel

	conn.wgWatcherWg.Add(1)
	go func() {
		defer conn.wgWatcherWg.Done()
		onDisconnected := func() { conn.onWGDisconnected(wgWatcherCtx) }
		watcher.EnableWgWatcher(wgWatcherCtx, enabledTime, onDisconnected, conn.onWGHandshakeSuccess, conn.onWGCheckSuccess)
	}()
}

// disableWgWatcherIfNeeded cancels and drops the watcher once no transport is active. It never
// waits for the goroutine: the timeout path reentrantly calls back here under conn.mu, so
// blocking would deadlock. Caller must hold conn.mu.
func (conn *Conn) disableWgWatcherIfNeeded() {
	if conn.currentConnPriority != conntype.None || conn.wgWatcher == nil {
		return
	}
	conn.wgWatcherCancel()
	conn.wgWatcher = nil
	conn.wgWatcherCancel = nil
}

func (conn *Conn) newProxy(remoteConn net.Conn) (wgproxy.Proxy, error) {
	conn.Log.Debugf("setup proxied WireGuard connection")
	udpAddr := &net.UDPAddr{
		IP:   conn.config.WgConfig.AllowedIps[0].Addr().AsSlice(),
		Port: conn.config.WgConfig.WgListenPort,
	}

	wgProxy := conn.config.WgConfig.WgInterface.GetProxy()
	if err := wgProxy.AddRelayedConn(conn.ctx, udpAddr, remoteConn); err != nil {
		return nil, fmt.Errorf("add relayed conn to proxy: %w", err)
	}
	return wgProxy, nil
}

func (conn *Conn) resetEndpoint() {
	if !isController(conn.config) {
		return
	}
	conn.Log.Infof("reset wg endpoint")
	if conn.wgWatcher != nil {
		conn.wgWatcher.Reset()
	}
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

// onWGCheckSuccess is called for every watcher check that observed a fresh
// handshake, including handshakes of connections that were already up when
// the watcher started.
func (conn *Conn) onWGCheckSuccess() {
	conn.mu.Lock()
	conn.wgTimeouts = 0
	conn.mu.Unlock()

	// A fresh WireGuard handshake clocks the post-quantum PSK rotation. Pass how long
	// ago the peer last exchanged real user data (keepalives excluded) so the pqkem
	// manager can skip rotation on idle tunnels — rotating then would push data-path
	// traffic that keeps the lazy connection artificially active.
	if conn.config.PQ != nil {
		conn.config.PQ.OnDataPathRekeyed(conn.config.Key, conn.dataActivityAge())
	}
}

// dataActivityAge returns how long ago the peer last exchanged real user data
// (WireGuard keepalives excluded), per the same LastActivities signal the
// lazy-connection inactivity monitor uses. It reports a very large duration when no
// activity has ever been recorded, so the peer is treated as idle.
//
// In kernel mode there is no per-peer data-activity signal (LastActivities is
// userspace-only), so we cannot tell active from idle. We report zero — always
// "active" — so PSK rotation is not disabled in kernel mode. Lazy back-to-idle is
// already limited there; the eBPF WG-activity detection (future) will supply a real
// signal that excludes handshake/pqkem traffic.
func (conn *Conn) dataActivityAge() time.Duration {
	if !conn.config.WgConfig.WgInterface.IsUserspaceBind() {
		return 0
	}
	last, ok := conn.config.WgConfig.WgInterface.LastActivities()[conn.config.WgConfig.RemoteKey]
	if !ok {
		return time.Duration(math.MaxInt64)
	}
	return monotime.Since(last)
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

	connType := metricsConnType(priority)
	if connType == metrics.ConnectionTypeUnknown {
		return
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
	// Post-quantum: once the ML-KEM exchange has derived a PSK for this peer, program
	// it here so the peer's next WireGuard handshake adopts it. Applied at peer-config
	// time (bootstrap / reconnect); steady-state rotation is pushed separately.
	if conn.config.PQ != nil {
		if psk, ok := conn.config.PQ.PSK(conn.config.Key); ok {
			return &psk
		}
		if conn.config.PQStrict && conn.pqStrictSentinelKey != nil {
			// Fail closed: program a non-matching sentinel so no session forms on a
			// non-PQ key until the ML-KEM exchange derives the real PSK (pushed via
			// SetPresharedKey once it converges). "pending" — turns into a "stuck"
			// warning from the manager if the exchange keeps failing (see raiseFailure).
			conn.Log.Debugf("pqkem: strict mode — no PQ PSK yet, blocking peer traffic until the ML-KEM exchange converges")
			return conn.pqStrictSentinelKey
		}
	}

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
	determKey, err := rosenpass.DeterministicSeedKey(conn.config.LocalKey, conn.config.Key)
	if err != nil {
		conn.Log.Errorf("failed to generate Rosenpass initial key: %v", err)
		return nil
	}

	return determKey
}

func isController(config ConnConfig) bool {
	return config.LocalKey > config.Key
}

func isRosenpassEnabled(remoteRosenpassPubKey []byte) bool {
	return remoteRosenpassPubKey != nil
}

// quantumResistant reports whether the peer's tunnel is post-quantum protected, for
// the status "Quantum resistance" field: either Rosenpass (the remote advertised a
// Rosenpass key) or the ML-KEM exchange (a PQ PSK has been derived for this peer).
func (conn *Conn) quantumResistant(remoteRosenpassPubKey []byte) bool {
	if isRosenpassEnabled(remoteRosenpassPubKey) {
		return true
	}
	if conn.config.PQ != nil {
		if _, ok := conn.config.PQ.PSK(conn.config.Key); ok {
			return true
		}
	}
	return false
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

func metricsConnType(priority conntype.ConnPriority) metrics.ConnectionType {
	switch priority {
	case conntype.Relay:
		return metrics.ConnectionTypeRelay
	case conntype.ICETurn:
		return metrics.ConnectionTypeICETurn
	case conntype.ICEP2P:
		return metrics.ConnectionTypeICEP2P
	default:
		return metrics.ConnectionTypeUnknown
	}
}
