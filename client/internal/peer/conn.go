package peer

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"runtime"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pion/ice/v4"
	log "github.com/sirupsen/logrus"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/netbirdio/netbird/client/iface/configurer"
	"github.com/netbirdio/netbird/client/iface/wgproxy"
	"github.com/netbirdio/netbird/client/internal/metrics"
	"github.com/netbirdio/netbird/client/internal/peer/guard"
	icemaker "github.com/netbirdio/netbird/client/internal/peer/ice"
	"github.com/netbirdio/netbird/client/internal/peer/id"
	"github.com/netbirdio/netbird/client/internal/peer/signaling"
	"github.com/netbirdio/netbird/client/internal/peer/state_dump"
	"github.com/netbirdio/netbird/client/internal/peer/status"
	"github.com/netbirdio/netbird/client/internal/peer/wg_watcher"
	"github.com/netbirdio/netbird/client/internal/peer/worker"
	"github.com/netbirdio/netbird/client/internal/portforward"
	"github.com/netbirdio/netbird/client/internal/rosenpass"
	"github.com/netbirdio/netbird/client/internal/stdnet"
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
	StatusRecorder     *status.Recorder
	Signaler           *signaling.Signaler
	IFaceDiscover      stdnet.ExternalIFaceDiscover
	RelayManager       *relayClient.Manager
	SrWatcher          *guard.SRWatcher
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
}

// Conn represents a connection to a remote peer. All mutable connection state
// is owned by a single event loop goroutine started in Open; external callers
// and the transport workers communicate with the loop by posting events into
// a non-blocking mailbox.
type Conn struct {
	Log *log.Entry
	// mu guards the open/close lifecycle (opened, loopDone). Everything else
	// is either immutable after construction or owned by the event loop.
	mu                 sync.Mutex
	ctx                context.Context
	ctxCancel          context.CancelFunc
	config             ConnConfig
	statusRecorder     *status.Recorder
	signaler           *signaling.Signaler
	iFaceDiscover      stdnet.ExternalIFaceDiscover
	relayManager       *relayClient.Manager
	srWatcher          *guard.SRWatcher
	portForwardManager *portforward.Manager

	onConnected                               func(remoteWireGuardKey string, remoteRosenpassPubKey []byte, wireGuardIP string, remoteRosenpassAddr string)
	onDisconnected                            func(remotePeer string)
	rosenpassInitializedPresharedKeyValidator func(peerKey string) bool

	statusRelay         *worker.AtomicWorkerStatus
	statusICE           *worker.AtomicWorkerStatus
	currentConnPriority ConnPriority
	opened              bool // this flag is used to prevent close in case of not opened connection

	// mailbox delivers events to the event loop of the current open
	// generation; a nil pointer or a closed mailbox rejects the post.
	mailbox  atomic.Pointer[mailbox]
	loopDone chan struct{}

	workerICE   *WorkerICE
	workerRelay *WorkerRelay

	// relayDialInFlight and pendingRelayOffer serialize the blocking relay
	// dials spawned by the event loop, keeping only the newest offer while a
	// dial is running.
	relayDialInFlight bool
	pendingRelayOffer *signaling.OfferAnswer

	wgWatcher       *wg_watcher.WGWatcher
	wgWatcherWg     sync.WaitGroup
	wgWatcherCancel context.CancelFunc
	// wgTimeouts counts consecutive WireGuard handshake timeouts without a
	// successful handshake in between. Owned by the event loop.
	wgTimeouts int

	// used to store the remote Rosenpass key for Relayed connection in case of connection update from ice
	rosenpassRemoteKey []byte

	wgProxyICE   wgproxy.Proxy
	wgProxyRelay wgproxy.Proxy
	handshaker   *signaling.Handshaker

	guard *guard.Guard
	wg    sync.WaitGroup

	// debug purpose
	dumpState *state_dump.StateDump

	endpointUpdater *EndpointUpdater

	// Connection stage timestamps for metrics
	metricsRecorder MetricsRecorder
	metricsStages   *MetricsStages

	// pendingFirstPacket is the lazyconn-captured handshake init, replayed once the real
	// transport is up.
	pendingFirstPacket []byte
}

// NewConn creates a new not opened Conn to the remote peer.
// To establish a connection run Conn.Open
func NewConn(config ConnConfig, services ServiceDependencies) (*Conn, error) {
	if len(config.WgConfig.AllowedIps) == 0 {
		return nil, fmt.Errorf("allowed IPs is empty")
	}

	connLog := log.WithField("peer", config.Key)

	dumpState := state_dump.NewStateDump(config.Key, connLog, services.StatusRecorder)
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
		wgWatcher:          wg_watcher.NewWGWatcher(connLog, config.WgConfig.WgInterface, config.Key, dumpState),
		metricsRecorder:    services.MetricsRecorder,
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

	if !IsForceRelayed() {
		relayIsSupportedLocally := conn.workerRelay.RelayIsSupportedLocally()
		workerICE, err := NewWorkerICE(conn.ctx, conn.Log, conn.config, conn, conn.signaler, conn.iFaceDiscover, conn.statusRecorder, conn.portForwardManager, relayIsSupportedLocally)
		if err != nil {
			return err
		}
		conn.workerICE = workerICE
	}

	var iceWorker signaling.ICEWorker
	if conn.workerICE != nil {
		iceWorker = conn.workerICE
	}
	conn.handshaker = signaling.NewHandshaker(conn.Log, signaling.Config{
		Key:             conn.config.Key,
		LocalWgPort:     conn.config.LocalWgPort,
		RosenpassPubKey: conn.config.RosenpassConfig.PubKey,
		RosenpassAddr:   conn.config.RosenpassConfig.Addr,
	}, conn.signaler, iceWorker, conn.relayManager)

	conn.guard = guard.NewGuard(conn.Log, conn.isConnectedOnAllWay, conn.config.Timeout, conn.srWatcher)

	conn.relayDialInFlight = false
	conn.pendingRelayOffer = nil
	if len(firstPacket) > 0 {
		conn.pendingFirstPacket = slices.Clone(firstPacket)
	}

	peerState := status.State{
		PubKey:           conn.config.Key,
		ConnStatusUpdate: time.Now(),
		ConnStatus:       status.StatusConnecting,
		Mux:              new(sync.RWMutex),
	}
	if err := conn.statusRecorder.UpdatePeerState(peerState); err != nil {
		conn.Log.Warnf("error while updating the state err: %v", err)
	}

	mb := newMailbox()
	conn.loopDone = make(chan struct{})
	conn.mailbox.Store(mb)

	go conn.run(mb)
	go conn.dumpState.Start(conn.ctx)

	conn.wg.Add(1)
	go func() {
		defer conn.wg.Done()
		conn.guard.Start(conn.ctx, conn.onGuardEvent)
	}()

	conn.opened = true
	return nil
}

// Close closes this peer Conn. It posts a close event to the event loop and
// blocks until the loop finished the teardown.
func (conn *Conn) Close(signalToRemote bool) {
	conn.mu.Lock()
	defer conn.mu.Unlock()

	if !conn.opened {
		conn.Log.Debugf("ignore close connection to peer")
		return
	}

	done := make(chan struct{})
	if conn.post(evClose{signalToRemote: signalToRemote, done: done}) {
		<-done
	} else {
		<-conn.loopDone
	}
	conn.opened = false
}

// OnRemoteOffer handles an offer from the remote peer. It never blocks; the
// offer is coalesced in the mailbox and processed by the event loop, older
// unprocessed offers are replaced by the newest one.
func (conn *Conn) OnRemoteOffer(offer signaling.OfferAnswer) {
	conn.dumpState.RemoteOffer()
	conn.Log.Infof("OnRemoteOffer, on status ICE: %s, status Relay: %s", conn.statusICE, conn.statusRelay)
	if !conn.post(evRemoteOffer{offer: offer}) {
		conn.Log.Debugf("connection is not open, discarding remote offer")
	}
}

// OnRemoteAnswer handles an answer from the remote peer. It never blocks; the
// answer is coalesced in the mailbox and processed by the event loop.
func (conn *Conn) OnRemoteAnswer(answer signaling.OfferAnswer) {
	conn.dumpState.RemoteAnswer()
	conn.Log.Infof("OnRemoteAnswer, on status ICE: %s, status Relay: %s", conn.statusICE, conn.statusRelay)
	if !conn.post(evRemoteAnswer{answer: answer}) {
		conn.Log.Debugf("connection is not open, discarding remote answer")
	}
}

// OnRemoteCandidate handles an ICE connection candidate provided by the
// remote peer. Candidates are queued in arrival order and applied by the
// event loop.
func (conn *Conn) OnRemoteCandidate(candidate ice.Candidate, haRoutes route.HAMap) {
	conn.dumpState.RemoteCandidate()
	if !conn.post(evRemoteCandidate{candidate: candidate, haRoutes: haRoutes}) {
		conn.Log.Debugf("connection is not open, discarding remote candidate")
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

// WgConfig returns the WireGuard config
func (conn *Conn) WgConfig() WgConfig {
	return conn.config.WgConfig
}

// IsConnected returns true if the peer is connected
func (conn *Conn) IsConnected() bool {
	return conn.evalStatus() == status.StatusConnected
}

func (conn *Conn) GetKey() string {
	return conn.config.Key
}

func (conn *Conn) ConnID() id.ConnID {
	return id.ConnID(conn)
}

// AllowedIP returns the allowed IP of the remote peer
func (conn *Conn) AllowedIP() netip.Addr {
	return conn.config.WgConfig.AllowedIps[0].Addr()
}

func (conn *Conn) AgentVersionString() string {
	return conn.config.AgentVersion
}

// post delivers an event to the event loop of the current open generation.
// It reports false if the connection is not open.
func (conn *Conn) post(ev event) bool {
	mb := conn.mailbox.Load()
	if mb == nil {
		return false
	}
	return mb.post(ev)
}

// run is the Conn event loop. From the moment open returns until the teardown
// it exclusively owns all mutable Conn state. It exits on an evClose event or
// when the engine context is cancelled.
func (conn *Conn) run(mb *mailbox) {
	defer close(conn.loopDone)

	for {
		select {
		case <-mb.wake:
			evs := mb.drain()
			for i, ev := range evs {
				if c, ok := ev.(evClose); ok {
					conn.teardown(mb, evs[i+1:], c.signalToRemote, c.done)
					return
				}
				conn.handleEvent(ev)
			}
		case <-conn.ctx.Done():
			conn.teardown(mb, nil, false, nil)
			return
		}
	}
}

func (conn *Conn) handleEvent(ev event) {
	switch e := ev.(type) {
	case evRemoteOffer:
		conn.handleRemoteOffer(&e.offer)
	case evRemoteAnswer:
		conn.handleRemoteAnswer(&e.answer)
	case evRemoteCandidate:
		conn.handleRemoteCandidate(e)
	case evICEReady:
		conn.handleICEReady(e.priority, e.info)
	case evICEDown:
		conn.handleICEDisconnected(e.sessionChanged)
	case evRelayReady:
		conn.handleRelayReady(e.info)
	case evRelayDown:
		conn.handleRelayDisconnected()
	case evRelayDialDone:
		conn.handleRelayDialDone()
	case evWGTimeout:
		conn.handleWGTimeout()
	case evWGHandshake:
		conn.handleWGHandshakeSuccess(e.when)
	case evWGCheckOK:
		conn.handleWGCheckSuccess()
	case evGuardTick:
		conn.handleGuardTick()
	default:
		conn.Log.Errorf("unhandled conn event type %T", ev)
	}
}

// teardown closes the transports and releases every resource of the current
// open generation. It runs exclusively on the event loop, either for an
// evClose event or after engine context cancellation. Leftover events drained
// together with the close are cleaned up alongside the ones still sitting in
// the mailbox.
func (conn *Conn) teardown(mb *mailbox, leftover []event, signalToRemote bool, done chan struct{}) {
	if signalToRemote {
		if err := conn.signaler.SignalIdle(conn.config.Key); err != nil {
			conn.Log.Errorf("failed to signal idle state to peer: %v", err)
		}
	}

	conn.Log.Infof("close peer connection")
	conn.ctxCancel()

	if conn.wgWatcherCancel != nil {
		conn.wgWatcherCancel()
		conn.wgWatcherCancel = nil
	}
	conn.workerRelay.CloseConn()
	if conn.workerICE != nil {
		conn.workerICE.Close()
	}

	if conn.wgProxyRelay != nil {
		if err := conn.wgProxyRelay.CloseConn(); err != nil {
			conn.Log.Errorf("failed to close wg proxy for relay: %v", err)
		}
		conn.wgProxyRelay = nil
	}

	if conn.wgProxyICE != nil {
		if err := conn.wgProxyICE.CloseConn(); err != nil {
			conn.Log.Errorf("failed to close wg proxy for ice: %v", err)
		}
		conn.wgProxyICE = nil
	}

	if err := conn.endpointUpdater.RemoveWgPeer(); err != nil {
		conn.Log.Errorf("failed to remove wg endpoint: %v", err)
	}

	if conn.evalStatus() == status.StatusConnected && conn.onDisconnected != nil {
		conn.onDisconnected(conn.config.WgConfig.RemoteKey)
	}

	conn.setStatusToDisconnected()
	conn.wgWatcherWg.Wait()
	conn.wg.Wait()

	conn.releaseEvents(leftover)
	conn.releaseEvents(mb.closeAndDrain())
	if done != nil {
		close(done)
	}
	conn.Log.Infof("peer connection closed")
}

// releaseEvents cleans up events that will never be processed because the
// event loop is shutting down.
func (conn *Conn) releaseEvents(evs []event) {
	for _, ev := range evs {
		switch e := ev.(type) {
		case evRelayReady:
			if err := e.info.relayedConn.Close(); err != nil {
				conn.Log.Warnf("failed to close unnecessary relayed connection: %v", err)
			}
		case evClose:
			if e.done != nil {
				close(e.done)
			}
		}
	}
}

// handleRemoteOffer applies a remote offer on the event loop: refreshes the
// remote ICE support state, dispatches the offer to the relay and ICE workers
// and answers it.
func (conn *Conn) handleRemoteOffer(offer *signaling.OfferAnswer) {
	conn.Log.Infof("received offer, running version %s, remote WireGuard listen port %d, session id: %s, remote ICE supported: %t", offer.Version, offer.WgListenPort, offer.SessionIDString(), offer.HasICECredentials())

	conn.metricsStages.RecordSignalingReceived()
	conn.handshaker.UpdateRemoteICEState(offer)
	conn.dispatchOfferToRelay(offer)
	conn.dispatchOfferToICE(offer)

	go func() {
		if err := conn.handshaker.SendAnswer(); err != nil {
			conn.Log.Errorf("failed to send remote offer confirmation: %s", err)
		}
	}()
}

// handleRemoteAnswer applies a remote answer on the event loop the same way
// as an offer, without answering it.
func (conn *Conn) handleRemoteAnswer(answer *signaling.OfferAnswer) {
	conn.Log.Infof("received answer, running version %s, remote WireGuard listen port %d, session id: %s, remote ICE supported: %t", answer.Version, answer.WgListenPort, answer.SessionIDString(), answer.HasICECredentials())

	conn.metricsStages.RecordSignalingReceived()
	conn.handshaker.UpdateRemoteICEState(answer)
	conn.dispatchOfferToRelay(answer)
	conn.dispatchOfferToICE(answer)
}

func (conn *Conn) handleRemoteCandidate(e evRemoteCandidate) {
	if conn.workerICE == nil {
		return
	}
	conn.workerICE.OnRemoteCandidate(e.candidate, e.haRoutes)
}

func (conn *Conn) dispatchOfferToICE(offer *signaling.OfferAnswer) {
	if conn.workerICE == nil || !conn.handshaker.RemoteICESupported() {
		return
	}
	conn.workerICE.OnNewOffer(offer)
}

// dispatchOfferToRelay runs the blocking relay dial on a helper goroutine. A
// single dial is kept in flight; newer offers replace the pending one and the
// newest is dispatched once the running dial reports completion.
func (conn *Conn) dispatchOfferToRelay(offer *signaling.OfferAnswer) {
	if conn.relayDialInFlight {
		conn.pendingRelayOffer = offer
		return
	}
	conn.relayDialInFlight = true

	go func() {
		conn.workerRelay.OnNewOffer(offer)
		conn.post(evRelayDialDone{})
	}()
}

func (conn *Conn) handleRelayDialDone() {
	conn.relayDialInFlight = false
	if offer := conn.pendingRelayOffer; offer != nil {
		conn.pendingRelayOffer = nil
		conn.dispatchOfferToRelay(offer)
	}
}

// handleGuardTick sends a new offer to restore connectivity; the signaling
// I/O runs off the loop.
func (conn *Conn) handleGuardTick() {
	conn.dumpState.SendOffer()
	go func() {
		if err := conn.handshaker.SendOffer(); err != nil {
			conn.Log.Errorf("failed to send offer: %v", err)
		}
	}()
}

// handleICEReady starts proxying traffic from/to local WireGuard and sets the
// connection status to StatusConnected.
func (conn *Conn) handleICEReady(priority ConnPriority, iceConnInfo ICEConnInfo) {
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

// handleICEDisconnected switches back to the relay connection if available,
// otherwise cleans up the WireGuard endpoint.
func (conn *Conn) handleICEDisconnected(sessionChanged bool) {
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

		conn.currentConnPriority = Relay
	} else {
		conn.Log.Infof("ICE disconnected, do not switch to Relay. Reset priority to: %s", None.String())
		conn.currentConnPriority = None
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

	if conn.currentConnPriority == None {
		conn.metricsStages.Disconnected()
	}

	peerState := status.State{
		PubKey:           conn.config.Key,
		ConnStatus:       conn.evalStatus(),
		Relayed:          conn.isRelayed(),
		ConnStatusUpdate: time.Now(),
	}
	if err := conn.statusRecorder.UpdatePeerICEStateToDisconnected(peerState); err != nil {
		conn.Log.Warnf("unable to set peer's state to disconnected ice, got error: %v", err)
	}
}

// handleRelayReady sets up the WireGuard proxy for a freshly opened relayed
// connection and activates it unless ICE has priority.
func (conn *Conn) handleRelayReady(rci RelayConnInfo) {
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
	conn.currentConnPriority = Relay
	conn.statusRelay.SetConnected()
	conn.setRelayedProxy(wgProxy)
	conn.updateRelayStatus(rci.relayedConn.RemoteAddr().String(), rci.rosenpassPubKey, updateTime)
	conn.Log.Infof("start to communicate with peer via relay")
	conn.doOnConnected(rci.rosenpassPubKey, rci.rosenpassAddr, updateTime)
}

// handleRelayDisconnected cleans up the relayed transport and the WireGuard
// endpoint if the relay was the active connection.
func (conn *Conn) handleRelayDisconnected() {
	if conn.ctx.Err() != nil {
		return
	}

	conn.Log.Debugf("relay connection is disconnected")

	if conn.currentConnPriority == Relay {
		conn.Log.Debugf("clean up WireGuard config")
		conn.currentConnPriority = None
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

	if conn.currentConnPriority == None {
		conn.metricsStages.Disconnected()
	}

	peerState := status.State{
		PubKey:           conn.config.Key,
		ConnStatus:       conn.evalStatus(),
		Relayed:          conn.isRelayed(),
		ConnStatusUpdate: time.Now(),
	}
	if err := conn.statusRecorder.UpdatePeerRelayedStateToDisconnected(peerState); err != nil {
		conn.Log.Warnf("unable to save peer's state to Relay disconnected, got error: %v", err)
	}
}

// handleWGTimeout closes the active connection after a WireGuard handshake
// timeout so the guard can trigger a reconnection.
func (conn *Conn) handleWGTimeout() {
	if conn.ctx.Err() != nil {
		return
	}

	conn.Log.Warnf("WireGuard handshake timeout detected, closing current connection")

	// Close the active connection based on current priority
	switch conn.currentConnPriority {
	case Relay:
		conn.workerRelay.CloseConn()
		conn.handleRelayDisconnected()
	case ICEP2P, ICETurn:
		conn.workerICE.Close()
	default:
		conn.Log.Debugf("No active connection to close on WG timeout")
	}

	conn.escalateWGTimeout()
}

// escalateWGTimeout resets the peer's rosenpass state after repeated
// handshake timeouts. With rosenpass enabled, persistent timeouts mean the
// preshared keys have desynced; the renewal exchange runs over the dead
// tunnel and cannot resync them. Reporting the peer disconnected drops its
// rosenpass state, so the next connection configuration programs the
// rendezvous key and the tunnel can bootstrap again. Runs on the event loop.
func (conn *Conn) escalateWGTimeout() {
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

func (conn *Conn) handleWGHandshakeSuccess(when time.Time) {
	conn.metricsStages.RecordWGHandshakeSuccess(when)
	conn.recordConnectionMetrics()
}

func (conn *Conn) handleWGCheckSuccess() {
	conn.wgTimeouts = 0
}

func (conn *Conn) onICEConnectionIsReady(priority ConnPriority, iceConnInfo ICEConnInfo) {
	conn.post(evICEReady{priority: priority, info: iceConnInfo})
}

func (conn *Conn) onICEStateDisconnected(sessionChanged bool) {
	conn.post(evICEDown{sessionChanged: sessionChanged})
}

// onRelayConnectionIsReady closes the relayed connection when the event loop
// is gone and nobody will take ownership of it.
func (conn *Conn) onRelayConnectionIsReady(rci RelayConnInfo) {
	if conn.post(evRelayReady{info: rci}) {
		return
	}
	if err := rci.relayedConn.Close(); err != nil {
		conn.Log.Warnf("failed to close unnecessary relayed connection: %v", err)
	}
}

func (conn *Conn) onRelayDisconnected() {
	conn.post(evRelayDown{})
}

func (conn *Conn) onGuardEvent() {
	conn.post(evGuardTick{})
}

func (conn *Conn) onWGDisconnected() {
	conn.post(evWGTimeout{})
}

func (conn *Conn) onWGHandshakeSuccess(when time.Time) {
	conn.post(evWGHandshake{when: when})
}

func (conn *Conn) onWGCheckSuccess() {
	conn.post(evWGCheckOK{})
}

// injectPendingFirstPacket replays the captured handshake through the proxy if present, else
// directly through the ICE conn. The packet is cleared only after a successful write, so a failed
// or transport-less attempt leaves it available for a later reinjection. Runs on the event loop.
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

func (conn *Conn) updateRelayStatus(relayServerAddr string, rosenpassPubKey []byte, updateTime time.Time) {
	peerState := status.State{
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
	peerState := status.State{
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
	conn.currentConnPriority = None

	peerState := status.State{
		PubKey:           conn.config.Key,
		ConnStatus:       status.StatusIdle,
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
	case Relay, ICETurn:
		return true
	default:
		return false
	}
}

func (conn *Conn) evalStatus() status.ConnStatus {
	if conn.statusRelay.Get() == worker.StatusConnected || conn.statusICE.Get() == worker.StatusConnected {
		return status.StatusConnected
	}

	return status.StatusConnecting
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

func (conn *Conn) enableWgWatcherIfNeeded(enabledTime time.Time) {
	if !conn.wgWatcher.PrepareInitialHandshake() {
		return
	}

	wgWatcherCtx, wgWatcherCancel := context.WithCancel(conn.ctx)
	conn.wgWatcherCancel = wgWatcherCancel
	conn.wgWatcherWg.Add(1)
	go func() {
		defer conn.wgWatcherWg.Done()
		conn.wgWatcher.EnableWgWatcher(wgWatcherCtx, enabledTime, conn.onWGDisconnected, conn.onWGHandshakeSuccess, conn.onWGCheckSuccess)
	}()
}

func (conn *Conn) disableWgWatcherIfNeeded() {
	if conn.currentConnPriority == None && conn.wgWatcherCancel != nil {
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
	return conn.wgProxyRelay != nil && conn.currentConnPriority != Relay
}

func (conn *Conn) isICEActive() bool {
	return (conn.currentConnPriority == ICEP2P || conn.currentConnPriority == ICETurn) && conn.statusICE.Get() == worker.StatusConnected
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

// recordConnectionMetrics records connection stage timestamps as metrics
func (conn *Conn) recordConnectionMetrics() {
	if conn.metricsRecorder == nil {
		return
	}

	var connType metrics.ConnectionType
	switch conn.currentConnPriority {
	case Relay:
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
