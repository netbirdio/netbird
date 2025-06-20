package peer

import (
	"context"
	"fmt"
	"math/rand"
	"net"
	"net/netip"
	"os"
	"runtime"
	"sync"
	"time"

	"github.com/pion/ice/v3"
	log "github.com/sirupsen/logrus"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/netbirdio/netbird/client/iface/configurer"
	"github.com/netbirdio/netbird/client/iface/wgproxy"
	"github.com/netbirdio/netbird/client/internal/peer/conntype"
	"github.com/netbirdio/netbird/client/internal/peer/dispatcher"
	"github.com/netbirdio/netbird/client/internal/peer/guard"
	icemaker "github.com/netbirdio/netbird/client/internal/peer/ice"
	"github.com/netbirdio/netbird/client/internal/peer/id"
	"github.com/netbirdio/netbird/client/internal/peer/worker"
	"github.com/netbirdio/netbird/client/internal/stdnet"
	relayClient "github.com/netbirdio/netbird/relay/client"
	"github.com/netbirdio/netbird/route"
	nbnet "github.com/netbirdio/netbird/util/net"
	semaphoregroup "github.com/netbirdio/netbird/util/semaphore-group"
)

const (
	defaultWgKeepAlive = 25 * time.Second
)

type ServiceDependencies struct {
	StatusRecorder     *Status
	Signaler           *Signaler
	IFaceDiscover      stdnet.ExternalIFaceDiscover
	RelayManager       *relayClient.Manager
	SrWatcher          *guard.SRWatcher
	Semaphore          *semaphoregroup.SemaphoreGroup
	PeerConnDispatcher *dispatcher.ConnectionDispatcher
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

type Conn struct {
	Log            *log.Entry
	mu             sync.Mutex
	ctx            context.Context
	ctxCancel      context.CancelFunc
	config         ConnConfig
	statusRecorder *Status
	signaler       *Signaler
	iFaceDiscover  stdnet.ExternalIFaceDiscover
	relayManager   *relayClient.Manager
	srWatcher      *guard.SRWatcher

	onConnected    func(remoteWireGuardKey string, remoteRosenpassPubKey []byte, wireGuardIP string, remoteRosenpassAddr string)
	onDisconnected func(remotePeer string)

	statusRelay         *worker.AtomicWorkerStatus
	statusICE           *worker.AtomicWorkerStatus
	currentConnPriority conntype.ConnPriority
	opened              bool // this flag is used to prevent close in case of not opened connection

	workerICE   *WorkerICE
	workerRelay *WorkerRelay
	wgWatcherWg sync.WaitGroup

	connIDRelay          nbnet.ConnectionID
	connIDICE            nbnet.ConnectionID
	beforeAddPeerHooks   []nbnet.AddHookFunc
	afterRemovePeerHooks []nbnet.RemoveHookFunc
	// used to store the remote Rosenpass key for Relayed connection in case of connection update from ice
	rosenpassRemoteKey []byte

	wgProxyICE   wgproxy.Proxy
	wgProxyRelay wgproxy.Proxy
	handshaker   *Handshaker

	guard              *guard.Guard
	semaphore          *semaphoregroup.SemaphoreGroup
	peerConnDispatcher *dispatcher.ConnectionDispatcher
	wg                 sync.WaitGroup

	// debug purpose
	dumpState *stateDump
}

// NewConn creates a new not opened Conn to the remote peer.
// To establish a connection run Conn.Open
func NewConn(config ConnConfig, services ServiceDependencies) (*Conn, error) {
	if len(config.WgConfig.AllowedIps) == 0 {
		return nil, fmt.Errorf("allowed IPs is empty")
	}

	connLog := log.WithField("peer", config.Key)

	var conn = &Conn{
		Log:                connLog,
		config:             config,
		statusRecorder:     services.StatusRecorder,
		signaler:           services.Signaler,
		iFaceDiscover:      services.IFaceDiscover,
		relayManager:       services.RelayManager,
		srWatcher:          services.SrWatcher,
		semaphore:          services.Semaphore,
		peerConnDispatcher: services.PeerConnDispatcher,
		statusRelay:        worker.NewAtomicStatus(),
		statusICE:          worker.NewAtomicStatus(),
		dumpState:          newStateDump(config.Key, connLog, services.StatusRecorder),
	}

	return conn, nil
}

// Open opens connection to the remote peer
// It will try to establish a connection using ICE and in parallel with relay. The higher priority connection type will
// be used.
func (conn *Conn) Open(engineCtx context.Context) error {
	conn.semaphore.Add(engineCtx)

	conn.mu.Lock()
	defer conn.mu.Unlock()

	if conn.opened {
		conn.semaphore.Done(engineCtx)
		return nil
	}

	conn.ctx, conn.ctxCancel = context.WithCancel(engineCtx)

	conn.workerRelay = NewWorkerRelay(conn.Log, isController(conn.config), conn.config, conn, conn.relayManager, conn.dumpState)

	relayIsSupportedLocally := conn.workerRelay.RelayIsSupportedLocally()
	workerICE, err := NewWorkerICE(conn.ctx, conn.Log, conn.config, conn, conn.signaler, conn.iFaceDiscover, conn.statusRecorder, relayIsSupportedLocally)
	if err != nil {
		return err
	}
	conn.workerICE = workerICE

	conn.handshaker = NewHandshaker(conn.Log, conn.config, conn.signaler, conn.workerICE, conn.workerRelay)

	conn.handshaker.AddOnNewOfferListener(conn.workerRelay.OnNewOffer)
	if os.Getenv("NB_FORCE_RELAY") != "true" {
		conn.handshaker.AddOnNewOfferListener(conn.workerICE.OnNewOffer)
	}

	conn.guard = guard.NewGuard(conn.Log, conn.isConnectedOnAllWay, conn.config.Timeout, conn.srWatcher)

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
		conn.waitInitialRandomSleepTime(conn.ctx)
		conn.semaphore.Done(conn.ctx)

		conn.dumpState.SendOffer()
		if err := conn.handshaker.sendOffer(); err != nil {
			conn.Log.Errorf("failed to send initial offer: %v", err)
		}

		conn.wg.Add(1)
		go func() {
			conn.guard.Start(conn.ctx, conn.onGuardEvent)
			conn.wg.Done()
		}()
	}()
	conn.opened = true
	return nil
}

// Close closes this peer Conn issuing a close event to the Conn closeCh
func (conn *Conn) Close() {
	conn.mu.Lock()
	defer conn.wgWatcherWg.Wait()
	defer conn.mu.Unlock()

	if !conn.opened {
		conn.Log.Debugf("ignore close connection to peer")
		return
	}

	conn.Log.Infof("close peer connection")
	conn.ctxCancel()

	conn.workerRelay.DisableWgWatcher()
	conn.workerRelay.CloseConn()
	conn.workerICE.Close()

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

	if err := conn.removeWgPeer(); err != nil {
		conn.Log.Errorf("failed to remove wg endpoint: %v", err)
	}

	conn.freeUpConnID()

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
func (conn *Conn) OnRemoteAnswer(answer OfferAnswer) bool {
	conn.dumpState.RemoteAnswer()
	conn.Log.Infof("OnRemoteAnswer, priority: %s, status ICE: %s, status relay: %s", conn.currentConnPriority, conn.statusICE, conn.statusRelay)
	return conn.handshaker.OnRemoteAnswer(answer)
}

// OnRemoteCandidate Handles ICE connection Candidate provided by the remote peer.
func (conn *Conn) OnRemoteCandidate(candidate ice.Candidate, haRoutes route.HAMap) {
	conn.dumpState.RemoteCandidate()
	conn.workerICE.OnRemoteCandidate(candidate, haRoutes)
}

func (conn *Conn) AddBeforeAddPeerHook(hook nbnet.AddHookFunc) {
	conn.beforeAddPeerHooks = append(conn.beforeAddPeerHooks, hook)
}
func (conn *Conn) AddAfterRemovePeerHook(hook nbnet.RemoveHookFunc) {
	conn.afterRemovePeerHooks = append(conn.afterRemovePeerHooks, hook)
}

// SetOnConnected sets a handler function to be triggered by Conn when a new connection to a remote peer established
func (conn *Conn) SetOnConnected(handler func(remoteWireGuardKey string, remoteRosenpassPubKey []byte, wireGuardIP string, remoteRosenpassAddr string)) {
	conn.onConnected = handler
}

// SetOnDisconnected sets a handler function to be triggered by Conn when a connection to a remote disconnected
func (conn *Conn) SetOnDisconnected(handler func(remotePeer string)) {
	conn.onDisconnected = handler
}

func (conn *Conn) OnRemoteOffer(offer OfferAnswer) bool {
	conn.dumpState.RemoteOffer()
	conn.Log.Infof("OnRemoteOffer, on status ICE: %s, status Relay: %s", conn.statusICE, conn.statusRelay)
	return conn.handshaker.OnRemoteOffer(offer)
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
		conn.updateIceState(iceConnInfo)
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

	if err := conn.runBeforeAddPeerHooks(ep.IP); err != nil {
		conn.Log.Errorf("Before add peer hook failed: %v", err)
	}

	conn.workerRelay.DisableWgWatcher()
	// todo consider to run conn.wgWatcherWg.Wait() here

	if conn.wgProxyRelay != nil {
		conn.wgProxyRelay.Pause()
	}

	if wgProxy != nil {
		wgProxy.Work()
	}

	if err = conn.configureWGEndpoint(ep, iceConnInfo.RosenpassPubKey); err != nil {
		conn.handleConfigurationFailure(err, wgProxy)
		return
	}
	wgConfigWorkaround()

	oldState := conn.currentConnPriority
	conn.currentConnPriority = priority
	conn.statusICE.SetConnected()
	conn.updateIceState(iceConnInfo)
	conn.doOnConnected(iceConnInfo.RosenpassPubKey, iceConnInfo.RosenpassAddr)

	if oldState == conntype.None {
		conn.peerConnDispatcher.NotifyConnected(conn.ConnID())
	}
}

func (conn *Conn) onICEStateDisconnected() {
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
		conn.wgProxyRelay.Work()

		if err := conn.configureWGEndpoint(conn.wgProxyRelay.EndpointAddr(), conn.rosenpassRemoteKey); err != nil {
			conn.Log.Errorf("failed to switch to relay conn: %v", err)
		}

		conn.wgWatcherWg.Add(1)
		go func() {
			defer conn.wgWatcherWg.Done()
			conn.workerRelay.EnableWgWatcher(conn.ctx)
		}()
		conn.currentConnPriority = conntype.Relay
	} else {
		conn.Log.Infof("ICE disconnected, do not switch to Relay. Reset priority to: %s", conntype.None.String())
		conn.currentConnPriority = conntype.None
		conn.peerConnDispatcher.NotifyDisconnected(conn.ConnID())
	}

	changed := conn.statusICE.Get() != worker.StatusDisconnected
	if changed {
		conn.guard.SetICEConnDisconnected()
	}
	conn.statusICE.SetDisconnected()

	peerState := State{
		PubKey:           conn.config.Key,
		ConnStatus:       conn.evalStatus(),
		Relayed:          conn.isRelayed(),
		ConnStatusUpdate: time.Now(),
	}

	err := conn.statusRecorder.UpdatePeerICEStateToDisconnected(peerState)
	if err != nil {
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
	conn.dumpState.NewLocalProxy()

	conn.Log.Infof("created new wgProxy for relay connection: %s", wgProxy.EndpointAddr().String())

	if conn.isICEActive() {
		conn.Log.Debugf("do not switch to relay because current priority is: %s", conn.currentConnPriority.String())
		conn.setRelayedProxy(wgProxy)
		conn.statusRelay.SetConnected()
		conn.updateRelayStatus(rci.relayedConn.RemoteAddr().String(), rci.rosenpassPubKey)
		return
	}

	if err := conn.runBeforeAddPeerHooks(wgProxy.EndpointAddr().IP); err != nil {
		conn.Log.Errorf("Before add peer hook failed: %v", err)
	}

	wgProxy.Work()
	if err := conn.configureWGEndpoint(wgProxy.EndpointAddr(), rci.rosenpassPubKey); err != nil {
		if err := wgProxy.CloseConn(); err != nil {
			conn.Log.Warnf("Failed to close relay connection: %v", err)
		}
		conn.Log.Errorf("Failed to update WireGuard peer configuration: %v", err)
		return
	}

	conn.wgWatcherWg.Add(1)
	go func() {
		defer conn.wgWatcherWg.Done()
		conn.workerRelay.EnableWgWatcher(conn.ctx)
	}()

	wgConfigWorkaround()
	conn.rosenpassRemoteKey = rci.rosenpassPubKey
	conn.currentConnPriority = conntype.Relay
	conn.statusRelay.SetConnected()
	conn.setRelayedProxy(wgProxy)
	conn.updateRelayStatus(rci.relayedConn.RemoteAddr().String(), rci.rosenpassPubKey)
	conn.Log.Infof("start to communicate with peer via relay")
	conn.doOnConnected(rci.rosenpassPubKey, rci.rosenpassAddr)
	conn.peerConnDispatcher.NotifyConnected(conn.ConnID())
}

func (conn *Conn) onRelayDisconnected() {
	conn.mu.Lock()
	defer conn.mu.Unlock()

	if conn.ctx.Err() != nil {
		return
	}

	conn.Log.Debugf("relay connection is disconnected")

	if conn.currentConnPriority == conntype.Relay {
		conn.Log.Debugf("clean up WireGuard config")
		if err := conn.removeWgPeer(); err != nil {
			conn.Log.Errorf("failed to remove wg endpoint: %v", err)
		}
		conn.currentConnPriority = conntype.None
		conn.peerConnDispatcher.NotifyDisconnected(conn.ConnID())
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
	conn.Log.Debugf("send offer to peer")
	conn.dumpState.SendOffer()
	if err := conn.handshaker.SendOffer(); err != nil {
		conn.Log.Errorf("failed to send offer: %v", err)
	}
}

func (conn *Conn) configureWGEndpoint(addr *net.UDPAddr, remoteRPKey []byte) error {
	presharedKey := conn.presharedKey(remoteRPKey)
	return conn.config.WgConfig.WgInterface.UpdatePeer(
		conn.config.WgConfig.RemoteKey,
		conn.config.WgConfig.AllowedIps,
		defaultWgKeepAlive,
		addr,
		presharedKey,
	)
}

func (conn *Conn) updateRelayStatus(relayServerAddr string, rosenpassPubKey []byte) {
	peerState := State{
		PubKey:             conn.config.Key,
		ConnStatusUpdate:   time.Now(),
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

func (conn *Conn) updateIceState(iceConnInfo ICEConnInfo) {
	peerState := State{
		PubKey:                     conn.config.Key,
		ConnStatusUpdate:           time.Now(),
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

func (conn *Conn) doOnConnected(remoteRosenpassPubKey []byte, remoteRosenpassAddr string) {
	if runtime.GOOS == "ios" {
		runtime.GC()
	}

	if conn.onConnected != nil {
		conn.onConnected(conn.config.Key, remoteRosenpassPubKey, conn.config.WgConfig.AllowedIps[0].Addr().String(), remoteRosenpassAddr)
	}
}

func (conn *Conn) waitInitialRandomSleepTime(ctx context.Context) {
	maxWait := 300
	duration := time.Duration(rand.Intn(maxWait)) * time.Millisecond

	timeout := time.NewTimer(duration)
	defer timeout.Stop()

	select {
	case <-ctx.Done():
	case <-timeout.C:
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

func (conn *Conn) isConnectedOnAllWay() (connected bool) {
	// would be better to protect this with a mutex, but it could cause deadlock with Close function

	defer func() {
		if !connected {
			conn.logTraceConnState()
		}
	}()

	if conn.statusICE.Get() == worker.StatusDisconnected {
		return false
	}

	if conn.workerRelay.IsRelayConnectionSupportedWithPeer() {
		if conn.statusRelay.Get() == worker.StatusDisconnected {
			return false
		}
	}

	return true
}

func (conn *Conn) runBeforeAddPeerHooks(ip net.IP) error {
	conn.connIDICE = nbnet.GenerateConnID()
	for _, hook := range conn.beforeAddPeerHooks {
		if err := hook(conn.connIDICE, ip); err != nil {
			return err
		}
	}
	return nil
}

func (conn *Conn) freeUpConnID() {
	if conn.connIDRelay != "" {
		for _, hook := range conn.afterRemovePeerHooks {
			if err := hook(conn.connIDRelay); err != nil {
				conn.Log.Errorf("After remove peer hook failed: %v", err)
			}
		}
		conn.connIDRelay = ""
	}

	if conn.connIDICE != "" {
		for _, hook := range conn.afterRemovePeerHooks {
			if err := hook(conn.connIDICE); err != nil {
				conn.Log.Errorf("After remove peer hook failed: %v", err)
			}
		}
		conn.connIDICE = ""
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

func (conn *Conn) isReadyToUpgrade() bool {
	return conn.wgProxyRelay != nil && conn.currentConnPriority != conntype.Relay
}

func (conn *Conn) isICEActive() bool {
	return (conn.currentConnPriority == conntype.ICEP2P || conn.currentConnPriority == conntype.ICETurn) && conn.statusICE.Get() == worker.StatusConnected
}

func (conn *Conn) removeWgPeer() error {
	return conn.config.WgConfig.WgInterface.RemovePeer(conn.config.WgConfig.RemoteKey)
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

	determKey, err := conn.rosenpassDetermKey()
	if err != nil {
		conn.Log.Errorf("failed to generate Rosenpass initial key: %v", err)
		return conn.config.WgConfig.PreSharedKey
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

// wgConfigWorkaround is a workaround for the issue with WireGuard configuration update
// When update a peer configuration in near to each other time, the second update can be ignored by WireGuard
func wgConfigWorkaround() {
	time.Sleep(100 * time.Millisecond)
}
