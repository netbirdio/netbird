package peer

import (
	"context"
	"math/rand"
	"net"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/cenkalti/backoff/v4"
	"github.com/pion/ice/v3"
	log "github.com/sirupsen/logrus"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/netbirdio/netbird/client/internal/stdnet"
	"github.com/netbirdio/netbird/client/internal/wgproxy"
	"github.com/netbirdio/netbird/iface"
	relayClient "github.com/netbirdio/netbird/relay/client"
	"github.com/netbirdio/netbird/route"
	nbnet "github.com/netbirdio/netbird/util/net"
)

type ConnPriority int

const (
	defaultWgKeepAlive = 25 * time.Second

	connPriorityRelay   ConnPriority = 1
	connPriorityICETurn ConnPriority = 1
	connPriorityICEP2P  ConnPriority = 2
)

type WgConfig struct {
	WgListenPort int
	RemoteKey    string
	WgInterface  iface.IWGIface
	AllowedIps   string
	PreSharedKey *wgtypes.Key
}

// ConnConfig is a peer Connection configuration
type ConnConfig struct {
	// Key is a public key of a remote peer
	Key string
	// LocalKey is a public key of a local peer
	LocalKey string

	Timeout time.Duration

	WgConfig WgConfig

	LocalWgPort int

	// RosenpassPubKey is this peer's Rosenpass public key
	RosenpassPubKey []byte
	// RosenpassPubKey is this peer's RosenpassAddr server address (IP:port)
	RosenpassAddr string

	// ICEConfig ICE protocol configuration
	ICEConfig ICEConfig
}

type WorkerCallbacks struct {
	OnRelayReadyCallback func(info RelayConnInfo)
	OnRelayStatusChanged func(ConnStatus)

	OnICEConnReadyCallback func(ConnPriority, ICEConnInfo)
	OnICEStatusChanged     func(ConnStatus)
}

type Conn struct {
	log            *log.Entry
	mu             sync.Mutex
	ctx            context.Context
	ctxCancel      context.CancelFunc
	config         ConnConfig
	statusRecorder *Status
	wgProxyFactory *wgproxy.Factory
	wgProxyICE     wgproxy.Proxy
	wgProxyRelay   wgproxy.Proxy
	signaler       *Signaler
	relayManager   *relayClient.Manager
	allowedIPsIP   string
	handshaker     *Handshaker

	onConnected    func(remoteWireGuardKey string, remoteRosenpassPubKey []byte, wireGuardIP string, remoteRosenpassAddr string)
	onDisconnected func(remotePeer string, wgIP string)

	statusRelay         ConnStatus
	statusICE           ConnStatus
	currentConnPriority ConnPriority
	opened              bool // this flag is used to prevent close in case of not opened connection

	workerICE   *WorkerICE
	workerRelay *WorkerRelay

	connIDRelay          nbnet.ConnectionID
	connIDICE            nbnet.ConnectionID
	beforeAddPeerHooks   []nbnet.AddHookFunc
	afterRemovePeerHooks []nbnet.RemoveHookFunc

	endpointRelay *net.UDPAddr

	// for reconnection operations
	iCEDisconnected   chan bool
	relayDisconnected chan bool
}

// NewConn creates a new not opened Conn to the remote peer.
// To establish a connection run Conn.Open
func NewConn(engineCtx context.Context, config ConnConfig, statusRecorder *Status, wgProxyFactory *wgproxy.Factory, signaler *Signaler, iFaceDiscover stdnet.ExternalIFaceDiscover, relayManager *relayClient.Manager) (*Conn, error) {
	_, allowedIPsIP, err := net.ParseCIDR(config.WgConfig.AllowedIps)
	if err != nil {
		log.Errorf("failed to parse allowedIPS: %v", err)
		return nil, err
	}

	ctx, ctxCancel := context.WithCancel(engineCtx)
	connLog := log.WithField("peer", config.Key)

	var conn = &Conn{
		log:               connLog,
		ctx:               ctx,
		ctxCancel:         ctxCancel,
		config:            config,
		statusRecorder:    statusRecorder,
		wgProxyFactory:    wgProxyFactory,
		signaler:          signaler,
		relayManager:      relayManager,
		allowedIPsIP:      allowedIPsIP.String(),
		statusRelay:       StatusDisconnected,
		statusICE:         StatusDisconnected,
		iCEDisconnected:   make(chan bool, 1),
		relayDisconnected: make(chan bool, 1),
	}

	rFns := WorkerRelayCallbacks{
		OnConnReady:    conn.relayConnectionIsReady,
		OnDisconnected: conn.onWorkerRelayStateDisconnected,
	}

	wFns := WorkerICECallbacks{
		OnConnReady:     conn.iCEConnectionIsReady,
		OnStatusChanged: conn.onWorkerICEStateDisconnected,
	}

	conn.workerRelay = NewWorkerRelay(connLog, config, relayManager, rFns)

	relayIsSupportedLocally := conn.workerRelay.RelayIsSupportedLocally()
	conn.workerICE, err = NewWorkerICE(ctx, connLog, config, signaler, iFaceDiscover, statusRecorder, relayIsSupportedLocally, wFns)
	if err != nil {
		return nil, err
	}

	conn.handshaker = NewHandshaker(ctx, connLog, config, signaler, conn.workerICE, conn.workerRelay)

	conn.handshaker.AddOnNewOfferListener(conn.workerRelay.OnNewOffer)
	if os.Getenv("NB_FORCE_RELAY") != "true" {
		conn.handshaker.AddOnNewOfferListener(conn.workerICE.OnNewOffer)
	}

	go conn.handshaker.Listen()

	return conn, nil
}

// Open opens connection to the remote peer
// It will try to establish a connection using ICE and in parallel with relay. The higher priority connection type will
// be used.
func (conn *Conn) Open() {
	conn.log.Debugf("open connection to peer")
	conn.mu.Lock()
	defer conn.mu.Unlock()
	conn.opened = true

	peerState := State{
		PubKey:           conn.config.Key,
		IP:               strings.Split(conn.config.WgConfig.AllowedIps, "/")[0],
		ConnStatusUpdate: time.Now(),
		ConnStatus:       StatusDisconnected,
		Mux:              new(sync.RWMutex),
	}
	err := conn.statusRecorder.UpdatePeerState(peerState)
	if err != nil {
		conn.log.Warnf("error while updating the state err: %v", err)
	}

	go conn.startHandshakeAndReconnect()
}

func (conn *Conn) startHandshakeAndReconnect() {
	conn.waitInitialRandomSleepTime()

	err := conn.handshaker.sendOffer()
	if err != nil {
		conn.log.Errorf("failed to send initial offer: %v", err)
	}

	if conn.workerRelay.IsController() {
		conn.reconnectLoopWithRetry()
	} else {
		conn.reconnectLoopForOnDisconnectedEvent()
	}
}

// Close closes this peer Conn issuing a close event to the Conn closeCh
func (conn *Conn) Close() {
	conn.mu.Lock()
	defer conn.mu.Unlock()

	conn.log.Infof("close peer connection")
	conn.ctxCancel()

	if !conn.opened {
		conn.log.Debugf("ignore close connection to peer")
		return
	}

	conn.workerRelay.DisableWgWatcher()

	if conn.wgProxyRelay != nil {
		err := conn.wgProxyRelay.CloseConn()
		if err != nil {
			conn.log.Errorf("failed to close wg proxy for relay: %v", err)
		}
		conn.wgProxyRelay = nil
	}

	if conn.wgProxyICE != nil {
		err := conn.wgProxyICE.CloseConn()
		if err != nil {
			conn.log.Errorf("failed to close wg proxy for ice: %v", err)
		}
		conn.wgProxyICE = nil
	}

	err := conn.config.WgConfig.WgInterface.RemovePeer(conn.config.WgConfig.RemoteKey)
	if err != nil {
		conn.log.Errorf("failed to remove wg endpoint: %v", err)
	}

	conn.freeUpConnID()

	if conn.evalStatus() == StatusConnected && conn.onDisconnected != nil {
		conn.onDisconnected(conn.config.WgConfig.RemoteKey, conn.config.WgConfig.AllowedIps)
	}

	conn.setStatusToDisconnected()
}

// OnRemoteAnswer handles an offer from the remote peer and returns true if the message was accepted, false otherwise
// doesn't block, discards the message if connection wasn't ready
func (conn *Conn) OnRemoteAnswer(answer OfferAnswer) bool {
	conn.log.Debugf("OnRemoteAnswer, status ICE: %s, status relay: %s", conn.statusICE, conn.statusRelay)
	return conn.handshaker.OnRemoteAnswer(answer)
}

// OnRemoteCandidate Handles ICE connection Candidate provided by the remote peer.
func (conn *Conn) OnRemoteCandidate(candidate ice.Candidate, haRoutes route.HAMap) {
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
func (conn *Conn) SetOnDisconnected(handler func(remotePeer string, wgIP string)) {
	conn.onDisconnected = handler
}

func (conn *Conn) OnRemoteOffer(offer OfferAnswer) bool {
	conn.log.Debugf("OnRemoteOffer, on status ICE: %s, status Relay: %s", conn.statusICE, conn.statusRelay)
	return conn.handshaker.OnRemoteOffer(offer)
}

// WgConfig returns the WireGuard config
func (conn *Conn) WgConfig() WgConfig {
	return conn.config.WgConfig
}

// Status returns current status of the Conn
func (conn *Conn) Status() ConnStatus {
	conn.mu.Lock()
	defer conn.mu.Unlock()
	return conn.evalStatus()
}

func (conn *Conn) GetKey() string {
	return conn.config.Key
}

func (conn *Conn) reconnectLoopWithRetry() {
	// Give chance to the peer to establish the initial connection.
	// With it, we can decrease to send necessary offer
	select {
	case <-conn.ctx.Done():
	case <-time.After(3 * time.Second):
	}

	ticker := conn.prepareExponentTicker()
	defer ticker.Stop()
	time.Sleep(1 * time.Second)
	for {
		select {
		case t := <-ticker.C:
			if t.IsZero() {
				// in case if the ticker has been canceled by context then avoid the temporary loop
				return
			}

			if conn.workerRelay.IsRelayConnectionSupportedWithPeer() {
				if conn.statusRelay == StatusDisconnected || conn.statusICE == StatusDisconnected {
					conn.log.Tracef("connectivity guard timedout, relay state: %s, ice state: %s", conn.statusRelay, conn.statusICE)
				}
			} else {
				if conn.statusICE == StatusDisconnected {
					conn.log.Tracef("connectivity guard timedout, ice state: %s", conn.statusICE)
				}
			}

			// checks if there is peer connection is established via relay or ice
			if conn.isConnected() {
				continue
			}

			err := conn.handshaker.sendOffer()
			if err != nil {
				conn.log.Errorf("failed to do handshake: %v", err)
			}
		case changed := <-conn.relayDisconnected:
			if !changed {
				continue
			}
			conn.log.Debugf("Relay state changed, reset reconnect timer")
			ticker.Stop()
			ticker = conn.prepareExponentTicker()
		case changed := <-conn.iCEDisconnected:
			if !changed {
				continue
			}
			conn.log.Debugf("ICE state changed, reset reconnect timer")
			ticker.Stop()
			ticker = conn.prepareExponentTicker()
		case <-conn.ctx.Done():
			conn.log.Debugf("context is done, stop reconnect loop")
			return
		}
	}
}

func (conn *Conn) prepareExponentTicker() *backoff.Ticker {
	bo := backoff.WithContext(&backoff.ExponentialBackOff{
		InitialInterval:     800 * time.Millisecond,
		RandomizationFactor: 0.01,
		Multiplier:          2,
		MaxInterval:         conn.config.Timeout,
		MaxElapsedTime:      0,
		Stop:                backoff.Stop,
		Clock:               backoff.SystemClock,
	}, conn.ctx)

	ticker := backoff.NewTicker(bo)
	<-ticker.C // consume the initial tick what is happening right after the ticker has been created

	return ticker
}

// reconnectLoopForOnDisconnectedEvent is used when the peer is not a controller and it should reconnect to the peer
// when the connection is lost. It will try to establish a connection only once time if before the connection was established
// It track separately the ice and relay connection status. Just because a lover priority connection reestablished it does not
// mean that to switch to it. We always force to use the higher priority connection.
func (conn *Conn) reconnectLoopForOnDisconnectedEvent() {
	for {
		select {
		case changed := <-conn.relayDisconnected:
			if !changed {
				continue
			}
			conn.log.Debugf("Relay state changed, try to send new offer")
		case changed := <-conn.iCEDisconnected:
			if !changed {
				continue
			}
			conn.log.Debugf("ICE state changed, try to send new offer")
		case <-conn.ctx.Done():
			conn.log.Debugf("context is done, stop reconnect loop")
			return
		}

		err := conn.handshaker.SendOffer()
		if err != nil {
			conn.log.Errorf("failed to do handshake: %v", err)
		}
	}
}

// configureConnection starts proxying traffic from/to local Wireguard and sets connection status to StatusConnected
func (conn *Conn) iCEConnectionIsReady(priority ConnPriority, iceConnInfo ICEConnInfo) {
	conn.mu.Lock()
	defer conn.mu.Unlock()

	if conn.ctx.Err() != nil {
		return
	}

	conn.log.Debugf("ICE connection is ready")

	conn.statusICE = StatusConnected

	defer conn.updateIceState(iceConnInfo)

	if conn.currentConnPriority > priority {
		return
	}

	conn.log.Infof("set ICE to active connection")

	endpoint, wgProxy, err := conn.getEndpointForICEConnInfo(iceConnInfo)
	if err != nil {
		return
	}

	endpointUdpAddr, _ := net.ResolveUDPAddr(endpoint.Network(), endpoint.String())
	conn.log.Debugf("Conn resolved IP is %s for endopint %s", endpoint, endpointUdpAddr.IP)

	conn.connIDICE = nbnet.GenerateConnID()
	for _, hook := range conn.beforeAddPeerHooks {
		if err := hook(conn.connIDICE, endpointUdpAddr.IP); err != nil {
			conn.log.Errorf("Before add peer hook failed: %v", err)
		}
	}

	conn.workerRelay.DisableWgWatcher()

	err = conn.configureWGEndpoint(endpointUdpAddr)
	if err != nil {
		if wgProxy != nil {
			if err := wgProxy.CloseConn(); err != nil {
				conn.log.Warnf("Failed to close turn connection: %v", err)
			}
		}
		conn.log.Warnf("Failed to update wg peer configuration: %v", err)
		return
	}
	wgConfigWorkaround()

	if conn.wgProxyICE != nil {
		if err := conn.wgProxyICE.CloseConn(); err != nil {
			conn.log.Warnf("failed to close deprecated wg proxy conn: %v", err)
		}
	}
	conn.wgProxyICE = wgProxy

	conn.currentConnPriority = priority

	conn.doOnConnected(iceConnInfo.RosenpassPubKey, iceConnInfo.RosenpassAddr)
}

// todo review to make sense to handle connecting and disconnected status also?
func (conn *Conn) onWorkerICEStateDisconnected(newState ConnStatus) {
	conn.mu.Lock()
	defer conn.mu.Unlock()

	if conn.ctx.Err() != nil {
		return
	}

	conn.log.Tracef("ICE connection state changed to %s", newState)

	// switch back to relay connection
	if conn.endpointRelay != nil && conn.currentConnPriority != connPriorityRelay {
		conn.log.Debugf("ICE disconnected, set Relay to active connection")
		err := conn.configureWGEndpoint(conn.endpointRelay)
		if err != nil {
			conn.log.Errorf("failed to switch to relay conn: %v", err)
		}
		conn.workerRelay.EnableWgWatcher(conn.ctx)
	}

	changed := conn.statusICE != newState && newState != StatusConnecting
	conn.statusICE = newState

	select {
	case conn.iCEDisconnected <- changed:
	default:
	}

	peerState := State{
		PubKey:           conn.config.Key,
		ConnStatus:       conn.evalStatus(),
		Relayed:          conn.isRelayed(),
		ConnStatusUpdate: time.Now(),
	}

	err := conn.statusRecorder.UpdatePeerICEStateToDisconnected(peerState)
	if err != nil {
		conn.log.Warnf("unable to set peer's state to disconnected ice, got error: %v", err)
	}
}

func (conn *Conn) relayConnectionIsReady(rci RelayConnInfo) {
	conn.mu.Lock()
	defer conn.mu.Unlock()

	if conn.ctx.Err() != nil {
		return
	}

	conn.log.Debugf("Relay connection is ready to use")
	conn.statusRelay = StatusConnected

	wgProxy := conn.wgProxyFactory.GetProxy(conn.ctx)
	endpoint, err := wgProxy.AddTurnConn(rci.relayedConn)
	if err != nil {
		conn.log.Errorf("failed to add relayed net.Conn to local proxy: %v", err)
		return
	}

	endpointUdpAddr, _ := net.ResolveUDPAddr(endpoint.Network(), endpoint.String())
	conn.endpointRelay = endpointUdpAddr
	conn.log.Debugf("conn resolved IP for %s: %s", endpoint, endpointUdpAddr.IP)

	defer conn.updateRelayStatus(rci.relayedConn.RemoteAddr().String(), rci.rosenpassPubKey)

	if conn.currentConnPriority > connPriorityRelay {
		if conn.statusICE == StatusConnected {
			log.Debugf("do not switch to relay because current priority is: %v", conn.currentConnPriority)
			return
		}
	}

	conn.connIDRelay = nbnet.GenerateConnID()
	for _, hook := range conn.beforeAddPeerHooks {
		if err := hook(conn.connIDRelay, endpointUdpAddr.IP); err != nil {
			conn.log.Errorf("Before add peer hook failed: %v", err)
		}
	}

	err = conn.configureWGEndpoint(endpointUdpAddr)
	if err != nil {
		if err := wgProxy.CloseConn(); err != nil {
			conn.log.Warnf("Failed to close relay connection: %v", err)
		}
		conn.log.Errorf("Failed to update wg peer configuration: %v", err)
		return
	}
	wgConfigWorkaround()
	conn.workerRelay.EnableWgWatcher(conn.ctx)

	if conn.wgProxyRelay != nil {
		if err := conn.wgProxyRelay.CloseConn(); err != nil {
			conn.log.Warnf("failed to close deprecated wg proxy conn: %v", err)
		}
	}
	conn.wgProxyRelay = wgProxy
	conn.currentConnPriority = connPriorityRelay

	conn.log.Infof("start to communicate with peer via relay")
	conn.doOnConnected(rci.rosenpassPubKey, rci.rosenpassAddr)
}

func (conn *Conn) onWorkerRelayStateDisconnected() {
	conn.mu.Lock()
	defer conn.mu.Unlock()

	if conn.ctx.Err() != nil {
		return
	}

	if conn.wgProxyRelay != nil {
		log.Debugf("relayed connection is closed, clean up WireGuard config")
		err := conn.config.WgConfig.WgInterface.RemovePeer(conn.config.WgConfig.RemoteKey)
		if err != nil {
			conn.log.Errorf("failed to remove wg endpoint: %v", err)
		}

		conn.endpointRelay = nil
		_ = conn.wgProxyRelay.CloseConn()
		conn.wgProxyRelay = nil
	}

	changed := conn.statusRelay != StatusDisconnected
	conn.statusRelay = StatusDisconnected

	select {
	case conn.relayDisconnected <- changed:
	default:
	}

	peerState := State{
		PubKey:           conn.config.Key,
		ConnStatus:       conn.evalStatus(),
		Relayed:          conn.isRelayed(),
		ConnStatusUpdate: time.Now(),
	}

	err := conn.statusRecorder.UpdatePeerRelayedStateToDisconnected(peerState)
	if err != nil {
		conn.log.Warnf("unable to save peer's state to Relay disconnected, got error: %v", err)
	}
}

func (conn *Conn) configureWGEndpoint(addr *net.UDPAddr) error {
	return conn.config.WgConfig.WgInterface.UpdatePeer(
		conn.config.WgConfig.RemoteKey,
		conn.config.WgConfig.AllowedIps,
		defaultWgKeepAlive,
		addr,
		conn.config.WgConfig.PreSharedKey,
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
		conn.log.Warnf("unable to save peer's Relay state, got error: %v", err)
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
		conn.log.Warnf("unable to save peer's ICE state, got error: %v", err)
	}
}

func (conn *Conn) setStatusToDisconnected() {
	conn.statusRelay = StatusDisconnected
	conn.statusICE = StatusDisconnected

	peerState := State{
		PubKey:           conn.config.Key,
		ConnStatus:       StatusDisconnected,
		ConnStatusUpdate: time.Now(),
		Mux:              new(sync.RWMutex),
	}
	err := conn.statusRecorder.UpdatePeerState(peerState)
	if err != nil {
		// pretty common error because by that time Engine can already remove the peer and status won't be available.
		// todo rethink status updates
		conn.log.Debugf("error while updating peer's state, err: %v", err)
	}
	if err := conn.statusRecorder.UpdateWireGuardPeerState(conn.config.Key, iface.WGStats{}); err != nil {
		conn.log.Debugf("failed to reset wireguard stats for peer: %s", err)
	}
}

func (conn *Conn) doOnConnected(remoteRosenpassPubKey []byte, remoteRosenpassAddr string) {
	if runtime.GOOS == "ios" {
		runtime.GC()
	}

	if conn.onConnected != nil {
		conn.onConnected(conn.config.Key, remoteRosenpassPubKey, conn.allowedIPsIP, remoteRosenpassAddr)
	}
}

func (conn *Conn) waitInitialRandomSleepTime() {
	minWait := 100
	maxWait := 800
	duration := time.Duration(rand.Intn(maxWait-minWait)+minWait) * time.Millisecond

	timeout := time.NewTimer(duration)
	defer timeout.Stop()

	select {
	case <-conn.ctx.Done():
	case <-timeout.C:
	}
}

func (conn *Conn) isRelayed() bool {
	if conn.statusRelay == StatusDisconnected && (conn.statusICE == StatusDisconnected || conn.statusICE == StatusConnecting) {
		return false
	}

	if conn.currentConnPriority == connPriorityICEP2P {
		return false
	}

	return true
}

func (conn *Conn) evalStatus() ConnStatus {
	if conn.statusRelay == StatusConnected || conn.statusICE == StatusConnected {
		return StatusConnected
	}

	if conn.statusRelay == StatusConnecting || conn.statusICE == StatusConnecting {
		return StatusConnecting
	}

	return StatusDisconnected
}

func (conn *Conn) isConnected() bool {
	conn.mu.Lock()
	defer conn.mu.Unlock()

	if conn.statusICE != StatusConnected && conn.statusICE != StatusConnecting {
		return false
	}

	if conn.workerRelay.IsRelayConnectionSupportedWithPeer() {
		if conn.statusRelay != StatusConnected {
			return false
		}
	}

	return true
}

func (conn *Conn) freeUpConnID() {
	if conn.connIDRelay != "" {
		for _, hook := range conn.afterRemovePeerHooks {
			if err := hook(conn.connIDRelay); err != nil {
				conn.log.Errorf("After remove peer hook failed: %v", err)
			}
		}
		conn.connIDRelay = ""
	}

	if conn.connIDICE != "" {
		for _, hook := range conn.afterRemovePeerHooks {
			if err := hook(conn.connIDICE); err != nil {
				conn.log.Errorf("After remove peer hook failed: %v", err)
			}
		}
		conn.connIDICE = ""
	}
}

func (conn *Conn) getEndpointForICEConnInfo(iceConnInfo ICEConnInfo) (net.Addr, wgproxy.Proxy, error) {
	if !iceConnInfo.RelayedOnLocal {
		return iceConnInfo.RemoteConn.RemoteAddr(), nil, nil
	}
	conn.log.Debugf("setup ice turn connection")
	wgProxy := conn.wgProxyFactory.GetProxy(conn.ctx)
	ep, err := wgProxy.AddTurnConn(iceConnInfo.RemoteConn)
	if err != nil {
		conn.log.Errorf("failed to add turn net.Conn to local proxy: %v", err)
		err = wgProxy.CloseConn()
		if err != nil {
			conn.log.Warnf("failed to close turn proxy connection: %v", err)
		}
		return nil, nil, err
	}
	return ep, wgProxy, nil
}

func isRosenpassEnabled(remoteRosenpassPubKey []byte) bool {
	return remoteRosenpassPubKey != nil
}

// wgConfigWorkaround is a workaround for the issue with WireGuard configuration update
// When update a peer configuration in near to each other time, the second update can be ignored by WireGuard
func wgConfigWorkaround() {
	time.Sleep(100 * time.Millisecond)
}
