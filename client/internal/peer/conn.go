package peer

import (
	"context"
	"net"
	"runtime"
	"strings"
	"sync"
	"time"

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
	connPriorityICETurn              = 1
	connPriorityICEP2P               = 2
)

type WgConfig struct {
	WgListenPort int
	RemoteKey    string
	WgInterface  *iface.WGIface
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

type BeforeAddPeerHookFunc func(connID nbnet.ConnectionID, IP net.IP) error
type AfterRemovePeerHookFunc func(connID nbnet.ConnectionID) error

type WorkerCallbacks struct {
	OnRelayReadyCallback func(info RelayConnInfo)
	OnRelayStatusChanged func(ConnStatus)

	OnICEConnReadyCallback func(ConnPriority, ICEConnInfo)
	OnICEStatusChanged     func(ConnStatus)
	DoHandshake            func(*OfferAnswer, error)
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
	allowedIPsIP   string
	handshaker     *Handshaker

	onConnected    func(remoteWireGuardKey string, remoteRosenpassPubKey []byte, wireGuardIP string, remoteRosenpassAddr string)
	onDisconnected func(remotePeer string, wgIP string)

	statusRelay ConnStatus
	statusICE   ConnStatus

	workerICE   *WorkerICE
	workerRelay *WorkerRelay

	connID               nbnet.ConnectionID
	beforeAddPeerHooks   []BeforeAddPeerHookFunc
	afterRemovePeerHooks []AfterRemovePeerHookFunc

	currentConnType ConnPriority

	endpointRelay *net.UDPAddr
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
		log:            connLog,
		ctx:            ctx,
		ctxCancel:      ctxCancel,
		config:         config,
		statusRecorder: statusRecorder,
		wgProxyFactory: wgProxyFactory,
		signaler:       signaler,
		allowedIPsIP:   allowedIPsIP.String(),
		statusRelay:    StatusDisconnected,
		statusICE:      StatusDisconnected,
	}

	rFns := WorkerRelayCallbacks{
		OnConnReady:     conn.relayConnectionIsReady,
		OnStatusChanged: conn.onWorkerRelayStateChanged,
	}

	wFns := WorkerICECallbacks{
		OnConnReady:     conn.iCEConnectionIsReady,
		OnStatusChanged: conn.onWorkerICEStateChanged,
		DoHandshake:     conn.doHandshake,
	}

	conn.handshaker = NewHandshaker(ctx, connLog, config, signaler, conn.onNewOffer)
	go conn.handshaker.Listen()
	conn.workerRelay = NewWorkerRelay(ctx, connLog, relayManager, config, rFns)
	conn.workerICE, err = NewWorkerICE(ctx, connLog, config, config.ICEConfig, signaler, iFaceDiscover, statusRecorder, wFns)
	if err != nil {
		return nil, err
	}
	return conn, nil
}

// Open opens connection to the remote peer
// It will try to establish a connection using ICE and in parallel with relay. The higher priority connection type will
// be used.
func (conn *Conn) Open() {
	conn.log.Debugf("open connection to peer")

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

	relayIsSupportedLocally := conn.workerRelay.RelayIsSupportedLocally()
	if relayIsSupportedLocally {
		go conn.workerRelay.SetupRelayConnection()
	}
	go conn.workerICE.SetupICEConnection(relayIsSupportedLocally)
}

// Close closes this peer Conn issuing a close event to the Conn closeCh
func (conn *Conn) Close() {
	conn.mu.Lock()
	defer conn.mu.Unlock()
	conn.ctxCancel()

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

	// todo: is it problem if we try to remove a peer what is never existed?
	err := conn.config.WgConfig.WgInterface.RemovePeer(conn.config.WgConfig.RemoteKey)
	if err != nil {
		conn.log.Errorf("failed to remove wg endpoint: %v", err)
	}

	if conn.connID != "" {
		for _, hook := range conn.afterRemovePeerHooks {
			if err := hook(conn.connID); err != nil {
				conn.log.Errorf("After remove peer hook failed: %v", err)
			}
		}
		conn.connID = ""
	}

	if conn.evalStatus() == StatusConnected && conn.onDisconnected != nil {
		conn.onDisconnected(conn.config.WgConfig.RemoteKey, conn.config.WgConfig.AllowedIps)
	}

	conn.statusRelay = StatusDisconnected
	conn.statusICE = StatusDisconnected

	peerState := State{
		PubKey:           conn.config.Key,
		ConnStatus:       StatusDisconnected,
		ConnStatusUpdate: time.Now(),
		Mux:              new(sync.RWMutex),
	}
	err = conn.statusRecorder.UpdatePeerState(peerState)
	if err != nil {
		// pretty common error because by that time Engine can already remove the peer and status won't be available.
		// todo rethink status updates
		conn.log.Debugf("error while updating peer's state, err: %v", err)
	}
	if err := conn.statusRecorder.UpdateWireGuardPeerState(conn.config.Key, iface.WGStats{}); err != nil {
		conn.log.Debugf("failed to reset wireguard stats for peer: %s", err)
	}
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

func (conn *Conn) AddBeforeAddPeerHook(hook BeforeAddPeerHookFunc) {
	conn.beforeAddPeerHooks = append(conn.beforeAddPeerHooks, hook)
}

func (conn *Conn) AddAfterRemovePeerHook(hook AfterRemovePeerHookFunc) {
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
	conn.log.Debugf("OnRemoteOffer, on status ICE: %s, status relay: %s", conn.statusICE, conn.statusRelay)
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

func (conn *Conn) onWorkerICEStateChanged(newState ConnStatus) {
	conn.mu.Lock()
	defer conn.mu.Unlock()
	log.Debugf("ICE connection state changed to %s", newState)
	defer func() {
		conn.statusICE = newState
	}()

	if conn.statusRelay == StatusConnected {
		return
	}

	if conn.evalStatus() == newState {
		return
	}

	if conn.endpointRelay != nil {
		err := conn.configureWGEndpoint(conn.endpointRelay)
		if err != nil {
			conn.log.Errorf("failed to switch back to relay conn: %v", err)
		}
		// todo update status to relay related things
		log.Debugf("switched back to relay connection")
		return
	}

	if newState > conn.statusICE {
		peerState := State{
			PubKey:           conn.config.Key,
			ConnStatus:       newState,
			ConnStatusUpdate: time.Now(),
			Mux:              new(sync.RWMutex),
		}
		_ = conn.statusRecorder.UpdatePeerState(peerState)
	}
}

func (conn *Conn) onWorkerRelayStateChanged(newState ConnStatus) {
	conn.mu.Lock()
	defer conn.mu.Unlock()
	defer func() {
		conn.statusRelay = newState
	}()

	conn.log.Debugf("Relay connection state changed to %s", newState)

	if conn.statusICE == StatusConnected {
		return
	}

	if conn.evalStatus() == newState {
		return
	}

	if newState > conn.statusRelay {
		peerState := State{
			PubKey:           conn.config.Key,
			ConnStatus:       newState,
			ConnStatusUpdate: time.Now(),
			Mux:              new(sync.RWMutex),
		}
		_ = conn.statusRecorder.UpdatePeerState(peerState)
	}
}

func (conn *Conn) relayConnectionIsReady(rci RelayConnInfo) {
	conn.mu.Lock()
	defer conn.mu.Unlock()

	if conn.ctx.Err() != nil {
		return
	}

	conn.log.Debugf("relay connection is ready")

	conn.statusRelay = stateConnected

	if conn.currentConnType > connPriorityRelay {
		return
	}

	if conn.currentConnType != 0 {
		conn.log.Infof("update connection to Relay type")
	}

	wgProxy := conn.wgProxyFactory.GetProxy(conn.ctx)
	endpoint, err := wgProxy.AddTurnConn(rci.relayedConn)
	if err != nil {
		conn.log.Errorf("failed to add relayed net.Conn to local proxy: %v", err)
		return
	}

	endpointUdpAddr, _ := net.ResolveUDPAddr(endpoint.Network(), endpoint.String())
	conn.log.Debugf("conn resolved IP for %s: %s", endpoint, endpointUdpAddr.IP)

	conn.connID = nbnet.GenerateConnID()
	for _, hook := range conn.beforeAddPeerHooks {
		if err := hook(conn.connID, endpointUdpAddr.IP); err != nil {
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
	conn.endpointRelay = endpointUdpAddr

	if conn.wgProxyRelay != nil {
		if err := conn.wgProxyRelay.CloseConn(); err != nil {
			conn.log.Warnf("failed to close depracated wg proxy conn: %v", err)
		}
	}
	conn.wgProxyRelay = wgProxy
	conn.currentConnType = connPriorityRelay

	peerState := State{
		Direct:  false,
		Relayed: true,
	}

	conn.updateStatus(peerState, rci.rosenpassPubKey, rci.rosenpassAddr)
}

// configureConnection starts proxying traffic from/to local Wireguard and sets connection status to StatusConnected
func (conn *Conn) iCEConnectionIsReady(priority ConnPriority, iceConnInfo ICEConnInfo) {
	conn.mu.Lock()
	defer conn.mu.Unlock()

	if conn.ctx.Err() != nil {
		return
	}

	conn.log.Debugf("ICE connection is ready")

	conn.statusICE = stateConnected

	if conn.currentConnType > priority {
		return
	}

	if conn.currentConnType != 0 {
		conn.log.Infof("update connection to ICE type")
	} else {
		conn.log.Infof("set ICE to active connection")
	}

	var (
		endpoint net.Addr
		wgProxy  wgproxy.Proxy
	)
	if iceConnInfo.RelayedOnLocal {
		conn.log.Debugf("setup ice turn connection")
		wgProxy = conn.wgProxyFactory.GetProxy(conn.ctx)
		ep, err := conn.wgProxyICE.AddTurnConn(iceConnInfo.RemoteConn)
		if err != nil {
			conn.log.Errorf("failed to add turn net.Conn to local proxy: %v", err)
			return
		}
		endpoint = ep
	} else {
		endpoint = iceConnInfo.RemoteConn.RemoteAddr()
	}

	endpointUdpAddr, _ := net.ResolveUDPAddr(endpoint.Network(), endpoint.String())
	conn.log.Debugf("Conn resolved IP is %s for endopint %s", endpoint, endpointUdpAddr.IP)

	conn.connID = nbnet.GenerateConnID()
	for _, hook := range conn.beforeAddPeerHooks {
		if err := hook(conn.connID, endpointUdpAddr.IP); err != nil {
			conn.log.Errorf("Before add peer hook failed: %v", err)
		}
	}

	err := conn.config.WgConfig.WgInterface.UpdatePeer(conn.config.WgConfig.RemoteKey, conn.config.WgConfig.AllowedIps, defaultWgKeepAlive, endpointUdpAddr, conn.config.WgConfig.PreSharedKey)
	if err != nil {
		if wgProxy != nil {
			if err := wgProxy.CloseConn(); err != nil {
				conn.log.Warnf("Failed to close turn connection: %v", err)
			}
		}
		conn.log.Warnf("Failed to update wg peer configuration: %v", err)
		return
	}

	if conn.wgProxyICE != nil {
		if err := conn.wgProxyICE.CloseConn(); err != nil {
			conn.log.Warnf("failed to close depracated wg proxy conn: %v", err)
		}
	}
	conn.wgProxyICE = wgProxy

	conn.currentConnType = priority

	peerState := State{
		LocalIceCandidateType:      iceConnInfo.LocalIceCandidateType,
		RemoteIceCandidateType:     iceConnInfo.RemoteIceCandidateType,
		LocalIceCandidateEndpoint:  iceConnInfo.LocalIceCandidateEndpoint,
		RemoteIceCandidateEndpoint: iceConnInfo.RemoteIceCandidateEndpoint,
		Direct:                     iceConnInfo.Direct,
		Relayed:                    iceConnInfo.Relayed,
	}

	conn.updateStatus(peerState, iceConnInfo.RosenpassPubKey, iceConnInfo.RosenpassAddr)
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
func (conn *Conn) updateStatus(peerState State, remoteRosenpassPubKey []byte, remoteRosenpassAddr string) {
	peerState.PubKey = conn.config.Key
	peerState.ConnStatus = StatusConnected
	peerState.ConnStatusUpdate = time.Now()
	peerState.RosenpassEnabled = isRosenpassEnabled(remoteRosenpassPubKey)
	peerState.Mux = new(sync.RWMutex)

	err := conn.statusRecorder.UpdatePeerState(peerState)
	if err != nil {
		conn.log.Warnf("unable to save peer's state, got error: %v", err)
	}

	if runtime.GOOS == "ios" {
		runtime.GC()
	}

	if conn.onConnected != nil {
		conn.onConnected(conn.config.Key, remoteRosenpassPubKey, conn.allowedIPsIP, remoteRosenpassAddr)
	}
	return
}

func (conn *Conn) doHandshake() error {
	if !conn.signaler.Ready() {
		return ErrSignalIsNotReady
	}

	var (
		ha  HandshakeArgs
		err error
	)
	ha.IceUFrag, ha.IcePwd = conn.workerICE.GetLocalUserCredentials()
	addr, err := conn.workerRelay.RelayAddress()
	if err == nil {
		ha.RelayAddr = addr.String()
	}
	return conn.handshaker.SendOffer(ha)
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

func (conn *Conn) onNewOffer(answer *OfferAnswer) {
	// todo move to this callback into handshaker
	go conn.workerRelay.OnNewOffer(answer)
	go conn.workerICE.OnNewOffer(answer)
}

func isRosenpassEnabled(remoteRosenpassPubKey []byte) bool {
	return remoteRosenpassPubKey != nil
}
