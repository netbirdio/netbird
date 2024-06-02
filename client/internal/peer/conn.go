package peer

import (
	"context"
	"fmt"
	"net"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/pion/ice/v3"
	"github.com/pion/stun/v2"
	log "github.com/sirupsen/logrus"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/netbirdio/netbird/client/internal/stdnet"
	"github.com/netbirdio/netbird/client/internal/wgproxy"
	"github.com/netbirdio/netbird/iface"
	"github.com/netbirdio/netbird/iface/bind"
	signal "github.com/netbirdio/netbird/signal/client"
	sProto "github.com/netbirdio/netbird/signal/proto"
	nbnet "github.com/netbirdio/netbird/util/net"
	"github.com/netbirdio/netbird/version"
)

const (
	iceKeepAliveDefault           = 4 * time.Second
	iceDisconnectedTimeoutDefault = 6 * time.Second
	// iceRelayAcceptanceMinWaitDefault is the same as in the Pion ICE package
	iceRelayAcceptanceMinWaitDefault = 2 * time.Second

	defaultWgKeepAlive = 25 * time.Second
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

	// StunTurn is a list of STUN and TURN URLs
	StunTurn []*stun.URI

	// InterfaceBlackList is a list of machine interfaces that should be filtered out by ICE Candidate gathering
	// (e.g. if eth0 is in the list, host candidate of this interface won't be used)
	InterfaceBlackList   []string
	DisableIPv6Discovery bool

	Timeout time.Duration

	WgConfig WgConfig

	UDPMux      ice.UDPMux
	UDPMuxSrflx ice.UniversalUDPMux

	LocalWgPort int

	NATExternalIPs []string

	// UsesBind indicates whether the WireGuard interface is userspace and uses bind.ICEBind
	UserspaceBind bool

	// RosenpassPubKey is this peer's Rosenpass public key
	RosenpassPubKey []byte
	// RosenpassPubKey is this peer's RosenpassAddr server address (IP:port)
	RosenpassAddr string
}

// OfferAnswer represents a session establishment offer or answer
type OfferAnswer struct {
	IceCredentials IceCredentials
	// WgListenPort is a remote WireGuard listen port.
	// This field is used when establishing a direct WireGuard connection without any proxy.
	// We can set the remote peer's endpoint with this port.
	WgListenPort int

	// Version of NetBird Agent
	Version string
	// RosenpassPubKey is the Rosenpass public key of the remote peer when receiving this message
	// This value is the local Rosenpass server public key when sending the message
	RosenpassPubKey []byte
	// RosenpassAddr is the Rosenpass server address (IP:port) of the remote peer when receiving this message
	// This value is the local Rosenpass server address when sending the message
	RosenpassAddr string
}

// IceCredentials ICE protocol credentials struct
type IceCredentials struct {
	UFrag string
	Pwd   string
}

type BeforeAddPeerHookFunc func(connID nbnet.ConnectionID, IP net.IP) error
type AfterRemovePeerHookFunc func(connID nbnet.ConnectionID) error

type Conn struct {
	config ConnConfig
	mu     sync.Mutex

	// signalCandidate is a handler function to signal remote peer about local connection candidate
	signalCandidate func(candidate ice.Candidate) error
	// signalOffer is a handler function to signal remote peer our connection offer (credentials)
	signalOffer       func(OfferAnswer) error
	signalAnswer      func(OfferAnswer) error
	sendSignalMessage func(message *sProto.Message) error
	onConnected       func(remoteWireGuardKey string, remoteRosenpassPubKey []byte, wireGuardIP string, remoteRosenpassAddr string)
	onDisconnected    func(remotePeer string, wgIP string)

	// remoteOffersCh is a channel used to wait for remote credentials to proceed with the connection
	remoteOffersCh chan OfferAnswer
	// remoteAnswerCh is a channel used to wait for remote credentials answer (confirmation of our offer) to proceed with the connection
	remoteAnswerCh     chan OfferAnswer
	closeCh            chan struct{}
	ctx                context.Context
	notifyDisconnected context.CancelFunc

	agent  *ice.Agent
	status ConnStatus

	statusRecorder *Status

	wgProxyFactory *wgproxy.Factory
	wgProxy        wgproxy.Proxy

	remoteModeCh chan ModeMessage
	meta         meta

	adapter        iface.TunAdapter
	iFaceDiscover  stdnet.ExternalIFaceDiscover
	sentExtraSrflx bool

	remoteEndpoint *net.UDPAddr
	remoteConn     *ice.Conn

	connID               nbnet.ConnectionID
	beforeAddPeerHooks   []BeforeAddPeerHookFunc
	afterRemovePeerHooks []AfterRemovePeerHookFunc
}

// meta holds meta information about a connection
type meta struct {
	protoSupport signal.FeaturesSupport
}

// ModeMessage represents a connection mode chosen by the peer
type ModeMessage struct {
	// Direct indicates that it decided to use a direct connection
	Direct bool
}

// GetConf returns the connection config
func (conn *Conn) GetConf() ConnConfig {
	return conn.config
}

// WgConfig returns the WireGuard config
func (conn *Conn) WgConfig() WgConfig {
	return conn.config.WgConfig
}

// UpdateStunTurn update the turn and stun addresses
func (conn *Conn) UpdateStunTurn(turnStun []*stun.URI) {
	conn.config.StunTurn = turnStun
}

// NewConn creates a new not opened Conn to the remote peer.
// To establish a connection run Conn.Open
func NewConn(config ConnConfig, statusRecorder *Status, wgProxyFactory *wgproxy.Factory, adapter iface.TunAdapter, iFaceDiscover stdnet.ExternalIFaceDiscover) (*Conn, error) {
	return &Conn{
		config:         config,
		mu:             sync.Mutex{},
		status:         StatusDisconnected,
		closeCh:        make(chan struct{}),
		remoteOffersCh: make(chan OfferAnswer),
		remoteAnswerCh: make(chan OfferAnswer),
		statusRecorder: statusRecorder,
		remoteModeCh:   make(chan ModeMessage, 1),
		wgProxyFactory: wgProxyFactory,
		adapter:        adapter,
		iFaceDiscover:  iFaceDiscover,
	}, nil
}

func (conn *Conn) reCreateAgent() error {
	conn.mu.Lock()
	defer conn.mu.Unlock()

	failedTimeout := 6 * time.Second

	var err error
	transportNet, err := conn.newStdNet()
	if err != nil {
		log.Errorf("failed to create pion's stdnet: %s", err)
	}

	iceKeepAlive := iceKeepAlive()
	iceDisconnectedTimeout := iceDisconnectedTimeout()
	iceRelayAcceptanceMinWait := iceRelayAcceptanceMinWait()

	agentConfig := &ice.AgentConfig{
		MulticastDNSMode:       ice.MulticastDNSModeDisabled,
		NetworkTypes:           []ice.NetworkType{ice.NetworkTypeUDP4, ice.NetworkTypeUDP6},
		Urls:                   conn.config.StunTurn,
		CandidateTypes:         conn.candidateTypes(),
		FailedTimeout:          &failedTimeout,
		InterfaceFilter:        stdnet.InterfaceFilter(conn.config.InterfaceBlackList),
		UDPMux:                 conn.config.UDPMux,
		UDPMuxSrflx:            conn.config.UDPMuxSrflx,
		NAT1To1IPs:             conn.config.NATExternalIPs,
		Net:                    transportNet,
		DisconnectedTimeout:    &iceDisconnectedTimeout,
		KeepaliveInterval:      &iceKeepAlive,
		RelayAcceptanceMinWait: &iceRelayAcceptanceMinWait,
	}

	if conn.config.DisableIPv6Discovery {
		agentConfig.NetworkTypes = []ice.NetworkType{ice.NetworkTypeUDP4}
	}

	conn.agent, err = ice.NewAgent(agentConfig)
	if err != nil {
		return err
	}

	err = conn.agent.OnCandidate(conn.onICECandidate)
	if err != nil {
		return err
	}

	err = conn.agent.OnConnectionStateChange(conn.onICEConnectionStateChange)
	if err != nil {
		return err
	}

	err = conn.agent.OnSelectedCandidatePairChange(conn.onICESelectedCandidatePair)
	if err != nil {
		return err
	}

	err = conn.agent.OnSuccessfulSelectedPairBindingResponse(func(p *ice.CandidatePair) {
		err := conn.statusRecorder.UpdateLatency(conn.config.Key, p.Latency())
		if err != nil {
			log.Debugf("failed to update latency for peer %s: %s", conn.config.Key, err)
			return
		}
	})
	if err != nil {
		return fmt.Errorf("failed setting binding response callback: %w", err)
	}

	return nil
}

func (conn *Conn) candidateTypes() []ice.CandidateType {
	if hasICEForceRelayConn() {
		return []ice.CandidateType{ice.CandidateTypeRelay}
	}
	// TODO: remove this once we have refactored userspace proxy into the bind package
	if runtime.GOOS == "ios" {
		return []ice.CandidateType{ice.CandidateTypeHost, ice.CandidateTypeServerReflexive}
	}
	return []ice.CandidateType{ice.CandidateTypeHost, ice.CandidateTypeServerReflexive, ice.CandidateTypeRelay}
}

// Open opens connection to the remote peer starting ICE candidate gathering process.
// Blocks until connection has been closed or connection timeout.
// ConnStatus will be set accordingly
func (conn *Conn) Open(ctx context.Context) error {
	log.Debugf("trying to connect to peer %s", conn.config.Key)

	peerState := State{
		PubKey:           conn.config.Key,
		IP:               strings.Split(conn.config.WgConfig.AllowedIps, "/")[0],
		ConnStatusUpdate: time.Now(),
		ConnStatus:       conn.status,
		Mux:              new(sync.RWMutex),
	}
	err := conn.statusRecorder.UpdatePeerState(peerState)
	if err != nil {
		log.Warnf("error while updating the state of peer %s,err: %v", conn.config.Key, err)
	}

	defer func() {
		err := conn.cleanup()
		if err != nil {
			log.Warnf("error while cleaning up peer connection %s: %v", conn.config.Key, err)
			return
		}
	}()

	err = conn.reCreateAgent()
	if err != nil {
		return err
	}

	err = conn.sendOffer()
	if err != nil {
		return err
	}

	log.Debugf("connection offer sent to peer %s, waiting for the confirmation", conn.config.Key)

	// Only continue once we got a connection confirmation from the remote peer.
	// The connection timeout could have happened before a confirmation received from the remote.
	// The connection could have also been closed externally (e.g. when we received an update from the management that peer shouldn't be connected)
	var remoteOfferAnswer OfferAnswer
	select {
	case remoteOfferAnswer = <-conn.remoteOffersCh:
		// received confirmation from the remote peer -> ready to proceed
		err = conn.sendAnswer()
		if err != nil {
			return err
		}
	case remoteOfferAnswer = <-conn.remoteAnswerCh:
	case <-time.After(conn.config.Timeout):
		return NewConnectionTimeoutError(conn.config.Key, conn.config.Timeout)
	case <-conn.closeCh:
		// closed externally
		return NewConnectionClosedError(conn.config.Key)
	}

	log.Debugf("received connection confirmation from peer %s running version %s and with remote WireGuard listen port %d",
		conn.config.Key, remoteOfferAnswer.Version, remoteOfferAnswer.WgListenPort)

	// at this point we received offer/answer and we are ready to gather candidates
	conn.mu.Lock()
	conn.status = StatusConnecting
	conn.ctx, conn.notifyDisconnected = context.WithCancel(ctx)
	defer conn.notifyDisconnected()
	conn.mu.Unlock()

	peerState = State{
		PubKey:           conn.config.Key,
		ConnStatus:       conn.status,
		ConnStatusUpdate: time.Now(),
		Mux:              new(sync.RWMutex),
	}
	err = conn.statusRecorder.UpdatePeerState(peerState)
	if err != nil {
		log.Warnf("error while updating the state of peer %s,err: %v", conn.config.Key, err)
	}

	err = conn.agent.GatherCandidates()
	if err != nil {
		return err
	}

	// will block until connection succeeded
	// but it won't release if ICE Agent went into Disconnected or Failed state,
	// so we have to cancel it with the provided context once agent detected a broken connection
	isControlling := conn.config.LocalKey > conn.config.Key
	var remoteConn *ice.Conn
	if isControlling {
		remoteConn, err = conn.agent.Dial(conn.ctx, remoteOfferAnswer.IceCredentials.UFrag, remoteOfferAnswer.IceCredentials.Pwd)
	} else {
		remoteConn, err = conn.agent.Accept(conn.ctx, remoteOfferAnswer.IceCredentials.UFrag, remoteOfferAnswer.IceCredentials.Pwd)
	}
	if err != nil {
		return err
	}

	// dynamically set remote WireGuard port is other side specified a different one from the default one
	remoteWgPort := iface.DefaultWgPort
	if remoteOfferAnswer.WgListenPort != 0 {
		remoteWgPort = remoteOfferAnswer.WgListenPort
	}

	conn.remoteConn = remoteConn

	// the ice connection has been established successfully so we are ready to start the proxy
	remoteAddr, err := conn.configureConnection(remoteConn, remoteWgPort, remoteOfferAnswer.RosenpassPubKey,
		remoteOfferAnswer.RosenpassAddr)
	if err != nil {
		return err
	}

	log.Infof("connected to peer %s, endpoint address: %s", conn.config.Key, remoteAddr.String())

	// wait until connection disconnected or has been closed externally (upper layer, e.g. engine)
	select {
	case <-conn.closeCh:
		// closed externally
		return NewConnectionClosedError(conn.config.Key)
	case <-conn.ctx.Done():
		// disconnected from the remote peer
		return NewConnectionDisconnectedError(conn.config.Key)
	}
}

func isRelayCandidate(candidate ice.Candidate) bool {
	return candidate.Type() == ice.CandidateTypeRelay
}

func (conn *Conn) AddBeforeAddPeerHook(hook BeforeAddPeerHookFunc) {
	conn.beforeAddPeerHooks = append(conn.beforeAddPeerHooks, hook)
}

func (conn *Conn) AddAfterRemovePeerHook(hook AfterRemovePeerHookFunc) {
	conn.afterRemovePeerHooks = append(conn.afterRemovePeerHooks, hook)
}

// configureConnection starts proxying traffic from/to local Wireguard and sets connection status to StatusConnected
func (conn *Conn) configureConnection(remoteConn net.Conn, remoteWgPort int, remoteRosenpassPubKey []byte, remoteRosenpassAddr string) (net.Addr, error) {
	conn.mu.Lock()
	defer conn.mu.Unlock()

	pair, err := conn.agent.GetSelectedCandidatePair()
	if err != nil {
		return nil, err
	}

	var endpoint net.Addr
	if isRelayCandidate(pair.Local) {
		log.Debugf("setup relay connection")
		conn.wgProxy = conn.wgProxyFactory.GetProxy(conn.ctx)
		endpoint, err = conn.wgProxy.AddTurnConn(remoteConn)
		if err != nil {
			return nil, err
		}
	} else {
		// To support old version's with direct mode we attempt to punch an additional role with the remote WireGuard port
		go conn.punchRemoteWGPort(pair, remoteWgPort)
		endpoint = remoteConn.RemoteAddr()
	}

	endpointUdpAddr, _ := net.ResolveUDPAddr(endpoint.Network(), endpoint.String())
	conn.remoteEndpoint = endpointUdpAddr
	log.Debugf("Conn resolved IP for %s: %s", endpoint, endpointUdpAddr.IP)

	conn.connID = nbnet.GenerateConnID()
	for _, hook := range conn.beforeAddPeerHooks {
		if err := hook(conn.connID, endpointUdpAddr.IP); err != nil {
			log.Errorf("Before add peer hook failed: %v", err)
		}
	}

	err = conn.config.WgConfig.WgInterface.UpdatePeer(conn.config.WgConfig.RemoteKey, conn.config.WgConfig.AllowedIps, defaultWgKeepAlive, endpointUdpAddr, conn.config.WgConfig.PreSharedKey)
	if err != nil {
		if conn.wgProxy != nil {
			if err := conn.wgProxy.CloseConn(); err != nil {
				log.Warnf("Failed to close turn connection: %v", err)
			}
		}
		return nil, fmt.Errorf("update peer: %w", err)
	}

	conn.status = StatusConnected
	rosenpassEnabled := false
	if remoteRosenpassPubKey != nil {
		rosenpassEnabled = true
	}

	peerState := State{
		PubKey:                     conn.config.Key,
		ConnStatus:                 conn.status,
		ConnStatusUpdate:           time.Now(),
		LocalIceCandidateType:      pair.Local.Type().String(),
		RemoteIceCandidateType:     pair.Remote.Type().String(),
		LocalIceCandidateEndpoint:  fmt.Sprintf("%s:%d", pair.Local.Address(), pair.Local.Port()),
		RemoteIceCandidateEndpoint: fmt.Sprintf("%s:%d", pair.Remote.Address(), pair.Remote.Port()),
		Direct:                     !isRelayCandidate(pair.Local),
		RosenpassEnabled:           rosenpassEnabled,
		Mux:                        new(sync.RWMutex),
	}
	if pair.Local.Type() == ice.CandidateTypeRelay || pair.Remote.Type() == ice.CandidateTypeRelay {
		peerState.Relayed = true
	}

	err = conn.statusRecorder.UpdatePeerState(peerState)
	if err != nil {
		log.Warnf("unable to save peer's state, got error: %v", err)
	}

	_, ipNet, err := net.ParseCIDR(strings.Split(conn.config.WgConfig.AllowedIps, ",")[0])
	if err != nil {
		return nil, err
	}

	if runtime.GOOS == "ios" {
		runtime.GC()
	}

	if conn.onConnected != nil {
		conn.onConnected(conn.config.Key, remoteRosenpassPubKey, ipNet.IP.String(), remoteRosenpassAddr)
	}

	return endpoint, nil
}

func (conn *Conn) punchRemoteWGPort(pair *ice.CandidatePair, remoteWgPort int) {
	// wait local endpoint configuration
	time.Sleep(time.Second)
	addr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", pair.Remote.Address(), remoteWgPort))
	if err != nil {
		log.Warnf("got an error while resolving the udp address, err: %s", err)
		return
	}

	mux, ok := conn.config.UDPMuxSrflx.(*bind.UniversalUDPMuxDefault)
	if !ok {
		log.Warn("invalid udp mux conversion")
		return
	}
	_, err = mux.GetSharedConn().WriteTo([]byte{0x6e, 0x62}, addr)
	if err != nil {
		log.Warnf("got an error while sending the punch packet, err: %s", err)
	}
}

// cleanup closes all open resources and sets status to StatusDisconnected
func (conn *Conn) cleanup() error {
	log.Debugf("trying to cleanup %s", conn.config.Key)
	conn.mu.Lock()
	defer conn.mu.Unlock()

	conn.sentExtraSrflx = false

	var err1, err2, err3 error
	if conn.agent != nil {
		err1 = conn.agent.Close()
		if err1 == nil {
			conn.agent = nil
		}
	}

	if conn.wgProxy != nil {
		err2 = conn.wgProxy.CloseConn()
		conn.wgProxy = nil
	}

	// todo: is it problem if we try to remove a peer what is never existed?
	err3 = conn.config.WgConfig.WgInterface.RemovePeer(conn.config.WgConfig.RemoteKey)

	if conn.connID != "" {
		for _, hook := range conn.afterRemovePeerHooks {
			if err := hook(conn.connID); err != nil {
				log.Errorf("After remove peer hook failed: %v", err)
			}
		}
	}
	conn.connID = ""

	if conn.notifyDisconnected != nil {
		conn.notifyDisconnected()
		conn.notifyDisconnected = nil
	}

	if conn.status == StatusConnected && conn.onDisconnected != nil {
		conn.onDisconnected(conn.config.WgConfig.RemoteKey, conn.config.WgConfig.AllowedIps)
	}

	conn.status = StatusDisconnected

	peerState := State{
		PubKey:           conn.config.Key,
		ConnStatus:       conn.status,
		ConnStatusUpdate: time.Now(),
		Mux:              new(sync.RWMutex),
	}
	err := conn.statusRecorder.UpdatePeerState(peerState)
	if err != nil {
		// pretty common error because by that time Engine can already remove the peer and status won't be available.
		// todo rethink status updates
		log.Debugf("error while updating peer's %s state, err: %v", conn.config.Key, err)
	}
	if err := conn.statusRecorder.UpdateWireGuardPeerState(conn.config.Key, iface.WGStats{}); err != nil {
		log.Debugf("failed to reset wireguard stats for peer %s: %s", conn.config.Key, err)
	}

	log.Debugf("cleaned up connection to peer %s", conn.config.Key)
	if err1 != nil {
		return err1
	}
	if err2 != nil {
		return err2
	}
	return err3
}

// SetSignalOffer sets a handler function to be triggered by Conn when a new connection offer has to be signalled to the remote peer
func (conn *Conn) SetSignalOffer(handler func(offer OfferAnswer) error) {
	conn.signalOffer = handler
}

// SetOnConnected sets a handler function to be triggered by Conn when a new connection to a remote peer established
func (conn *Conn) SetOnConnected(handler func(remoteWireGuardKey string, remoteRosenpassPubKey []byte, wireGuardIP string, remoteRosenpassAddr string)) {
	conn.onConnected = handler
}

// SetOnDisconnected sets a handler function to be triggered by Conn when a connection to a remote disconnected
func (conn *Conn) SetOnDisconnected(handler func(remotePeer string, wgIP string)) {
	conn.onDisconnected = handler
}

// SetSignalAnswer sets a handler function to be triggered by Conn when a new connection answer has to be signalled to the remote peer
func (conn *Conn) SetSignalAnswer(handler func(answer OfferAnswer) error) {
	conn.signalAnswer = handler
}

// SetSignalCandidate sets a handler function to be triggered by Conn when a new ICE local connection candidate has to be signalled to the remote peer
func (conn *Conn) SetSignalCandidate(handler func(candidate ice.Candidate) error) {
	conn.signalCandidate = handler
}

// SetSendSignalMessage sets a handler function to be triggered by Conn when there is new message to send via signal
func (conn *Conn) SetSendSignalMessage(handler func(message *sProto.Message) error) {
	conn.sendSignalMessage = handler
}

// onICECandidate is a callback attached to an ICE Agent to receive new local connection candidates
// and then signals them to the remote peer
func (conn *Conn) onICECandidate(candidate ice.Candidate) {
	if candidate != nil {
		// TODO: reported port is incorrect for CandidateTypeHost, makes understanding ICE use via logs confusing as port is ignored
		log.Debugf("discovered local candidate %s", candidate.String())
		go func() {
			err := conn.signalCandidate(candidate)
			if err != nil {
				log.Errorf("failed signaling candidate to the remote peer %s %s", conn.config.Key, err)
			}

			// sends an extra server reflexive candidate to the remote peer with our related port (usually the wireguard port)
			// this is useful when network has an existing port forwarding rule for the wireguard port and this peer
			if !conn.sentExtraSrflx && candidate.Type() == ice.CandidateTypeServerReflexive && candidate.Port() != candidate.RelatedAddress().Port {
				relatedAdd := candidate.RelatedAddress()
				extraSrflx, err := ice.NewCandidateServerReflexive(&ice.CandidateServerReflexiveConfig{
					Network:   candidate.NetworkType().String(),
					Address:   candidate.Address(),
					Port:      relatedAdd.Port,
					Component: candidate.Component(),
					RelAddr:   relatedAdd.Address,
					RelPort:   relatedAdd.Port,
				})
				if err != nil {
					log.Errorf("failed creating extra server reflexive candidate %s", err)
					return
				}
				err = conn.signalCandidate(extraSrflx)
				if err != nil {
					log.Errorf("failed signaling the extra server reflexive candidate to the remote peer %s: %s", conn.config.Key, err)
					return
				}
				conn.sentExtraSrflx = true
			}
		}()
	}
}

func (conn *Conn) onICESelectedCandidatePair(c1 ice.Candidate, c2 ice.Candidate) {
	log.Debugf("selected candidate pair [local <-> remote] -> [%s <-> %s], peer %s", c1.String(), c2.String(),
		conn.config.Key)
}

// onICEConnectionStateChange registers callback of an ICE Agent to track connection state
func (conn *Conn) onICEConnectionStateChange(state ice.ConnectionState) {
	log.Debugf("peer %s ICE ConnectionState has changed to %s", conn.config.Key, state.String())
	if state == ice.ConnectionStateFailed || state == ice.ConnectionStateDisconnected {
		conn.notifyDisconnected()
	}
}

func (conn *Conn) sendAnswer() error {
	conn.mu.Lock()
	defer conn.mu.Unlock()

	localUFrag, localPwd, err := conn.agent.GetLocalUserCredentials()
	if err != nil {
		return err
	}

	log.Debugf("sending answer to %s", conn.config.Key)
	err = conn.signalAnswer(OfferAnswer{
		IceCredentials:  IceCredentials{localUFrag, localPwd},
		WgListenPort:    conn.config.LocalWgPort,
		Version:         version.NetbirdVersion(),
		RosenpassPubKey: conn.config.RosenpassPubKey,
		RosenpassAddr:   conn.config.RosenpassAddr,
	})
	if err != nil {
		return err
	}

	return nil
}

// sendOffer prepares local user credentials and signals them to the remote peer
func (conn *Conn) sendOffer() error {
	conn.mu.Lock()
	defer conn.mu.Unlock()

	localUFrag, localPwd, err := conn.agent.GetLocalUserCredentials()
	if err != nil {
		return err
	}
	err = conn.signalOffer(OfferAnswer{
		IceCredentials:  IceCredentials{localUFrag, localPwd},
		WgListenPort:    conn.config.LocalWgPort,
		Version:         version.NetbirdVersion(),
		RosenpassPubKey: conn.config.RosenpassPubKey,
		RosenpassAddr:   conn.config.RosenpassAddr,
	})
	if err != nil {
		return err
	}
	return nil
}

// Close closes this peer Conn issuing a close event to the Conn closeCh
func (conn *Conn) Close() error {
	conn.mu.Lock()
	defer conn.mu.Unlock()
	select {
	case conn.closeCh <- struct{}{}:
		return nil
	default:
		// probably could happen when peer has been added and removed right after not even starting to connect
		// todo further investigate
		// this really happens due to unordered messages coming from management
		// more importantly it causes inconsistency -> 2 Conn objects for the same peer
		// e.g. this flow:
		// update from management has peers: [1,2,3,4]
		// engine creates a Conn for peers:  [1,2,3,4] and schedules Open in ~1sec
		// before conn.Open() another update from management arrives with peers: [1,2,3]
		// engine removes peer 4 and calls conn.Close() which does nothing (this default clause)
		// before conn.Open() another update from management arrives with peers: [1,2,3,4,5]
		// engine adds a new Conn for 4 and 5
		// therefore peer 4 has 2 Conn objects
		log.Warnf("Connection has been already closed or attempted closing not started connection %s", conn.config.Key)
		return NewConnectionAlreadyClosed(conn.config.Key)
	}
}

// Status returns current status of the Conn
func (conn *Conn) Status() ConnStatus {
	conn.mu.Lock()
	defer conn.mu.Unlock()
	return conn.status
}

// OnRemoteOffer handles an offer from the remote peer and returns true if the message was accepted, false otherwise
// doesn't block, discards the message if connection wasn't ready
func (conn *Conn) OnRemoteOffer(offer OfferAnswer) bool {
	log.Debugf("OnRemoteOffer from peer %s on status %s", conn.config.Key, conn.status.String())

	select {
	case conn.remoteOffersCh <- offer:
		return true
	default:
		log.Debugf("OnRemoteOffer skipping message from peer %s on status %s because is not ready", conn.config.Key, conn.status.String())
		// connection might not be ready yet to receive so we ignore the message
		return false
	}
}

// OnRemoteAnswer handles an offer from the remote peer and returns true if the message was accepted, false otherwise
// doesn't block, discards the message if connection wasn't ready
func (conn *Conn) OnRemoteAnswer(answer OfferAnswer) bool {
	log.Debugf("OnRemoteAnswer from peer %s on status %s", conn.config.Key, conn.status.String())

	select {
	case conn.remoteAnswerCh <- answer:
		return true
	default:
		// connection might not be ready yet to receive so we ignore the message
		log.Debugf("OnRemoteAnswer skipping message from peer %s on status %s because is not ready", conn.config.Key, conn.status.String())
		return false
	}
}

// OnRemoteCandidate Handles ICE connection Candidate provided by the remote peer.
func (conn *Conn) OnRemoteCandidate(candidate ice.Candidate) {
	log.Debugf("OnRemoteCandidate from peer %s -> %s", conn.config.Key, candidate.String())
	go func() {
		conn.mu.Lock()
		defer conn.mu.Unlock()

		if conn.agent == nil {
			return
		}

		err := conn.agent.AddRemoteCandidate(candidate)
		if err != nil {
			log.Errorf("error while handling remote candidate from peer %s", conn.config.Key)
			return
		}
	}()
}

func (conn *Conn) GetKey() string {
	return conn.config.Key
}

// RegisterProtoSupportMeta register supported proto message in the connection metadata
func (conn *Conn) RegisterProtoSupportMeta(support []uint32) {
	protoSupport := signal.ParseFeaturesSupported(support)
	conn.meta.protoSupport = protoSupport
}
