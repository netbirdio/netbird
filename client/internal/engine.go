package internal

import (
	"context"
	"fmt"
	"math/rand"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/pion/ice/v2"
	log "github.com/sirupsen/logrus"
	"github.com/wiretrustee/wiretrustee/client/internal/peer"
	"github.com/wiretrustee/wiretrustee/client/internal/proxy"
	"github.com/wiretrustee/wiretrustee/iface"
	mgm "github.com/wiretrustee/wiretrustee/management/client"
	mgmProto "github.com/wiretrustee/wiretrustee/management/proto"
	signal "github.com/wiretrustee/wiretrustee/signal/client"
	sProto "github.com/wiretrustee/wiretrustee/signal/proto"
	"github.com/wiretrustee/wiretrustee/util"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// PeerConnectionTimeoutMax is a timeout of an initial connection attempt to a remote peer.
// E.g. this peer will wait PeerConnectionTimeoutMax for the remote peer to respond,
// if not successful then it will retry the connection attempt.
// Todo pass timeout at EnginConfig
const (
	PeerConnectionTimeoutMax = 45000 // ms
	PeerConnectionTimeoutMin = 30000 // ms
)

var ErrResetConnection = fmt.Errorf("reset connection")

// EngineConfig is a config for the Engine
type EngineConfig struct {
	WgPort      int
	WgIfaceName string

	// WgAddr is a Wireguard local address (Wiretrustee Network IP)
	WgAddr string

	// WgPrivateKey is a Wireguard private key of our peer (it MUST never leave the machine)
	WgPrivateKey wgtypes.Key

	// IFaceBlackList is a list of network interfaces to ignore when discovering connection candidates (ICE related)
	IFaceBlackList map[string]struct{}

	PreSharedKey *wgtypes.Key

	// UDPMuxPort default value 0 - the system will pick an available port
	UDPMuxPort int

	// UDPMuxSrflxPort default value 0 - the system will pick an available port
	UDPMuxSrflxPort int
}

// Engine is a mechanism responsible for reacting on Signal and Management stream events and managing connections to the remote peers.
type Engine struct {
	// signal is a Signal Service client
	signal signal.Client
	// mgmClient is a Management Service client
	mgmClient mgm.Client
	// peerConns is a map that holds all the peers that are known to this peer
	peerConns map[string]*peer.Conn

	// syncMsgMux is used to guarantee sequential Management Service message processing
	syncMsgMux *sync.Mutex

	config *EngineConfig
	// STUNs is a list of STUN servers used by ICE
	STUNs []*ice.URL
	// TURNs is a list of STUN servers used by ICE
	TURNs []*ice.URL

	cancel context.CancelFunc

	ctx context.Context

	wgInterface iface.WGIface

	udpMux          ice.UDPMux
	udpMuxSrflx     ice.UniversalUDPMux
	udpMuxConn      *net.UDPConn
	udpMuxConnSrflx *net.UDPConn

	// networkSerial is the latest Serial (state ID) of the network sent by the Management service
	networkSerial uint64
}

// Peer is an instance of the Connection Peer
type Peer struct {
	WgPubKey     string
	WgAllowedIps string
}

// NewEngine creates a new Connection Engine
func NewEngine(
	ctx context.Context, cancel context.CancelFunc,
	signalClient signal.Client, mgmClient mgm.Client, config *EngineConfig,
) *Engine {
	return &Engine{
		ctx:           ctx,
		cancel:        cancel,
		signal:        signalClient,
		mgmClient:     mgmClient,
		peerConns:     map[string]*peer.Conn{},
		syncMsgMux:    &sync.Mutex{},
		config:        config,
		STUNs:         []*ice.URL{},
		TURNs:         []*ice.URL{},
		networkSerial: 0,
	}
}

func (e *Engine) Stop() error {
	e.syncMsgMux.Lock()
	defer e.syncMsgMux.Unlock()

	err := e.removeAllPeers()
	if err != nil {
		return err
	}

	log.Debugf("removing Wiretrustee interface %s", e.config.WgIfaceName)
	if e.wgInterface.Interface != nil {
		err = e.wgInterface.Close()
		if err != nil {
			log.Errorf("failed closing Wiretrustee interface %s %v", e.config.WgIfaceName, err)
			return err
		}
	}

	if e.udpMux != nil {
		if err := e.udpMux.Close(); err != nil {
			log.Debugf("close udp mux: %v", err)
		}
	}

	if e.udpMuxSrflx != nil {
		if err := e.udpMuxSrflx.Close(); err != nil {
			log.Debugf("close server reflexive udp mux: %v", err)
		}
	}

	if e.udpMuxConn != nil {
		if err := e.udpMuxConn.Close(); err != nil {
			log.Debugf("close udp mux connection: %v", err)
		}
	}

	if e.udpMuxConnSrflx != nil {
		if err := e.udpMuxConnSrflx.Close(); err != nil {
			log.Debugf("close server reflexive udp mux connection: %v", err)
		}
	}

	log.Infof("stopped Wiretrustee Engine")

	return nil
}

// Start creates a new Wireguard tunnel interface and listens to events from Signal and Management services
// Connections to remote peers are not established here.
// However, they will be established once an event with a list of peers to connect to will be received from Management Service
func (e *Engine) Start() error {
	e.syncMsgMux.Lock()
	defer e.syncMsgMux.Unlock()

	wgIfaceName := e.config.WgIfaceName
	wgAddr := e.config.WgAddr
	myPrivateKey := e.config.WgPrivateKey
	var err error

	e.wgInterface, err = iface.NewWGIface(wgIfaceName, wgAddr, iface.DefaultMTU)
	if err != nil {
		log.Errorf("failed creating wireguard interface instance %s: [%s]", wgIfaceName, err.Error())
		return err
	}

	e.udpMuxConn, err = net.ListenUDP("udp4", &net.UDPAddr{Port: e.config.UDPMuxPort})
	if err != nil {
		log.Errorf("failed listening on UDP port %d: [%s]", e.config.UDPMuxPort, err.Error())
		return err
	}

	e.udpMuxConnSrflx, err = net.ListenUDP("udp4", &net.UDPAddr{Port: e.config.UDPMuxSrflxPort})
	if err != nil {
		log.Errorf("failed listening on UDP port %d: [%s]", e.config.UDPMuxSrflxPort, err.Error())
		return err
	}

	e.udpMux = ice.NewUDPMuxDefault(ice.UDPMuxParams{UDPConn: e.udpMuxConn})
	e.udpMuxSrflx = ice.NewUniversalUDPMuxDefault(ice.UniversalUDPMuxParams{UDPConn: e.udpMuxConnSrflx})

	err = e.wgInterface.Create()
	if err != nil {
		log.Errorf("failed creating tunnel interface %s: [%s]", wgIfaceName, err.Error())
		return err
	}

	err = e.wgInterface.Configure(myPrivateKey.String(), e.config.WgPort)
	if err != nil {
		log.Errorf("failed configuring Wireguard interface [%s]: %s", wgIfaceName, err.Error())
		return err
	}

	e.receiveSignalEvents()
	e.receiveManagementEvents()

	return nil
}

// removePeers finds and removes peers that do not exist anymore in the network map received from the Management Service
func (e *Engine) removePeers(peersUpdate []*mgmProto.RemotePeerConfig) error {
	currentPeers := make([]string, 0, len(e.peerConns))
	for p := range e.peerConns {
		currentPeers = append(currentPeers, p)
	}

	newPeers := make([]string, 0, len(peersUpdate))
	for _, p := range peersUpdate {
		newPeers = append(newPeers, p.GetWgPubKey())
	}

	toRemove := util.SliceDiff(currentPeers, newPeers)

	for _, p := range toRemove {
		err := e.removePeer(p)
		if err != nil {
			return err
		}
		log.Infof("removed peer %s", p)
	}
	return nil
}

func (e *Engine) removeAllPeers() error {
	log.Debugf("removing all peer connections")
	for p := range e.peerConns {
		err := e.removePeer(p)
		if err != nil {
			return err
		}
	}
	return nil
}

// removePeer closes an existing peer connection and removes a peer
func (e *Engine) removePeer(peerKey string) error {
	log.Debugf("removing peer from engine %s", peerKey)
	conn, exists := e.peerConns[peerKey]
	if exists {
		delete(e.peerConns, peerKey)
		err := conn.Close()
		if err != nil {
			switch err.(type) {
			case *peer.ConnectionAlreadyClosedError:
				return nil
			default:
				return err
			}
		}
	}
	return nil
}

// GetPeerConnectionStatus returns a connection Status or nil if peer connection wasn't found
func (e *Engine) GetPeerConnectionStatus(peerKey string) peer.ConnStatus {
	conn, exists := e.peerConns[peerKey]
	if exists && conn != nil {
		return conn.Status()
	}

	return -1
}

func (e *Engine) GetPeers() []string {
	e.syncMsgMux.Lock()
	defer e.syncMsgMux.Unlock()

	peers := []string{}
	for s := range e.peerConns {
		peers = append(peers, s)
	}
	return peers
}

// GetConnectedPeers returns a connection Status or nil if peer connection wasn't found
func (e *Engine) GetConnectedPeers() []string {
	e.syncMsgMux.Lock()
	defer e.syncMsgMux.Unlock()

	peers := []string{}
	for s, conn := range e.peerConns {
		if conn.Status() == peer.StatusConnected {
			peers = append(peers, s)
		}
	}

	return peers
}

func signalCandidate(candidate ice.Candidate, myKey wgtypes.Key, remoteKey wgtypes.Key, s signal.Client) error {
	err := s.Send(&sProto.Message{
		Key:       myKey.PublicKey().String(),
		RemoteKey: remoteKey.String(),
		Body: &sProto.Body{
			Type:    sProto.Body_CANDIDATE,
			Payload: candidate.Marshal(),
		},
	})
	if err != nil {
		log.Errorf("failed signaling candidate to the remote peer %s %s", remoteKey.String(), err)
		// todo ??
		return err
	}

	return nil
}

func signalAuth(uFrag string, pwd string, myKey wgtypes.Key, remoteKey wgtypes.Key, s signal.Client, isAnswer bool) error {
	var t sProto.Body_Type
	if isAnswer {
		t = sProto.Body_ANSWER
	} else {
		t = sProto.Body_OFFER
	}

	msg, err := signal.MarshalCredential(myKey, remoteKey, &signal.Credential{
		UFrag: uFrag,
		Pwd:   pwd,
	}, t)
	if err != nil {
		return err
	}
	err = s.Send(msg)
	if err != nil {
		return err
	}

	return nil
}

func (e *Engine) handleSync(update *mgmProto.SyncResponse) error {
	e.syncMsgMux.Lock()
	defer e.syncMsgMux.Unlock()

	if update.GetWiretrusteeConfig() != nil {
		err := e.updateTURNs(update.GetWiretrusteeConfig().GetTurns())
		if err != nil {
			return err
		}

		err = e.updateSTUNs(update.GetWiretrusteeConfig().GetStuns())
		if err != nil {
			return err
		}

		// todo update signal
	}

	if update.GetNetworkMap() != nil {
		// only apply new changes and ignore old ones
		err := e.updateNetworkMap(update.GetNetworkMap())
		if err != nil {
			return err
		}
	}

	return nil
}

// receiveManagementEvents connects to the Management Service event stream to receive updates from the management service
// E.g. when a new peer has been registered and we are allowed to connect to it.
func (e *Engine) receiveManagementEvents() {
	go func() {
		err := e.mgmClient.Sync(func(update *mgmProto.SyncResponse) error {
			return e.handleSync(update)
		})
		if err != nil {
			// happens if management is unavailable for a long time.
			// We want to cancel the operation of the whole client
			_ = CtxGetState(e.ctx).Wrap(ErrResetConnection)
			e.cancel()
			return
		}
		log.Debugf("stopped receiving updates from Management Service")
	}()
	log.Debugf("connecting to Management Service updates stream")
}

func (e *Engine) updateSTUNs(stuns []*mgmProto.HostConfig) error {
	if len(stuns) == 0 {
		return nil
	}
	var newSTUNs []*ice.URL
	log.Debugf("got STUNs update from Management Service, updating")
	for _, stun := range stuns {
		url, err := ice.ParseURL(stun.Uri)
		if err != nil {
			return err
		}
		newSTUNs = append(newSTUNs, url)
	}
	e.STUNs = newSTUNs

	return nil
}

func (e *Engine) updateTURNs(turns []*mgmProto.ProtectedHostConfig) error {
	if len(turns) == 0 {
		return nil
	}
	var newTURNs []*ice.URL
	log.Debugf("got TURNs update from Management Service, updating")
	for _, turn := range turns {
		url, err := ice.ParseURL(turn.HostConfig.Uri)
		if err != nil {
			return err
		}
		url.Username = turn.User
		url.Password = turn.Password
		newTURNs = append(newTURNs, url)
	}
	e.TURNs = newTURNs

	return nil
}

func (e *Engine) updateNetworkMap(networkMap *mgmProto.NetworkMap) error {
	serial := networkMap.GetSerial()
	if e.networkSerial > serial {
		log.Debugf("received outdated NetworkMap with serial %d, ignoring", serial)
		return nil
	}

	log.Debugf("got peers update from Management Service, total peers to connect to = %d", len(networkMap.GetRemotePeers()))

	// cleanup request, most likely our peer has been deleted
	if networkMap.GetRemotePeersIsEmpty() {
		err := e.removeAllPeers()
		if err != nil {
			return err
		}
	} else {
		err := e.removePeers(networkMap.GetRemotePeers())
		if err != nil {
			return err
		}

		err = e.addNewPeers(networkMap.GetRemotePeers())
		if err != nil {
			return err
		}
	}

	e.networkSerial = serial
	return nil
}

// addNewPeers finds and adds peers that were not know before but arrived from the Management service with the update
func (e *Engine) addNewPeers(peersUpdate []*mgmProto.RemotePeerConfig) error {
	for _, p := range peersUpdate {
		peerKey := p.GetWgPubKey()
		peerIPs := p.GetAllowedIps()
		if _, ok := e.peerConns[peerKey]; !ok {
			conn, err := e.createPeerConn(peerKey, strings.Join(peerIPs, ","))
			if err != nil {
				return err
			}
			e.peerConns[peerKey] = conn

			go e.connWorker(conn, peerKey)
		}

	}
	return nil
}

func (e Engine) connWorker(conn *peer.Conn, peerKey string) {
	for {

		// randomize starting time a bit
		min := 500
		max := 2000
		time.Sleep(time.Duration(rand.Intn(max-min)+min) * time.Millisecond)

		// if peer has been removed -> give up
		if !e.peerExists(peerKey) {
			log.Infof("peer %s doesn't exist anymore, won't retry connection", peerKey)
			return
		}

		if !e.signal.Ready() {
			log.Infof("signal client isn't ready, skipping connection attempt %s", peerKey)
			continue
		}

		err := conn.Open()
		if err != nil {
			log.Debugf("connection to peer %s failed: %v", peerKey, err)
		}
	}
}

func (e Engine) peerExists(peerKey string) bool {
	e.syncMsgMux.Lock()
	defer e.syncMsgMux.Unlock()
	_, ok := e.peerConns[peerKey]
	return ok
}

func (e Engine) createPeerConn(pubKey string, allowedIPs string) (*peer.Conn, error) {
	var stunTurn []*ice.URL
	stunTurn = append(stunTurn, e.STUNs...)
	stunTurn = append(stunTurn, e.TURNs...)

	interfaceBlacklist := make([]string, 0, len(e.config.IFaceBlackList))
	for k := range e.config.IFaceBlackList {
		interfaceBlacklist = append(interfaceBlacklist, k)
	}

	proxyConfig := proxy.Config{
		RemoteKey:    pubKey,
		WgListenAddr: fmt.Sprintf("127.0.0.1:%d", e.config.WgPort),
		WgInterface:  e.wgInterface,
		AllowedIps:   allowedIPs,
		PreSharedKey: e.config.PreSharedKey,
	}

	// randomize connection timeout
	timeout := time.Duration(rand.Intn(PeerConnectionTimeoutMax-PeerConnectionTimeoutMin)+PeerConnectionTimeoutMin) * time.Millisecond
	config := peer.ConnConfig{
		Key:                pubKey,
		LocalKey:           e.config.WgPrivateKey.PublicKey().String(),
		StunTurn:           stunTurn,
		InterfaceBlackList: interfaceBlacklist,
		Timeout:            timeout,
		UDPMux:             e.udpMux,
		UDPMuxSrflx:        e.udpMuxSrflx,
		ProxyConfig:        proxyConfig,
	}

	peerConn, err := peer.NewConn(config)
	if err != nil {
		return nil, err
	}

	wgPubKey, err := wgtypes.ParseKey(pubKey)
	if err != nil {
		return nil, err
	}

	signalOffer := func(uFrag string, pwd string) error {
		return signalAuth(uFrag, pwd, e.config.WgPrivateKey, wgPubKey, e.signal, false)
	}

	signalCandidate := func(candidate ice.Candidate) error {
		return signalCandidate(candidate, e.config.WgPrivateKey, wgPubKey, e.signal)
	}

	signalAnswer := func(uFrag string, pwd string) error {
		return signalAuth(uFrag, pwd, e.config.WgPrivateKey, wgPubKey, e.signal, true)
	}

	peerConn.SetSignalCandidate(signalCandidate)
	peerConn.SetSignalOffer(signalOffer)
	peerConn.SetSignalAnswer(signalAnswer)

	return peerConn, nil
}

// receiveSignalEvents connects to the Signal Service event stream to negotiate connection with remote peers
func (e *Engine) receiveSignalEvents() {
	go func() {
		// connect to a stream of messages coming from the signal server
		err := e.signal.Receive(func(msg *sProto.Message) error {
			e.syncMsgMux.Lock()
			defer e.syncMsgMux.Unlock()

			conn := e.peerConns[msg.Key]
			if conn == nil {
				return fmt.Errorf("wrongly addressed message %s", msg.Key)
			}

			switch msg.GetBody().Type {
			case sProto.Body_OFFER:
				remoteCred, err := signal.UnMarshalCredential(msg)
				if err != nil {
					return err
				}
				conn.OnRemoteOffer(peer.IceCredentials{
					UFrag: remoteCred.UFrag,
					Pwd:   remoteCred.Pwd,
				})
			case sProto.Body_ANSWER:
				remoteCred, err := signal.UnMarshalCredential(msg)
				if err != nil {
					return err
				}
				conn.OnRemoteAnswer(peer.IceCredentials{
					UFrag: remoteCred.UFrag,
					Pwd:   remoteCred.Pwd,
				})
			case sProto.Body_CANDIDATE:
				candidate, err := ice.UnmarshalCandidate(msg.GetBody().Payload)
				if err != nil {
					log.Errorf("failed on parsing remote candidate %s -> %s", candidate, err)
					return err
				}
				conn.OnRemoteCandidate(candidate)
			}

			return nil
		})
		if err != nil {
			// happens if signal is unavailable for a long time.
			// We want to cancel the operation of the whole client
			_ = CtxGetState(e.ctx).Wrap(ErrResetConnection)
			e.cancel()
			return
		}
	}()

	e.signal.WaitStreamConnected()
}
