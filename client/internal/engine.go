package internal

import (
	"context"
	"fmt"
	"github.com/pion/ice/v2"
	log "github.com/sirupsen/logrus"
	"github.com/wiretrustee/wiretrustee/client/internal/peer"
	"github.com/wiretrustee/wiretrustee/client/internal/proxy"
	"github.com/wiretrustee/wiretrustee/iface"
	mgm "github.com/wiretrustee/wiretrustee/management/client"
	mgmProto "github.com/wiretrustee/wiretrustee/management/proto"
	signal "github.com/wiretrustee/wiretrustee/signal/client"
	sProto "github.com/wiretrustee/wiretrustee/signal/proto"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"math/rand"
	"strings"
	"sync"
	"time"
)

// PeerConnectionTimeoutMax is a timeout of an initial connection attempt to a remote peer.
// E.g. this peer will wait PeerConnectionTimeoutMax for the remote peer to respond, if not successful then it will retry the connection attempt.
const PeerConnectionTimeoutMax = 45 //sec
const PeerConnectionTimeoutMin = 30 //sec

const WgPort = 51820

// EngineConfig is a config for the Engine
type EngineConfig struct {
	WgPort  int
	WgIface string
	// WgAddr is a Wireguard local address (Wiretrustee Network IP)
	WgAddr string
	// WgPrivateKey is a Wireguard private key of our peer (it MUST never leave the machine)
	WgPrivateKey wgtypes.Key
	// IFaceBlackList is a list of network interfaces to ignore when discovering connection candidates (ICE related)
	IFaceBlackList map[string]struct{}

	PreSharedKey *wgtypes.Key
}

// Engine is a mechanism responsible for reacting on Signal and Management stream events and managing connections to the remote peers.
type Engine struct {
	// signal is a Signal Service client
	signal *signal.Client
	// mgmClient is a Management Service client
	mgmClient *mgm.Client
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
}

// Peer is an instance of the Connection Peer
type Peer struct {
	WgPubKey     string
	WgAllowedIps string
}

// NewEngine creates a new Connection Engine
func NewEngine(signalClient *signal.Client, mgmClient *mgm.Client, config *EngineConfig, cancel context.CancelFunc, ctx context.Context) *Engine {
	return &Engine{
		signal:     signalClient,
		mgmClient:  mgmClient,
		peerConns:  map[string]*peer.Conn{},
		syncMsgMux: &sync.Mutex{},
		config:     config,
		STUNs:      []*ice.URL{},
		TURNs:      []*ice.URL{},
		cancel:     cancel,
		ctx:        ctx,
	}
}

func (e *Engine) Stop() error {
	e.syncMsgMux.Lock()
	defer e.syncMsgMux.Unlock()

	err := e.removeAllPeerConnections()
	if err != nil {
		return err
	}

	log.Debugf("removing Wiretrustee interface %s", e.config.WgIface)
	err = iface.Close(e.config.WgPort)
	if err != nil {
		log.Errorf("failed closing Wiretrustee interface %s %v", e.config.WgIface, err)
		return err
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

	wgIface := e.config.WgIface
	wgAddr := e.config.WgAddr
	myPrivateKey := e.config.WgPrivateKey

	err := iface.Create(wgIface, wgAddr)
	if err != nil {
		log.Errorf("failed creating interface %s: [%s]", wgIface, err.Error())
		return err
	}

	err = iface.Configure(wgIface, myPrivateKey.String(), e.config.WgPort)
	if err != nil {
		log.Errorf("failed configuring Wireguard interface [%s]: %s", wgIface, err.Error())
		return err
	}

	e.receiveSignalEvents()
	e.receiveManagementEvents()

	return nil
}

func (e *Engine) removePeers(peers []string) error {
	for _, p := range peers {
		err := e.removePeer(p)
		if err != nil {
			return err
		}
		log.Infof("removed peer %s", p)
	}
	return nil
}

func (e *Engine) removeAllPeerConnections() error {
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
	conn, exists := e.peerConns[peerKey]
	if exists {
		delete(e.peerConns, peerKey)
		return conn.Close()
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

func signalCandidate(candidate ice.Candidate, myKey wgtypes.Key, remoteKey wgtypes.Key, s *signal.Client) error {
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
		//todo ??
		return err
	}

	return nil
}

func signalAuth(uFrag string, pwd string, myKey wgtypes.Key, remoteKey wgtypes.Key, s *signal.Client, isAnswer bool) error {

	var t sProto.Body_Type
	if isAnswer {
		t = sProto.Body_ANSWER
	} else {
		t = sProto.Body_OFFER
	}

	msg, err := signal.MarshalCredential(myKey, remoteKey, &signal.Credential{
		UFrag: uFrag,
		Pwd:   pwd}, t)
	if err != nil {
		return err
	}
	err = s.Send(msg)
	if err != nil {
		return err
	}

	return nil
}

// receiveManagementEvents connects to the Management Service event stream to receive updates from the management service
// E.g. when a new peer has been registered and we are allowed to connect to it.
func (e *Engine) receiveManagementEvents() {
	go func() {
		err := e.mgmClient.Sync(func(update *mgmProto.SyncResponse) error {
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

				//todo update signal
			}

			if update.GetRemotePeers() != nil || update.GetRemotePeersIsEmpty() {
				// empty arrays are serialized by protobuf to null, but for our case empty array is a valid state.
				err := e.updatePeers(update.GetRemotePeers())
				if err != nil {
					return err
				}
			}

			return nil
		})
		if err != nil {
			// happens if management is unavailable for a long time.
			// We want to cancel the operation of the whole client
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

func (e *Engine) updatePeers(remotePeers []*mgmProto.RemotePeerConfig) error {
	log.Debugf("got peers update from Management Service, total peers to connect to = %d", len(remotePeers))
	remotePeerMap := make(map[string]struct{})
	for _, p := range remotePeers {
		remotePeerMap[p.GetWgPubKey()] = struct{}{}
	}

	//remove peers that are no longer available for us
	toRemove := []string{}
	for p := range e.peerConns {
		if _, ok := remotePeerMap[p]; !ok {
			toRemove = append(toRemove, p)
		}
	}
	err := e.removePeers(toRemove)
	if err != nil {
		return err
	}

	// add new peers
	for _, p := range remotePeers {
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
		max := 1500
		time.Sleep(time.Duration(rand.Intn(max-min)+min) * time.Millisecond)

		// of peer has been removed -> give up
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
	for k, _ := range e.config.IFaceBlackList {
		interfaceBlacklist = append(interfaceBlacklist, k)
	}

	proxyConfig := proxy.Config{
		RemoteKey:    pubKey,
		WgListenAddr: fmt.Sprintf("127.0.0.1:%d", e.config.WgPort),
		WgInterface:  e.config.WgIface,
		AllowedIps:   allowedIPs,
		PreSharedKey: e.config.PreSharedKey,
	}

	config := peer.ConnConfig{
		Key:                pubKey,
		LocalKey:           e.config.WgPrivateKey.PublicKey().String(),
		StunTurn:           stunTurn,
		InterfaceBlackList: interfaceBlacklist,
		Timeout:            35 * time.Second,
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

			conn, ok := e.peerConns[msg.Key]
			if !ok {
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

				return nil
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

				err = conn.OnRemoteCandidate(candidate)
				if err != nil {
					log.Errorf("error handling CANDIATE from %s", msg.Key)
					return err
				}
			}

			return nil
		})
		if err != nil {
			// happens if signal is unavailable for a long time.
			// We want to cancel the operation of the whole client
			e.cancel()
			return
		}
	}()

	e.signal.WaitStreamConnected()
}
