package connection

import (
	"fmt"
	"github.com/cenkalti/backoff/v4"
	ice "github.com/pion/ice/v2"
	log "github.com/sirupsen/logrus"
	"github.com/wiretrustee/wiretrustee/iface"
	"github.com/wiretrustee/wiretrustee/signal"
	sProto "github.com/wiretrustee/wiretrustee/signal/proto"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"time"
)

// Engine is an instance of the Connection Engine
type Engine struct {
	// a list of STUN and TURN servers
	stunsTurns []*ice.URL
	// signal server client
	signal *signal.Client
	// peer agents indexed by local public key of the remote peers
	conns map[string]*Connection
	// peer agents connection control channel
	connsControllers map[string]peerConnStop
	// Wireguard interface
	wgIface string
	// Wireguard local address
	wgIP string
	// Network Interfaces to ignore
	iFaceBlackList map[string]struct{}
}

// Peer is an instance of the Connection Peer
type Peer struct {
	WgPubKey     string
	WgAllowedIps string
}

// controls when to stop peer connection and retries
type peerConnStop chan struct{}

// NewEngine creates a new Connection Engine
func NewEngine(signal *signal.Client, stunsTurns []*ice.URL, wgIface string, wgAddr string,
	iFaceBlackList map[string]struct{}) *Engine {
	return &Engine{
		stunsTurns:       stunsTurns,
		signal:           signal,
		wgIface:          wgIface,
		wgIP:             wgAddr,
		conns:            map[string]*Connection{},
		connsControllers: make(map[string]peerConnStop),
		iFaceBlackList:   iFaceBlackList,
	}
}

// Start creates a new tunnel interface and listens to signals from the Signal service.
// It also creates an Go routine to handle each peer communication from the config file
func (e *Engine) Start(myKey wgtypes.Key, peers []Peer) error {

	err := iface.Create(e.wgIface, e.wgIP)
	if err != nil {
		log.Errorf("error while creating interface %s: [%s]", e.wgIface, err.Error())
		return err
	}

	err = iface.Configure(e.wgIface, myKey.String())
	if err != nil {
		log.Errorf("error while configuring Wireguard interface [%s]: %s", e.wgIface, err.Error())
		return err
	}

	wgPort, err := iface.GetListenPort(e.wgIface)
	if err != nil {
		log.Errorf("error while getting Wireguard interface port [%s]: %s", e.wgIface, err.Error())
		return err
	}

	e.receiveSignal()

	for _, peer := range peers {
		peer := peer
		go e.InitializePeer(*wgPort, myKey, peer)
	}
	return nil
}

// initialize peer agent attempt to close connection
func (e *Engine) InitializePeer(wgPort int, myKey wgtypes.Key, peer Peer) {
	var backOff = &backoff.ExponentialBackOff{
		InitialInterval:     backoff.DefaultInitialInterval,
		RandomizationFactor: backoff.DefaultRandomizationFactor,
		Multiplier:          backoff.DefaultMultiplier,
		MaxInterval:         5 * time.Second,
		MaxElapsedTime:      time.Duration(0), //never stop
		Stop:                backoff.Stop,
		Clock:               backoff.SystemClock,
	}
	e.connsControllers[peer.WgPubKey] = make(chan struct{})
	operation := func() error {
		_, err := e.openPeerConnection(wgPort, myKey, peer)
		if err != nil {
			log.Warnln(err)
			log.Warnln("retrying connection because of error: ", err.Error())
			e.conns[peer.WgPubKey] = nil
			return err
		}
		log.Infof("removing connection with Peer: %v, not retrying", peer.WgPubKey)

		// Cleanup maps
		delete(e.conns, peer.WgPubKey)
		delete(e.connsControllers, peer.WgPubKey)

		backOff.Reset()
		return nil
	}

	err := backoff.Retry(operation, backOff)
	if err != nil {
		// should actually never happen
		panic(err)
	}
}

// close existing peer connection attempt
func (e *Engine) ClosePeerConnection(peer Peer) error {
	conn, exists := e.conns[peer.WgPubKey]
	if exists && conn != nil {
		close(e.connsControllers[peer.WgPubKey])
		return conn.Close()
	}
	return nil
}

// opens a new peer connection
func (e *Engine) openPeerConnection(wgPort int, myKey wgtypes.Key, peer Peer) (*Connection, error) {

	remoteKey, _ := wgtypes.ParseKey(peer.WgPubKey)
	connConfig := &ConnConfig{
		WgListenAddr:   fmt.Sprintf("127.0.0.1:%d", wgPort),
		WgPeerIP:       e.wgIP,
		WgIface:        e.wgIface,
		WgAllowedIPs:   peer.WgAllowedIps,
		WgKey:          myKey,
		RemoteWgKey:    remoteKey,
		StunTurnURLS:   e.stunsTurns,
		iFaceBlackList: e.iFaceBlackList,
	}

	signalOffer := func(uFrag string, pwd string) error {
		return signalAuth(uFrag, pwd, myKey, remoteKey, e.signal, false)
	}

	signalAnswer := func(uFrag string, pwd string) error {
		return signalAuth(uFrag, pwd, myKey, remoteKey, e.signal, true)
	}
	signalCandidate := func(candidate ice.Candidate) error {
		return signalCandidate(candidate, myKey, remoteKey, e.signal)
	}
	conn := NewConnection(*connConfig, signalCandidate, signalOffer, signalAnswer)
	e.conns[remoteKey.String()] = conn

	select {
	// did we received stop retrying signal?
	case <-e.connsControllers[remoteKey.String()]:
		log.Infoln("received stop retrying signal for: ", remoteKey.String())
	// opens a connection if is allowed to retry
	default:
		// blocks until the connection is open (or timeout)
		err := conn.Open(60 * time.Second)
		if err != nil {
			return nil, err
		}
	}
	return conn, nil
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

func (e *Engine) receiveSignal() {
	// connect to a stream of messages coming from the signal server
	e.signal.Receive(func(msg *sProto.Message) error {

		conn := e.conns[msg.Key]
		if conn == nil {
			return fmt.Errorf("wrongly addressed message %s", msg.Key)
		}

		if conn.Config.RemoteWgKey.String() != msg.Key {
			return fmt.Errorf("unknown peer %s", msg.Key)
		}

		switch msg.GetBody().Type {
		case sProto.Body_OFFER:
			remoteCred, err := signal.UnMarshalCredential(msg)
			if err != nil {
				return err
			}
			err = conn.OnOffer(IceCredentials{
				uFrag: remoteCred.UFrag,
				pwd:   remoteCred.Pwd,
			})

			if err != nil {
				return err
			}

			return nil
		case sProto.Body_ANSWER:
			remoteCred, err := signal.UnMarshalCredential(msg)
			if err != nil {
				return err
			}
			err = conn.OnAnswer(IceCredentials{
				uFrag: remoteCred.UFrag,
				pwd:   remoteCred.Pwd,
			})

			if err != nil {
				return err
			}

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

	e.signal.WaitConnected()
}
