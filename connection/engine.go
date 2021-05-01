package connection

import (
	"fmt"
	"github.com/cenkalti/backoff/v4"
	"github.com/pion/ice/v2"
	log "github.com/sirupsen/logrus"
	"github.com/wiretrustee/wiretrustee/iface"
	"github.com/wiretrustee/wiretrustee/signal"
	sProto "github.com/wiretrustee/wiretrustee/signal/proto"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"time"
)

type Engine struct {
	// a list of STUN and TURN servers
	stunsTurns []*ice.URL
	// signal server client
	signal *signal.Client
	// peer agents indexed by local public key of the remote peers
	conns map[string]*Connection
	// Wireguard interface
	wgIface string
	// Wireguard local address
	wgIp string
}

type Peer struct {
	WgPubKey     string
	WgAllowedIps string
}

func NewEngine(signal *signal.Client, stunsTurns []*ice.URL, wgIface string, wgAddr string) *Engine {
	return &Engine{
		stunsTurns: stunsTurns,
		signal:     signal,
		wgIface:    wgIface,
		wgIp:       wgAddr,
		conns:      map[string]*Connection{},
	}
}

func (e *Engine) Start(myKey wgtypes.Key, peers []Peer) error {

	err := iface.Create(e.wgIface, e.wgIp)
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

	e.receiveSignal(myKey.PublicKey().String())

	// initialize peer agents
	for _, peer := range peers {

		peer := peer
		go func() {
			var backOff = &backoff.ExponentialBackOff{
				InitialInterval:     backoff.DefaultInitialInterval,
				RandomizationFactor: backoff.DefaultRandomizationFactor,
				Multiplier:          backoff.DefaultMultiplier,
				MaxInterval:         5 * time.Second,
				MaxElapsedTime:      time.Duration(0), //never stop
				Stop:                backoff.Stop,
				Clock:               backoff.SystemClock,
			}
			operation := func() error {
				_, err := e.openPeerConnection(*wgPort, myKey, peer)
				if err != nil {
					log.Warnln("retrying connection because of error: ", err.Error())
					e.conns[peer.WgPubKey] = nil
					return err
				}
				backOff.Reset()
				return nil
			}

			err = backoff.Retry(operation, backOff)
			if err != nil {
				// should actually never happen
				panic(err)
			}
		}()
	}
	return nil
}

func (e *Engine) openPeerConnection(wgPort int, myKey wgtypes.Key, peer Peer) (*Connection, error) {

	remoteKey, _ := wgtypes.ParseKey(peer.WgPubKey)
	connConfig := &ConnConfig{
		WgListenAddr: fmt.Sprintf("127.0.0.1:%d", wgPort),
		WgPeerIp:     e.wgIp,
		WgIface:      e.wgIface,
		WgAllowedIPs: peer.WgAllowedIps,
		WgKey:        myKey,
		RemoteWgKey:  remoteKey,
		StunTurnURLS: e.stunsTurns,
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
	// blocks until the connection is open (or timeout)
	err := conn.Open(60 * time.Second)
	if err != nil {
		return nil, err
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

	err = s.Send(msg)
	if err != nil {
		return err
	}

	return nil
}

func (e *Engine) receiveSignal(localKey string) {
	// connect to a stream of messages coming from the signal server
	e.signal.Receive(localKey, func(msg *sProto.Message) error {

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
