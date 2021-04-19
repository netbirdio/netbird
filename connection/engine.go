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

func (e *Engine) Start(privateKey string, peers []Peer) error {

	// setup wireguard
	myKey, err := wgtypes.ParseKey(privateKey)
	myPubKey := myKey.PublicKey().String()
	if err != nil {
		log.Errorf("error parsing Wireguard key %s: [%s]", privateKey, err.Error())
		return err
	}

	err = iface.Create(e.wgIface, e.wgIp)
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

	e.receiveSignal(myPubKey)

	// initialize peer agents
	for _, peer := range peers {

		peer := peer
		go func() {

			operation := func() error {
				_, closed, err := e.openPeerConnection(*wgPort, myKey, peer)
				if err != nil {
					e.conns[peer.WgPubKey] = nil
					return err
				}

				select {
				case _, ok := <-closed:
					if !ok {
						e.conns[peer.WgPubKey] = nil
						return fmt.Errorf("connection to peer %s has been closed", peer.WgPubKey)
					}
					return nil
				}
			}

			err = backoff.Retry(operation, backoff.NewExponentialBackOff())
			if err != nil {
				log.Errorf("----------------------> %s ", err)
				return
			}

		}()
	}

	return nil
}

func (e *Engine) openPeerConnection(wgPort int, myKey wgtypes.Key, peer Peer) (*Connection, chan struct{}, error) {

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
	closedCh, err := conn.Open(60 * time.Second)
	if err != nil {
		log.Errorf("error openning connection to a remote peer %s %s", remoteKey.String(), err.Error())
		return nil, nil, err
	}
	return conn, closedCh, nil
}

func signalCandidate(candidate ice.Candidate, myKey wgtypes.Key, remoteKey wgtypes.Key, s *signal.Client) error {
	err := s.Send(&sProto.Message{
		Type:      sProto.Message_CANDIDATE,
		Key:       myKey.PublicKey().String(),
		RemoteKey: remoteKey.String(),
		Body:      candidate.Marshal(),
	})
	if err != nil {
		log.Errorf("failed signaling candidate to the remote peer %s %s", remoteKey.String(), err)
		//todo ??
		return err
	}

	return nil
}

func signalAuth(uFrag string, pwd string, myKey wgtypes.Key, remoteKey wgtypes.Key, s *signal.Client, isAnswer bool) error {

	var t sProto.Message_Type
	if isAnswer {
		t = sProto.Message_ANSWER
	} else {
		t = sProto.Message_OFFER
	}

	msg := signal.MarshalCredential(myKey.PublicKey().String(), remoteKey.String(), &signal.Credential{
		UFrag: uFrag,
		Pwd:   pwd}, t)

	err := s.Send(msg)
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

		switch msg.Type {
		case sProto.Message_OFFER:
			remoteCred, err := signal.UnMarshalCredential(msg)
			if err != nil {
				return err
			}
			err = conn.OnOffer(IceCredentials{
				uFrag:         remoteCred.UFrag,
				pwd:           remoteCred.Pwd,
				isControlling: false,
			})

			if err != nil {
				return err
			}

			return nil
		case sProto.Message_ANSWER:
			remoteCred, err := signal.UnMarshalCredential(msg)
			if err != nil {
				return err
			}
			err = conn.OnAnswer(IceCredentials{
				uFrag:         remoteCred.UFrag,
				pwd:           remoteCred.Pwd,
				isControlling: true,
			})

			if err != nil {
				return err
			}

		case sProto.Message_CANDIDATE:

			candidate, err := ice.UnmarshalCandidate(msg.Body)
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
