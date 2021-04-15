package engine

import (
	"fmt"
	"github.com/pion/ice/v2"
	log "github.com/sirupsen/logrus"
	"github.com/wiretrustee/wiretrustee/iface"
	signal "github.com/wiretrustee/wiretrustee/signal"
	sProto "github.com/wiretrustee/wiretrustee/signal/proto"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type Engine struct {
	// a list of STUN and TURN servers
	stunsTurns []*ice.URL
	// signal server client
	signal *signal.Client
	// peer agents indexed by local public key of the remote peers
	agents map[string]*PeerAgent
	// Wireguard interface
	wgIface string
	// Wireguard local address
	wgAddr string
}

func NewEngine(signal *signal.Client, stunsTurns []*ice.URL, wgIface string, wgAddr string) *Engine {
	return &Engine{
		stunsTurns: stunsTurns,
		signal:     signal,
		wgIface:    wgIface,
		wgAddr:     wgAddr,
		agents:     map[string]*PeerAgent{},
	}
}

func (e *Engine) Start(privateKey string, peers []string) error {

	// setup wireguard
	myKey, err := wgtypes.ParseKey(privateKey)
	myPubKey := myKey.PublicKey().String()
	if err != nil {
		log.Errorf("error parsing Wireguard key %s: [%s]", privateKey, err.Error())
		return err
	}

	err = iface.Create(e.wgIface, e.wgAddr)
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
		peerAgent, err := NewPeerAgent(myPubKey, peer, e.stunsTurns, fmt.Sprintf("127.0.0.1:%d", *wgPort), e.signal, e.wgIface)
		if err != nil {
			log.Fatalf("failed creating peer agent for pair %s - %s", myPubKey, peer)
			return err
		}
		e.agents[myPubKey] = peerAgent

		err = peerAgent.OfferConnection()
		if err != nil {
			log.Fatalf("failed starting agent %s %s", myPubKey, err)
			return err
		}
	}

	return nil
}

func (e *Engine) receiveSignal(localKey string) {
	// connect to a stream of messages coming from the signal server
	e.signal.Receive(localKey, func(msg *sProto.Message) error {

		peerAgent := e.agents[msg.RemoteKey]
		if peerAgent == nil {
			return fmt.Errorf("wrongly addressed message %s", msg.Key)
		}

		if peerAgent.RemoteKey != msg.Key {
			return fmt.Errorf("unknown peer %s", msg.Key)
		}

		switch msg.Type {
		case sProto.Message_OFFER:
			err := peerAgent.OnOffer(msg)
			if err != nil {
				log.Errorf("error handling OFFER from %s", msg.Key)
				return err
			}
			return nil
		case sProto.Message_ANSWER:
			err := peerAgent.OnAnswer(msg)
			if err != nil {
				log.Errorf("error handling ANSWER from %s", msg.Key)
				return err
			}
		case sProto.Message_CANDIDATE:
			err := peerAgent.OnRemoteCandidate(msg)
			if err != nil {
				log.Errorf("error handling CANDIATE from %s", msg.Key)
				return err
			}
		}

		return nil
	})

	e.signal.WaitConnected()
}
