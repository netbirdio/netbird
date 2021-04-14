package engine

import (
	"fmt"
	"github.com/pion/ice/v2"
	log "github.com/sirupsen/logrus"
	"github.com/wiretrustee/wiretrustee/iface"
	signal "github.com/wiretrustee/wiretrustee/signal"
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
	agents map[string]*PeerAgent
	// Wireguard interface
	wgIface string
	// Wireguard local address
	wgAddr string
}

func NewEngine(signal *signal.Client, stunsTurns []*ice.URL) *Engine {
	return &Engine{
		stunsTurns: stunsTurns,
		signal:     signal,
	}
}

func (e *Engine) Start(localKey string, peers []string) error {

	// setup wireguard
	myKey, err := wgtypes.ParseKey(localKey)
	if err != nil {
		log.Errorf("error parsing Wireguard key %s: [%s]", localKey, err.Error())
		return err
	}

	err = iface.Create(e.wgIface, e.wgIface)
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

	// initialize peer agents
	for _, peer := range peers {
		peerAgent, err := NewPeerAgent(localKey, peer, e.stunsTurns, fmt.Sprintf("127.0.0.1:%d", *wgPort))
		if err != nil {
			log.Fatalf("failed creating peer agent for pair %s - %s", localKey, peer)
			return err
		}
		e.agents[localKey] = peerAgent
	}

	e.receiveSignal(localKey)

	return nil
}

func (e *Engine) receiveSignal(localKey string) {
	// connect to a stream of messages coming from the signal server
	e.signal.Receive(localKey, func(msg *sProto.Message) error {

		// check if this is our "buddy" peer
		peerAgent := e.agents[msg.Key]
		if peerAgent == nil {
			return fmt.Errorf("unknown peer %s", msg.Key)
		}

		// the one who send offer (expects answer) is the initiator of teh connection
		initiator := msg.Type == sProto.Message_ANSWER

		switch msg.Type {
		case sProto.Message_OFFER:
		case sProto.Message_ANSWER:
			remoteCred, err := signal.UnMarshalCredential(msg)
			if err != nil {
				return err
			}

			err = peerAgent.Authenticate(remoteCred)
			if err != nil {
				log.Errorf("error authenticating remote peer %s", msg.Key)
				return err
			}

			conn, err := peerAgent.OpenConnection(initiator)
			if err != nil {
				log.Errorf("error opening connection ot remote peer %s", msg.Key)
				return err
			}

			err = iface.UpdatePeer(e.wgIface, peerAgent.RemoteKey, "0.0.0.0/0", 15*time.Second, conn.LocalAddr().String())
			if err != nil {
				log.Errorf("error while configuring Wireguard peer [%s] %s", peerAgent.RemoteKey, err.Error())
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
