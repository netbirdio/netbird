package engine

import (
	"context"
	"github.com/pion/ice/v2"
	log "github.com/sirupsen/logrus"
	"github.com/wiretrustee/wiretrustee/signal"
	sProto "github.com/wiretrustee/wiretrustee/signal/proto"
	"net"
)

// PeerAgent is responsible for establishing and maintaining of the connection between two peers (local and remote)
// It uses underlying ice.Agent and ice.Conn
type PeerAgent struct {
	// a Wireguard public key of the peer
	LocalKey string
	// a Wireguard public key of the remote peer
	RemoteKey string
	// ICE iceAgent that actually negotiates and maintains peer-to-peer connection
	iceAgent *ice.Agent
	// Actual peer-to-peer connection
	conn *ice.Conn
	// a signal.Client to negotiate initial connection
	signal signal.Client
	// a connection to a local Wireguard instance to proxy data
	wgConn net.Conn
	// an address of local Wireguard instance
	wgAddr string
}

// NewPeerAgent creates a new PeerAgent with give local and remote Wireguard public keys and initializes an ICE Agent
func NewPeerAgent(localKey string, remoteKey string, stunTurnURLS []*ice.URL, wgAddr string) (*PeerAgent, error) {

	// init ICE Agent
	iceAgent, err := ice.NewAgent(&ice.AgentConfig{
		NetworkTypes: []ice.NetworkType{ice.NetworkTypeUDP4},
		Urls:         stunTurnURLS,
	})
	if err != nil {
		return nil, err
	}

	peerAgent := &PeerAgent{
		LocalKey:  localKey,
		RemoteKey: remoteKey,
		iceAgent:  iceAgent,
		wgAddr:    wgAddr,
		conn:      nil,
		wgConn:    nil,
	}

	err = peerAgent.onConnectionStateChange()
	if err != nil {
		//todo close agent
		return nil, err
	}

	err = peerAgent.onCandidate()
	if err != nil {
		log.Errorf("failed listening on ICE connection state changes %s", err)
		//todo close agent
		return nil, err
	}

	return peerAgent, nil

}

// proxyToRemotePeer proxies everything from Wireguard to the remote peer
// blocks
func (pa *PeerAgent) proxyToRemotePeer() {

	buf := make([]byte, 1500)
	for {
		n, err := pa.wgConn.Read(buf)
		if err != nil {
			log.Warnln("Error reading from peer: ", err.Error())
			continue
		}

		n, err = pa.conn.Write(buf[:n])
		if err != nil {
			log.Warnln("Error writing to remote peer: ", err.Error())
		}
	}
}

// proxyToLocalWireguard proxies everything from the remote peer to local Wireguard
// blocks
func (pa *PeerAgent) proxyToLocalWireguard() {

	buf := make([]byte, 1500)
	for {
		n, err := pa.conn.Read(buf)
		if err != nil {
			log.Errorf("failed reading from remote connection %s", err)
		}

		n, err = pa.wgConn.Write(buf[:n])
		if err != nil {
			log.Errorf("failed writing to local Wireguard instance %s", err)
		}

	}
}

// OpenConnection opens connection to remote peer. Flow:
// 1. start gathering connection candidates
// 2. if the peer was an initiator then it dials to the remote peer
// 3. if the peer wasn't an initiator then it waits for incoming connection from the remote peer
// 4. after connection has been established peer starts to:
//	  - proxy all local Wireguard's packets to the remote peer
//    - proxy all incoming data from the remote peer to local Wireguard
// The returned connection address can be used to be set as Wireguard's remote peer endpoint
func (pa *PeerAgent) OpenConnection(initiator bool) (net.Conn, error) {
	// start gathering candidates
	err := pa.iceAgent.GatherCandidates()
	if err != nil {
		return nil, err
	}

	// by that time it should be already set
	frag, pwd, err := pa.iceAgent.GetRemoteUserCredentials()
	if err != nil {
		log.Errorf("remote credentials are not set for remote peer %s", pa.RemoteKey)
		return nil, err
	}

	// initiate remote connection
	// will block until connection was established
	var conn *ice.Conn = nil
	if initiator {
		conn, err = pa.iceAgent.Dial(context.TODO(), frag, pwd)
	} else {
		conn, err = pa.iceAgent.Accept(context.TODO(), frag, pwd)
	}

	if err != nil {
		log.Fatalf("failed listening on local port %s", err)
		return nil, err
	}

	log.Infof("Local addr %s, remote addr %s", conn.LocalAddr(), conn.RemoteAddr())
	pa.conn = conn

	// connect to local Wireguard instance
	wgConn, err := net.Dial("udp", pa.wgAddr)
	if err != nil {
		log.Fatalf("failed dialing to local Wireguard port %s", err)
		return nil, err
	}
	pa.wgConn = wgConn

	go func() {
		pa.proxyToRemotePeer()
	}()

	go func() {
		pa.proxyToLocalWireguard()
	}()

	return wgConn, nil
}

func (pa *PeerAgent) OnAnswer(msg *sProto.Message) error {
	return nil
}

func (pa *PeerAgent) OnRemoteCandidate(msg *sProto.Message) error {
	return nil
}

// signalCandidate sends a message with a local ice.Candidate details to the remote peer via signal server
func (pa *PeerAgent) signalCandidate(c ice.Candidate) error {
	err := pa.signal.Send(&sProto.Message{
		Type:      sProto.Message_CANDIDATE,
		Key:       pa.LocalKey,
		RemoteKey: pa.RemoteKey,
		Body:      c.Marshal(),
	})

	if err != nil {
		return err
	}
	return nil
}

// onCandidate detects new local ice.Candidate and sends it to the remote peer via signal server
func (pa *PeerAgent) onCandidate() error {
	return pa.iceAgent.OnCandidate(func(candidate ice.Candidate) {
		if candidate != nil {
			err := pa.signalCandidate(candidate)
			if err != nil {
				log.Errorf("failed signaling candidate to the remote peer %s %s", pa.RemoteKey, err)
				//todo ??
				return
			}
		}
	})
}

// onConnectionStateChange listens on ice.Agent connection state change events and once connected checks a Candidate pair
// the ice.Conn was established with
// Mostly used for debugging purposes (e.g. connection time, etc)
func (pa *PeerAgent) onConnectionStateChange() error {
	return pa.iceAgent.OnConnectionStateChange(func(state ice.ConnectionState) {
		log.Debugf("ICE Connection State has changed: %s", state.String())
		if state == ice.ConnectionStateConnected {
			// once the connection has been established we can check the selected candidate pair
			pair, err := pa.iceAgent.GetSelectedCandidatePair()
			if err != nil {
				log.Errorf("failed selecting active ICE candidate pair %s", err)
				return
			}
			log.Debugf("connected to peer %s via selected candidate pair %s", pa.RemoteKey, pair)
		}
	})
}

// authenticate sets the signal.Credential of the remote peer
// and sends local signal.Credential to teh remote peer via signal server
func (pa *PeerAgent) Authenticate(credential *signal.Credential) error {

	err := pa.iceAgent.SetRemoteCredentials(credential.UFrag, credential.Pwd)
	if err != nil {
		return err
	}

	localUFrag, localPwd, err := pa.iceAgent.GetLocalUserCredentials()
	if err != nil {
		return err
	}

	// notify the remote peer about our credentials
	answer := signal.MarshalCredential(pa.LocalKey, pa.RemoteKey, &signal.Credential{
		UFrag: localUFrag,
		Pwd:   localPwd,
	}, sProto.Message_ANSWER)

	//notify the remote peer of our credentials
	err = pa.signal.Send(answer)
	if err != nil {
		return err
	}

	return nil

}
