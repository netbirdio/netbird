package connection

import (
	"context"
	"github.com/cenkalti/backoff/v4"
	"github.com/pion/ice/v2"
	log "github.com/sirupsen/logrus"
	"github.com/wiretrustee/wiretrustee/iface"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"net"
	"sync"
	"time"
)

var (
	DefaultWgKeepAlive = 20 * time.Second
)

type ConnConfig struct {
	// Local Wireguard listening address  e.g. 127.0.0.1:51820
	WgListenAddr string
	// A Local Wireguard Peer IP address in CIDR notation e.g. 10.30.30.1/24
	WgPeerIp string
	// Local Wireguard Interface name (e.g. wg0)
	WgIface string
	// Wireguard allowed IPs (e.g. 10.30.30.2/32)
	WgAllowedIPs string
	// Local Wireguard private key
	WgKey wgtypes.Key
	// Remote Wireguard public key
	RemoteWgKey wgtypes.Key

	StunTurnURLS []*ice.URL
}

type IceCredentials struct {
	uFrag         string
	pwd           string
	isControlling bool //todo think of better solution??
}

type Connection struct {
	Config ConnConfig
	// signalCandidate is a handler function to signal remote peer about local connection candidate
	signalCandidate func(candidate ice.Candidate) error

	// signalOffer is a handler function to signal remote peer our connection offer (credentials)
	signalOffer func(uFrag string, pwd string) error

	// signalOffer is a handler function to signal remote peer our connection answer (credentials)
	signalAnswer func(uFrag string, pwd string) error

	// remoteAuthChannel is a channel used to wait for remote credentials to proceed with the connection
	remoteAuthChannel chan IceCredentials

	closeChannel chan bool

	// agent is an actual ice.Agent that is used to negotiate and maintain a connection to a remote peer
	agent *ice.Agent

	wgConn net.Conn
	// mux is used to ensure exclusive access to Open() and Close() operations on connection
	mux sync.Mutex
	// isActive indicates whether connection is active or not.
	isActive bool
}

func NewConnection(config ConnConfig,
	signalCandidate func(candidate ice.Candidate) error,
	signalOffer func(uFrag string, pwd string) error,
	signalAnswer func(uFrag string, pwd string) error,
) *Connection {

	return &Connection{
		Config:            config,
		signalCandidate:   signalCandidate,
		signalOffer:       signalOffer,
		signalAnswer:      signalAnswer,
		remoteAuthChannel: make(chan IceCredentials, 1),
		closeChannel:      make(chan bool, 2),
		agent:             nil,
		isActive:          false,
		mux:               sync.Mutex{},
	}
}

func (conn *Connection) Close() error {

	conn.mux.Lock()
	defer conn.mux.Unlock()

	if !conn.isActive {
		log.Infof("connection to peer %s has been already closed, skipping", conn.Config.RemoteWgKey.String())
		return nil
	}

	log.Debugf("closing connection to peer %s", conn.Config.RemoteWgKey.String())

	conn.closeChannel <- true
	conn.closeChannel <- true

	err := conn.agent.Close()
	if err != nil {
		return err
	}

	err = conn.wgConn.Close()
	if err != nil {
		return err
	}

	log.Debugf("closed connection to peer %s", conn.Config.RemoteWgKey.String())

	conn.isActive = false

	return nil
}

// Open opens connection to a remote peer.
// Will block until the connection has successfully established
func (conn *Connection) Open() error {

	log.Debugf("opening connection to peer %s", conn.Config.RemoteWgKey.String())

	conn.mux.Lock()
	defer conn.mux.Unlock()

	wgConn, err := conn.createWireguardProxy()
	if err != nil {
		return err
	}
	conn.wgConn = *wgConn

	// create an ice.Agent that will be responsible for negotiating and establishing actual peer-to-peer connection
	conn.agent, err = ice.NewAgent(&ice.AgentConfig{
		NetworkTypes: []ice.NetworkType{ice.NetworkTypeUDP4},
		Urls:         conn.Config.StunTurnURLS,
	})
	if err != nil {
		return err
	}

	err = conn.listenOnLocalCandidates()
	if err != nil {
		return err
	}

	err = conn.listenOnConnectionStateChanges()
	if err != nil {
		return err
	}

	err = conn.signalCredentials()
	if err != nil {
		return err
	}

	// wait until credentials have been sent from the remote peer (will arrive via signal channel)
	remoteAuth := <-conn.remoteAuthChannel

	err = conn.agent.GatherCandidates()
	if err != nil {
		return err
	}

	remoteConn, err := conn.openConnectionToRemote(remoteAuth.isControlling, remoteAuth)
	if err != nil {
		log.Errorf("failed establishing connection with the remote peer %s %s", conn.Config.RemoteWgKey.String(), err)
		return err
	}

	go conn.proxyToRemotePeer(*wgConn, remoteConn)
	go conn.proxyToLocalWireguard(*wgConn, remoteConn)

	log.Debugf("opened connection to peer %s", conn.Config.RemoteWgKey.String())

	conn.isActive = true

	return nil
}

func (conn *Connection) OnAnswer(remoteAuth IceCredentials) error {
	log.Debugf("OnAnswer from peer %s", conn.Config.RemoteWgKey.String())

	if conn.isActive {
		log.Debugf("connection is active, ignoring OnAnswer from peer %s", conn.Config.RemoteWgKey.String())
		return nil
	}

	conn.remoteAuthChannel <- remoteAuth
	return nil
}

func (conn *Connection) OnOffer(remoteAuth IceCredentials) error {

	log.Debugf("OnOffer from peer %s", conn.Config.RemoteWgKey.String())

	if conn.isActive {
		log.Debugf("connection is active, ignoring OnOffer from peer %s", conn.Config.RemoteWgKey.String())
		return nil
	}

	conn.remoteAuthChannel <- remoteAuth

	uFrag, pwd, err := conn.agent.GetLocalUserCredentials()
	if err != nil {
		return err
	}

	err = conn.signalAnswer(uFrag, pwd)
	if err != nil {
		return err
	}

	return nil
}

func (conn *Connection) OnRemoteCandidate(candidate ice.Candidate) error {

	log.Debugf("onRemoteCandidate from peer %s -> %s", conn.Config.RemoteWgKey.String(), candidate.String())

	err := conn.agent.AddRemoteCandidate(candidate)
	if err != nil {
		return err
	}

	return nil
}

// openConnectionToRemote opens an ice.Conn to the remote peer. This is a real peer-to-peer connection
func (conn *Connection) openConnectionToRemote(isControlling bool, credentials IceCredentials) (*ice.Conn, error) {
	var realConn *ice.Conn
	var err error

	if isControlling {
		realConn, err = conn.agent.Dial(context.TODO(), credentials.uFrag, credentials.pwd)
	} else {
		realConn, err = conn.agent.Accept(context.TODO(), credentials.uFrag, credentials.pwd)
	}

	if err != nil {
		return nil, err
	}

	return realConn, err
}

// signalCredentials prepares local user credentials and signals them to the remote peer
func (conn *Connection) signalCredentials() error {
	localUFrag, localPwd, err := conn.agent.GetLocalUserCredentials()
	if err != nil {
		return err
	}

	err = conn.signalOffer(localUFrag, localPwd)
	if err != nil {
		return err
	}
	return nil
}

// listenOnLocalCandidates registers callback of an ICE Agent to receive new local connection candidates and then
// signals them to the remote peer
func (conn *Connection) listenOnLocalCandidates() error {
	err := conn.agent.OnCandidate(func(candidate ice.Candidate) {
		if candidate != nil {
			log.Debugf("discovered local candidate %s", candidate.String())
			err := conn.signalCandidate(candidate)
			if err != nil {
				log.Errorf("failed signaling candidate to the remote peer %s %s", conn.Config.RemoteWgKey.String(), err)
				//todo ??
				return
			}
		}
	})

	if err != nil {
		return err
	}

	return nil
}

// listenOnConnectionStateChanges registers callback of an ICE Agent to track connection state
func (conn *Connection) listenOnConnectionStateChanges() error {
	err := conn.agent.OnConnectionStateChange(func(state ice.ConnectionState) {
		log.Debugf("ICE Connection State has changed: %s", state.String())
		if state == ice.ConnectionStateConnected {
			// once the connection has been established we can check the selected candidate pair
			pair, err := conn.agent.GetSelectedCandidatePair()
			if err != nil {
				log.Errorf("failed selecting active ICE candidate pair %s", err)
				return
			}
			log.Debugf("connected to peer %s via selected candidate pair %s", conn.Config.RemoteWgKey.String(), pair)
		} else if state == ice.ConnectionStateDisconnected || state == ice.ConnectionStateFailed {
			// todo do we really wanna have a connection restart within connection itself? Think of moving it outside
			operation := func() error {
				return conn.Restart()
			}
			err := backoff.Retry(operation, backoff.NewExponentialBackOff())
			if err != nil {
				log.Errorf("error while communicating with the Signal Exchange %s ", err)
				return
			}
		}
	})

	if err != nil {
		return err
	}

	return nil
}

func (conn *Connection) Restart() error {
	err := conn.Close()
	if err != nil {
		log.Errorf("failed closing connection to peer %s %s", conn.Config.RemoteWgKey.String(), err)
		return nil
	}
	err = conn.Open()
	if err != nil {
		log.Errorf("failed reopenning connection to peer %s %s", conn.Config.RemoteWgKey.String(), err)
		return nil
	}

	return nil
}

// createWireguardProxy opens connection to a local Wireguard instance (proxy) and sets Wireguard's peer endpoint to point
// to a local address of a proxy
func (conn *Connection) createWireguardProxy() (*net.Conn, error) {
	wgConn, err := net.Dial("udp", conn.Config.WgListenAddr)
	if err != nil {
		log.Fatalf("failed dialing to local Wireguard port %s", err)
		return nil, err
	}
	// add local proxy connection as a Wireguard peer
	err = iface.UpdatePeer(conn.Config.WgIface, conn.Config.RemoteWgKey.String(), conn.Config.WgAllowedIPs, DefaultWgKeepAlive,
		wgConn.LocalAddr().String())
	if err != nil {
		log.Errorf("error while configuring Wireguard peer [%s] %s", conn.Config.RemoteWgKey.String(), err.Error())
		return nil, err
	}

	return &wgConn, err
}

// proxyToRemotePeer proxies everything from Wireguard to the remote peer
// blocks
func (conn *Connection) proxyToRemotePeer(wgConn net.Conn, remoteConn *ice.Conn) {

	buf := make([]byte, 1500)
	for {
		select {
		default:
			n, err := wgConn.Read(buf)
			if err != nil {
				log.Warnln("Error reading from peer: ", err.Error())
				continue
			}

			n, err = remoteConn.Write(buf[:n])
			if err != nil {
				log.Warnln("Error writing to remote peer: ", err.Error())
			}
		case <-conn.closeChannel:
			log.Infof("stopped proxying to remote peer %s", conn.Config.RemoteWgKey.String())
			return
		}
	}
}

// proxyToLocalWireguard proxies everything from the remote peer to local Wireguard
// blocks
func (conn *Connection) proxyToLocalWireguard(wgConn net.Conn, remoteConn *ice.Conn) {

	buf := make([]byte, 1500)
	for {
		select {
		default:
			n, err := remoteConn.Read(buf)
			if err != nil {
				log.Errorf("failed reading from remote connection %s", err)
			}

			n, err = wgConn.Write(buf[:n])
			if err != nil {
				log.Errorf("failed writing to local Wireguard instance %s", err)
			}
		case <-conn.closeChannel:
			log.Infof("stopped proxying from remote peer %s", conn.Config.RemoteWgKey.String())
			return
		}
	}
}
