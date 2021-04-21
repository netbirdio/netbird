package connection

import (
	"context"
	"fmt"
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
	uFrag string
	pwd   string
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

	// agent is an actual ice.Agent that is used to negotiate and maintain a connection to a remote peer
	agent *ice.Agent

	wgConn net.Conn

	connected *Cond
	closeCond *Cond

	remoteAuthCond sync.Once
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
		closeCond:         NewCond(),
		connected:         NewCond(),
		agent:             nil,
	}
}

// Open opens connection to a remote peer.
// Will block until the connection has successfully established
func (conn *Connection) Open(timeout time.Duration) error {

	// create an ice.Agent that will be responsible for negotiating and establishing actual peer-to-peer connection
	a, err := ice.NewAgent(&ice.AgentConfig{
		NetworkTypes: []ice.NetworkType{ice.NetworkTypeUDP4},
		Urls:         conn.Config.StunTurnURLS,
	})
	conn.agent = a

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

	log.Infof("trying to connect to peer %s", conn.Config.RemoteWgKey.String())

	// wait until credentials have been sent from the remote peer (will arrive via a signal server)
	select {
	case remoteAuth := <-conn.remoteAuthChannel:

		log.Infof("got a connection confirmation from peer %s", conn.Config.RemoteWgKey.String())

		err = conn.agent.GatherCandidates()
		if err != nil {
			return err
		}

		isControlling := conn.Config.WgKey.PublicKey().String() > conn.Config.RemoteWgKey.String()
		remoteConn, err := conn.openConnectionToRemote(isControlling, remoteAuth)
		if err != nil {
			log.Errorf("failed establishing connection with the remote peer %s %s", conn.Config.RemoteWgKey.String(), err)
			return err
		}

		wgConn, err := conn.createWireguardProxy()
		if err != nil {
			return err
		}
		conn.wgConn = *wgConn

		go conn.proxyToRemotePeer(*wgConn, remoteConn)
		go conn.proxyToLocalWireguard(*wgConn, remoteConn)

		log.Infof("opened connection to peer %s", conn.Config.RemoteWgKey.String())
	case <-time.After(timeout):
		err := conn.Close()
		if err != nil {
			log.Warnf("error while closing connection to peer %s -> %s", conn.Config.RemoteWgKey.String(), err.Error())
		}
		return fmt.Errorf("timeout of %vs exceeded while waiting for the remote peer %s", timeout.Seconds(), conn.Config.RemoteWgKey.String())
	}

	// wait until connection has been closed
	select {
	case <-conn.closeCond.C:
		return fmt.Errorf("connection to peer %s has been closed", conn.Config.RemoteWgKey.String())
	}
}

func (conn *Connection) Close() error {
	var err error
	conn.closeCond.Do(func() {

		log.Warnf("closing connection to peer %s", conn.Config.RemoteWgKey.String())

		if a := conn.agent; a != nil {
			e := a.Close()
			if e != nil {
				log.Warnf("error while closing ICE agent of peer connection %s", conn.Config.RemoteWgKey.String())
				err = e
			}
		}

		if c := conn.wgConn; c != nil {
			e := c.Close()
			if e != nil {
				log.Warnf("error while closingWireguard proxy connection of peer connection %s", conn.Config.RemoteWgKey.String())
				err = e
			}
		}
	})
	return err
}

func (conn *Connection) OnAnswer(remoteAuth IceCredentials) error {

	conn.remoteAuthCond.Do(func() {
		log.Debugf("OnAnswer from peer %s", conn.Config.RemoteWgKey.String())
		conn.remoteAuthChannel <- remoteAuth
	})
	return nil
}

func (conn *Connection) OnOffer(remoteAuth IceCredentials) error {

	conn.remoteAuthCond.Do(func() {
		log.Debugf("OnOffer from peer %s", conn.Config.RemoteWgKey.String())
		conn.remoteAuthChannel <- remoteAuth
		uFrag, pwd, err := conn.agent.GetLocalUserCredentials()
		if err != nil {
		}

		err = conn.signalAnswer(uFrag, pwd)
		if err != nil {
		}
	})

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
// blocks until connection has been established
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
		log.Debugf("ICE Connection State has changed for peer %s -> %s", conn.Config.RemoteWgKey.String(), state.String())
		if state == ice.ConnectionStateConnected {
			// closed the connection has been established we can check the selected candidate pair
			pair, err := conn.agent.GetSelectedCandidatePair()
			if err != nil {
				log.Errorf("failed selecting active ICE candidate pair %s", err)
				return
			}
			log.Debugf("closed to peer %s via selected candidate pair %s", conn.Config.RemoteWgKey.String(), pair)
		} else if state == ice.ConnectionStateDisconnected || state == ice.ConnectionStateFailed {
			// todo do we really wanna have a connection restart within connection itself? Think of moving it outside
			err := conn.Close()
			if err != nil {
				log.Warnf("error while closing connection to peer %s -> %s", conn.Config.RemoteWgKey.String(), err.Error())
			}
		}
	})

	if err != nil {
		return err
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
		case <-conn.closeCond.C:
			log.Infof("stopped proxying from remote peer %s due to closed connection", conn.Config.RemoteWgKey.String())
			return
		default:
			n, err := wgConn.Read(buf)
			if err != nil {
				//log.Warnln("failed reading from peer: ", err.Error())
				continue
			}

			n, err = remoteConn.Write(buf[:n])
			if err != nil {
				//log.Warnln("failed writing to remote peer: ", err.Error())
			}
		}
	}
}

// proxyToLocalWireguard proxies everything from the remote peer to local Wireguard
// blocks
func (conn *Connection) proxyToLocalWireguard(wgConn net.Conn, remoteConn *ice.Conn) {

	buf := make([]byte, 1500)
	for {
		select {
		case <-conn.closeCond.C:
			log.Infof("stopped proxying from remote peer %s due to closed connection", conn.Config.RemoteWgKey.String())
			return
		default:
			n, err := remoteConn.Read(buf)
			if err != nil {
				//log.Errorf("failed reading from remote connection %s", err)
			}

			n, err = wgConn.Write(buf[:n])
			if err != nil {
				//log.Errorf("failed writing to local Wireguard instance %s", err)
			}

		}
	}
}
