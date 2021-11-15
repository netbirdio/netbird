package internal

import (
	"context"
	"fmt"
	ice "github.com/pion/ice/v2"
	log "github.com/sirupsen/logrus"
	"github.com/wiretrustee/wiretrustee/iface"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"net"
	"sync"
	"time"
)

var (
	// DefaultWgKeepAlive default Wireguard keep alive constant
	DefaultWgKeepAlive = 20 * time.Second
	privateIPBlocks    []*net.IPNet
)

type Status string

const (
	StatusConnected    Status = "Connected"
	StatusConnecting   Status = "Connecting"
	StatusDisconnected Status = "Disconnected"
)

func init() {
	for _, cidr := range []string{
		"127.0.0.0/8",    // IPv4 loopback
		"10.0.0.0/8",     // RFC1918
		"172.16.0.0/12",  // RFC1918
		"192.168.0.0/16", // RFC1918
		"169.254.0.0/16", // RFC3927 link-local
		"::1/128",        // IPv6 loopback
		"fe80::/10",      // IPv6 link-local
		"fc00::/7",       // IPv6 unique local addr
	} {
		_, block, err := net.ParseCIDR(cidr)
		if err != nil {
			panic(fmt.Errorf("parse error on %q: %v", cidr, err))
		}
		privateIPBlocks = append(privateIPBlocks, block)
	}
}

// ConnConfig Connection configuration struct
type ConnConfig struct {
	// Local Wireguard listening address  e.g. 127.0.0.1:51820
	WgListenAddr string
	// A Local Wireguard Peer IP address in CIDR notation e.g. 10.30.30.1/24
	WgPeerIP string
	// Local Wireguard Interface name (e.g. wg0)
	WgIface string
	// Wireguard allowed IPs (e.g. 10.30.30.2/32)
	WgAllowedIPs string
	// Local Wireguard private key
	WgKey wgtypes.Key
	// Remote Wireguard public key
	RemoteWgKey wgtypes.Key

	StunTurnURLS []*ice.URL

	iFaceBlackList map[string]struct{}
}

// IceCredentials ICE protocol credentials struct
type IceCredentials struct {
	uFrag string
	pwd   string
}

// Connection Holds information about a connection and handles signal protocol
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

	wgProxy *WgProxy

	connected *Cond
	closeCond *Cond

	remoteAuthCond sync.Once

	Status Status
}

// NewConnection Creates a new connection and sets handling functions for signal protocol
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
		wgProxy:           NewWgProxy(config.WgIface, config.RemoteWgKey.String(), config.WgAllowedIPs, config.WgListenAddr),
		Status:            StatusDisconnected,
	}
}

// Open opens connection to a remote peer.
// Will block until the connection has successfully established
func (conn *Connection) Open(timeout time.Duration) error {

	// create an ice.Agent that will be responsible for negotiating and establishing actual peer-to-peer connection
	a, err := ice.NewAgent(&ice.AgentConfig{
		// MulticastDNSMode: ice.MulticastDNSModeQueryAndGather,
		NetworkTypes:   []ice.NetworkType{ice.NetworkTypeUDP4},
		Urls:           conn.Config.StunTurnURLS,
		CandidateTypes: []ice.CandidateType{ice.CandidateTypeHost, ice.CandidateTypeServerReflexive, ice.CandidateTypeRelay},
		InterfaceFilter: func(s string) bool {
			if conn.Config.iFaceBlackList == nil {
				return true
			}
			_, ok := conn.Config.iFaceBlackList[s]
			return !ok
		},
	})
	if err != nil {
		return err
	}

	conn.agent = a
	defer func() {
		err := conn.agent.Close()
		if err != nil {
			return
		}
	}()

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

	conn.Status = StatusConnecting
	log.Debugf("trying to connect to peer %s", conn.Config.RemoteWgKey.String())

	// wait until credentials have been sent from the remote peer (will arrive via a signal server)
	select {
	case remoteAuth := <-conn.remoteAuthChannel:

		log.Debugf("got a connection confirmation from peer %s", conn.Config.RemoteWgKey.String())

		err = conn.agent.GatherCandidates()
		if err != nil {
			return err
		}

		isControlling := conn.Config.WgKey.PublicKey().String() > conn.Config.RemoteWgKey.String()
		var remoteConn *ice.Conn
		remoteConn, err = conn.openConnectionToRemote(isControlling, remoteAuth)
		if err != nil {
			log.Errorf("failed establishing connection with the remote peer %s %s", conn.Config.RemoteWgKey.String(), err)
			return err
		}

		var pair *ice.CandidatePair
		pair, err = conn.agent.GetSelectedCandidatePair()
		if err != nil {
			return err
		}

		useProxy := useProxy(pair)

		// in case the remote peer is in the local network or one of the peers has public static IP -> no need for a Wireguard proxy, direct communication is possible.
		if !useProxy {
			log.Debugf("it is possible to establish a direct connection (without proxy) to peer %s - my addr: %s, remote addr: %s", conn.Config.RemoteWgKey.String(), pair.Local, pair.Remote)
			err = conn.wgProxy.StartLocal(fmt.Sprintf("%s:%d", pair.Remote.Address(), iface.WgPort))
			if err != nil {
				return err
			}

		} else {
			log.Debugf("establishing secure tunnel to peer %s via selected candidate pair %s", conn.Config.RemoteWgKey.String(), pair)
			err = conn.wgProxy.Start(remoteConn)
			if err != nil {
				return err
			}
		}

		relayed := pair.Remote.Type() == ice.CandidateTypeRelay || pair.Local.Type() == ice.CandidateTypeRelay

		conn.Status = StatusConnected
		log.Infof("opened connection to peer %s [localProxy=%v, relayed=%v]", conn.Config.RemoteWgKey.String(), useProxy, relayed)
	case <-conn.closeCond.C:
		conn.Status = StatusDisconnected
		return fmt.Errorf("connection to peer %s has been closed", conn.Config.RemoteWgKey.String())
	case <-time.After(timeout):
		err = conn.Close()
		if err != nil {
			log.Warnf("error while closing connection to peer %s -> %s", conn.Config.RemoteWgKey.String(), err.Error())
		}
		conn.Status = StatusDisconnected
		return fmt.Errorf("timeout of %vs exceeded while waiting for the remote peer %s", timeout.Seconds(), conn.Config.RemoteWgKey.String())
	}

	// wait until connection has been closed
	<-conn.closeCond.C
	conn.Status = StatusDisconnected
	return fmt.Errorf("connection to peer %s has been closed", conn.Config.RemoteWgKey.String())
}

func isPublicIP(ip net.IP) bool {
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return false
	}

	for _, block := range privateIPBlocks {
		if block.Contains(ip) {
			return false
		}
	}
	return true
}

//useProxy determines whether a direct connection (without a go proxy) is possible
//There are 3 cases: one of the peers has a public IP or both peers are in the same private network
//Please note, that this check happens when peers were already able to ping each other with ICE layer.
func useProxy(pair *ice.CandidatePair) bool {
	remoteIP := net.ParseIP(pair.Remote.Address())
	myIp := net.ParseIP(pair.Local.Address())
	remoteIsPublic := isPublicIP(remoteIP)
	myIsPublic := isPublicIP(myIp)

	//one of the hosts has a public IP
	if remoteIsPublic && pair.Remote.Type() == ice.CandidateTypeHost {
		return false
	}
	if myIsPublic && pair.Local.Type() == ice.CandidateTypeHost {
		return false
	}

	if pair.Local.Type() == ice.CandidateTypeHost && pair.Remote.Type() == ice.CandidateTypeHost {
		if !remoteIsPublic && !myIsPublic {
			//both hosts are in the same private network
			return false
		}
	}

	return true
}

// Close Closes a peer connection
func (conn *Connection) Close() error {
	var err error
	conn.closeCond.Do(func() {

		log.Debugf("closing connection to peer %s", conn.Config.RemoteWgKey.String())

		if a := conn.agent; a != nil {
			e := a.Close()
			if e != nil {
				log.Warnf("error while closing ICE agent of peer connection %s", conn.Config.RemoteWgKey.String())
				err = e
			}
		}

		if c := conn.wgProxy; c != nil {
			e := c.Close()
			if e != nil {
				log.Warnf("error while closingWireguard proxy connection of peer connection %s", conn.Config.RemoteWgKey.String())
				err = e
			}
		}
	})
	return err
}

// OnAnswer Handles the answer from the other peer
func (conn *Connection) OnAnswer(remoteAuth IceCredentials) error {

	conn.remoteAuthCond.Do(func() {
		log.Debugf("OnAnswer from peer %s", conn.Config.RemoteWgKey.String())
		conn.remoteAuthChannel <- remoteAuth
	})
	return nil
}

// OnOffer Handles the offer from the other peer
func (conn *Connection) OnOffer(remoteAuth IceCredentials) error {

	conn.remoteAuthCond.Do(func() {
		log.Debugf("OnOffer from peer %s", conn.Config.RemoteWgKey.String())
		conn.remoteAuthChannel <- remoteAuth
		uFrag, pwd, err := conn.agent.GetLocalUserCredentials()
		if err != nil { //nolint
		}

		err = conn.signalAnswer(uFrag, pwd)
		if err != nil { //nolint
		}
	})

	return nil
}

// OnRemoteCandidate Handles remote candidate provided by the peer.
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
			log.Debugf("ICE connected to peer %s via a selected connnection candidate pair %s", conn.Config.RemoteWgKey.String(), pair)
		} else if state == ice.ConnectionStateDisconnected || state == ice.ConnectionStateFailed {
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
