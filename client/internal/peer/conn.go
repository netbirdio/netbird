package peer

import (
	"context"
	"github.com/pion/ice/v2"
	log "github.com/sirupsen/logrus"
	"github.com/wiretrustee/wiretrustee/client/internal/proxy"
	"net"
	"sync"
	"time"
)

// ConnConfig is a peer Connection configuration
type ConnConfig struct {

	// Key is a public key of a remote peer
	Key string
	// LocalKey is a public key of a local peer
	LocalKey string

	// StunTurn is a list of STUN and TURN URLs
	StunTurn []*ice.URL

	// InterfaceBlackList is a list of machine interfaces that should be filtered out by ICE Candidate gathering
	// (e.g. if eth0 is in the list, host candidate of this interface won't be used)
	InterfaceBlackList []string

	Timeout time.Duration

	ProxyConfig proxy.Config
}

// IceCredentials ICE protocol credentials struct
type IceCredentials struct {
	UFrag string
	Pwd   string
}

type Conn struct {
	config ConnConfig
	mu     sync.Mutex

	// signalCandidate is a handler function to signal remote peer about local connection candidate
	signalCandidate func(candidate ice.Candidate) error
	// signalOffer is a handler function to signal remote peer our connection offer (credentials)
	signalOffer  func(uFrag string, pwd string) error
	signalAnswer func(uFrag string, pwd string) error

	// remoteOffersCh is a channel used to wait for remote credentials to proceed with the connection
	remoteOffersCh chan IceCredentials
	// remoteAnswerCh is a channel used to wait for remote credentials answer (confirmation of our offer) to proceed with the connection
	remoteAnswerCh     chan IceCredentials
	closeCh            chan struct{}
	ctx                context.Context
	notifyDisconnected context.CancelFunc

	agent  *ice.Agent
	status ConnStatus

	proxy proxy.Proxy
}

// NewConn creates a new not opened Conn to the remote peer.
// To establish a connection run Conn.Open
func NewConn(config ConnConfig) (*Conn, error) {
	return &Conn{
		config:         config,
		mu:             sync.Mutex{},
		status:         StatusDisconnected,
		closeCh:        make(chan struct{}),
		remoteOffersCh: make(chan IceCredentials),
		remoteAnswerCh: make(chan IceCredentials),
	}, nil
}

// interfaceFilter is a function passed to ICE Agent to filter out blacklisted interfaces
func interfaceFilter(blackList []string) func(string) bool {
	var blackListMap map[string]struct{}
	if blackList != nil {
		blackListMap = make(map[string]struct{})
		for _, s := range blackList {
			blackListMap[s] = struct{}{}
		}
	}
	return func(iFace string) bool {
		if len(blackListMap) == 0 {
			return true
		}
		_, ok := blackListMap[iFace]
		return !ok
	}
}

func (conn *Conn) reCreateAgent() error {
	conn.mu.Lock()
	defer conn.mu.Unlock()

	failedTimeout := 6 * time.Second
	var err error
	conn.agent, err = ice.NewAgent(&ice.AgentConfig{
		MulticastDNSMode: ice.MulticastDNSModeDisabled,
		NetworkTypes:     []ice.NetworkType{ice.NetworkTypeUDP4},
		Urls:             conn.config.StunTurn,
		CandidateTypes:   []ice.CandidateType{ice.CandidateTypeHost, ice.CandidateTypeServerReflexive, ice.CandidateTypeRelay},
		FailedTimeout:    &failedTimeout,
		InterfaceFilter:  interfaceFilter(conn.config.InterfaceBlackList),
	})
	if err != nil {
		return err
	}

	err = conn.agent.OnCandidate(conn.onICECandidate)
	if err != nil {
		return err
	}

	err = conn.agent.OnConnectionStateChange(conn.onICEConnectionStateChange)
	if err != nil {
		return err
	}

	err = conn.agent.OnSelectedCandidatePairChange(conn.onICESelectedCandidatePair)
	if err != nil {
		return err
	}

	return nil
}

// Open opens connection to the remote peer starting ICE candidate gathering process.
// Blocks until connection has been closed or connection timeout.
// ConnStatus will be set accordingly
func (conn *Conn) Open() error {
	log.Debugf("trying to connect to peer %s", conn.config.Key)

	defer func() {
		err := conn.cleanup()
		if err != nil {
			log.Errorf("error while cleaning up peer connection %s: %v", conn.config.Key, err)
			return
		}
	}()

	err := conn.reCreateAgent()
	if err != nil {
		return err
	}

	err = conn.sendOffer()
	if err != nil {
		return err
	}

	log.Debugf("connection offer sent to peer %s, waiting for the confirmation", conn.config.Key)

	// Only continue once we got a connection confirmation from the remote peer.
	// The connection timeout could have happened before a confirmation received from the remote.
	// The connection could have also been closed externally (e.g. when we received an update from the management that peer shouldn't be connected)
	var remoteCredentials IceCredentials
	select {
	case remoteCredentials = <-conn.remoteOffersCh:
		err = conn.sendAnswer()
		if err != nil {
			return err
		}
	case remoteCredentials = <-conn.remoteAnswerCh:
	case <-time.After(conn.config.Timeout):
		return NewConnectionTimeoutError(conn.config.Key, conn.config.Timeout)
	case <-conn.closeCh:
		// closed externally
		return NewConnectionClosedError(conn.config.Key)
	}

	log.Debugf("received connection confirmation from peer %s", conn.config.Key)

	//at this point we received offer/answer and we are ready to gather candidates
	conn.mu.Lock()
	conn.status = StatusConnecting
	conn.ctx, conn.notifyDisconnected = context.WithCancel(context.Background())
	defer conn.notifyDisconnected()
	conn.mu.Unlock()

	err = conn.agent.GatherCandidates()
	if err != nil {
		return err
	}

	// will block until connection succeeded
	// but it won't release if ICE Agent went into Disconnected or Failed state,
	// so we have to cancel it with the provided context once agent detected a broken connection
	isControlling := conn.config.LocalKey > conn.config.Key
	var remoteConn *ice.Conn
	if isControlling {
		remoteConn, err = conn.agent.Dial(conn.ctx, remoteCredentials.UFrag, remoteCredentials.Pwd)
	} else {
		remoteConn, err = conn.agent.Accept(conn.ctx, remoteCredentials.UFrag, remoteCredentials.Pwd)
	}
	if err != nil {
		return err
	}

	// the connection has been established successfully so we are ready to start the proxy
	err = conn.startProxy(remoteConn)
	if err != nil {
		return err
	}

	log.Infof("connected to peer %s [laddr <-> raddr] [%s <-> %s]", conn.config.Key, remoteConn.LocalAddr().String(), remoteConn.RemoteAddr().String())

	// wait until connection disconnected or has been closed externally (upper layer, e.g. engine)
	select {
	case <-conn.closeCh:
		//closed externally
		return NewConnectionClosedError(conn.config.Key)
	case <-conn.ctx.Done():
		//disconnected from the remote peer
		return NewConnectionDisconnectedError(conn.config.Key)
	}
}

// startProxy starts proxying traffic from/to local Wireguard and sets connection status to StatusConnected
func (conn *Conn) startProxy(remoteConn net.Conn) error {
	conn.mu.Lock()
	defer conn.mu.Unlock()

	conn.proxy = proxy.NewWireguardProxy(conn.config.ProxyConfig)
	err := conn.proxy.Start(remoteConn)
	if err != nil {
		return err
	}
	conn.status = StatusConnected

	return nil
}

// cleanup closes all open resources and sets status to StatusDisconnected
func (conn *Conn) cleanup() error {
	log.Debugf("trying to cleanup %s", conn.config.Key)
	conn.mu.Lock()
	defer conn.mu.Unlock()

	if conn.agent != nil {
		err := conn.agent.Close()
		if err != nil {
			return err
		}
	}

	if conn.proxy != nil {
		err := conn.proxy.Close()
		if err != nil {
			return err
		}
	}

	conn.status = StatusDisconnected

	log.Debugf("cleaned up connection to peer %s", conn.config.Key)

	return nil
}

// SetSignalOffer sets a handler function to be triggered by Conn when a new connection offer has to be signalled to the remote peer
func (conn *Conn) SetSignalOffer(handler func(uFrag string, pwd string) error) {
	conn.signalOffer = handler
}

// SetSignalAnswer sets a handler function to be triggered by Conn when a new connection answer has to be signalled to the remote peer
func (conn *Conn) SetSignalAnswer(handler func(uFrag string, pwd string) error) {
	conn.signalAnswer = handler
}

// SetSignalCandidate sets a handler function to be triggered by Conn when a new ICE local connection candidate has to be signalled to the remote peer
func (conn *Conn) SetSignalCandidate(handler func(candidate ice.Candidate) error) {
	conn.signalCandidate = handler
}

// onICECandidate is a callback attached to an ICE Agent to receive new local connection candidates
// and then signals them to the remote peer
func (conn *Conn) onICECandidate(candidate ice.Candidate) {
	if candidate != nil {
		//log.Debugf("discovered local candidate %s", candidate.String())
		go func() {
			err := conn.signalCandidate(candidate)
			if err != nil {
				log.Errorf("failed signaling candidate to the remote peer %s %s", conn.config.Key, err)
			}
		}()
	}
}

func (conn *Conn) onICESelectedCandidatePair(c1 ice.Candidate, c2 ice.Candidate) {
	log.Debugf("selected candidate pair [local <-> remote] -> [%s <-> %s], peer %s", conn.config.Key,
		c1.String(), c2.String())
}

// onICEConnectionStateChange registers callback of an ICE Agent to track connection state
func (conn *Conn) onICEConnectionStateChange(state ice.ConnectionState) {
	log.Debugf("peer %s ICE ConnectionState has changed to %s", conn.config.Key, state.String())
	if state == ice.ConnectionStateFailed || state == ice.ConnectionStateDisconnected {
		conn.notifyDisconnected()
	}
}

func (conn *Conn) sendAnswer() error {
	conn.mu.Lock()
	defer conn.mu.Unlock()

	localUFrag, localPwd, err := conn.agent.GetLocalUserCredentials()
	if err != nil {
		return err
	}

	log.Debugf("sending asnwer to %s", conn.config.Key)
	err = conn.signalAnswer(localUFrag, localPwd)
	if err != nil {
		return err
	}

	return nil
}

// sendOffer prepares local user credentials and signals them to the remote peer
func (conn *Conn) sendOffer() error {
	conn.mu.Lock()
	defer conn.mu.Unlock()

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

// Close closes this peer Conn issuing a close event to the Conn closeCh
func (conn *Conn) Close() error {
	conn.mu.Lock()
	defer conn.mu.Unlock()
	conn.closeCh <- struct{}{}
	return nil
}

// Status returns current status of the Conn
func (conn *Conn) Status() ConnStatus {
	conn.mu.Lock()
	defer conn.mu.Unlock()
	return conn.status
}

// OnRemoteOffer handles an offer from the remote peer
// can block until Conn restarts
func (conn *Conn) OnRemoteOffer(remoteAuth IceCredentials) {
	log.Debugf("OnRemoteOffer from peer %s on status %s", conn.config.Key, conn.status.String())

	select {
	case conn.remoteOffersCh <- remoteAuth:
	default:
		log.Debugf("OnRemoteOffer skipping message from peer %s on status %s because is not ready", conn.config.Key, conn.status.String())
		//connection might not be ready yet to receive so we ignore the message
	}
}

// OnRemoteAnswer handles an offer from the remote peer
// can block until Conn restarts
func (conn *Conn) OnRemoteAnswer(remoteAuth IceCredentials) {
	log.Debugf("OnRemoteAnswer from peer %s on status %s", conn.config.Key, conn.status.String())

	select {
	case conn.remoteAnswerCh <- remoteAuth:
	default:
		//connection might not be ready yet to receive so we ignore the message
		log.Debugf("OnRemoteAnswer skipping message from peer %s on status %s because is not ready", conn.config.Key, conn.status.String())
	}
}

// OnRemoteCandidate Handles ICE connection Candidate provided by the remote peer.
func (conn *Conn) OnRemoteCandidate(candidate ice.Candidate) {
	log.Debugf("OnRemoteCandidate from peer %s -> %s", conn.config.Key, candidate.String())
	go func() {
		conn.mu.Lock()
		defer conn.mu.Unlock()

		err := conn.agent.AddRemoteCandidate(candidate)
		if err != nil {
			log.Errorf("error while handling remote candidate from peer %s", conn.config.Key)
			return
		}
	}()
}
