package peer

import (
	"context"
	"github.com/pion/ice/v2"
	log "github.com/sirupsen/logrus"
	"sync"
	"time"
)

// Config is a peer Connection configuration
type Config struct {

	// RemoteKey is a public key of a remote peer
	RemoteKey string
	// LocalKey is a public key of a local peer
	LocalKey string

	// StunTurn is a list of STUN and TURN URLs
	StunTurn []*ice.URL

	// InterfaceBlackList is a list of machine interfaces that should be filtered out by ICE Candidate gathering
	// (e.g. if eth0 is in the list, host candidate of this interface won't be used)
	InterfaceBlackList []string

	Timeout time.Duration
}

// IceCredentials ICE protocol credentials struct
type IceCredentials struct {
	uFrag string
	pwd   string
}

type Conn struct {
	config Config
	mu     sync.Mutex

	// signalCandidate is a handler function to signal remote peer about local connection candidate
	signalCandidate func(candidate ice.Candidate) error
	// signalOffer is a handler function to signal remote peer our connection offer (credentials)
	signalOffer func(uFrag string, pwd string) error

	// remoteAuthCh is a channel used to wait for remote credentials to proceed with the connection
	remoteAuthCh chan IceCredentials
	closeCh      chan struct{}

	agent  *ice.Agent
	status ConnStatus
}

func New(config Config) (*Conn, error) {
	agent, err := ice.NewAgent(&ice.AgentConfig{
		MulticastDNSMode: ice.MulticastDNSModeDisabled,
		NetworkTypes:     []ice.NetworkType{ice.NetworkTypeUDP4},
		Urls:             config.StunTurn,
		CandidateTypes:   []ice.CandidateType{ice.CandidateTypeHost, ice.CandidateTypeServerReflexive, ice.CandidateTypeRelay},
		FailedTimeout:    &config.Timeout,
		InterfaceFilter:  interfaceFilter(config.InterfaceBlackList),
	})
	if err != nil {
		return nil, err
	}

	p := &Conn{
		config:  config,
		mu:      sync.Mutex{},
		agent:   agent,
		status:  StatusDisconnected,
		closeCh: make(chan struct{}),
	}

	err = p.agent.OnCandidate(p.onICECandidate)
	if err != nil {
		return nil, err
	}

	err = p.agent.OnConnectionStateChange(p.onICEConnectionStateChange)
	if err != nil {
		return nil, err
	}

	err = p.agent.OnSelectedCandidatePairChange(func(c1 ice.Candidate, c2 ice.Candidate) {
		log.Debugf("new selected candidate pair [local <-> remote] -> [%s <-> %s]", c1.String(), c2.String())
	})
	if err != nil {
		return nil, err
	}

	return p, nil
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

// Open opens connection to the remote peer
// blocks until connection has been closed or connection timeout
// ConnStatus will be set accordingly
func (p *Conn) Open() error {

	defer func() {
		p.mu.Lock()
		defer p.mu.Unlock()
		p.status = StatusDisconnected
	}()

	p.mu.Lock()
	p.remoteAuthCh = make(chan IceCredentials)
	p.mu.Unlock()

	var err error
	err = p.sendOffer()
	if err != nil {
		return err
	}

	select {
	case remoteAuth := <-p.remoteAuthCh:
		log.Debugf("got a connection confirmation from a remote peer %s", p.config.RemoteKey)

		err = p.agent.GatherCandidates()
		if err != nil {
			return err
		}

		isControlling := p.config.LocalKey > p.config.RemoteKey
		var remoteConn *ice.Conn
		// will block until connection succeeded
		if isControlling {
			remoteConn, err = p.agent.Dial(context.TODO(), remoteAuth.uFrag, remoteAuth.pwd)
		} else {
			remoteConn, err = p.agent.Accept(context.TODO(), remoteAuth.uFrag, remoteAuth.pwd)
		}

		if err != nil {
			return err
		}

		p.mu.Lock()
		log.Debugf("connected to the remote peer %s - laddr %s, raddr %s",
			p.config.RemoteKey, remoteConn.LocalAddr(), remoteConn.RemoteAddr())

		proxy := NewProxy(remoteConn, p.config.RemoteKey)
		proxy.Start()
		p.status = StatusConnected
		p.mu.Unlock()
	case <-time.After(p.config.Timeout):
		return NewConnectionTimeoutError(p.config.RemoteKey, p.config.Timeout)
	}

	<-p.closeCh
	//todo close agent?
	return NewConnectionClosedError(p.config.RemoteKey)
}

// SetSignalOffer sets a handler function to be triggered by Conn when a new connection offer has to be signalled to the remote peer
func (p *Conn) SetSignalOffer(handler func(uFrag string, pwd string) error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.signalOffer = handler
}

// SetSignalCandidate sets a handler function to be triggered by Conn when a new ICE local connection candidate has to be signalled to the remote peer
func (p *Conn) SetSignalCandidate(handler func(candidate ice.Candidate) error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.signalCandidate = handler
}

// onICECandidate is a callback attached to an ICE Agent to receive new local connection candidates
// and then signals them to the remote peer
func (p *Conn) onICECandidate(candidate ice.Candidate) {
	if candidate != nil {
		log.Debugf("discovered local candidate %s", candidate.String())
		go func() {
			err := p.signalCandidate(candidate)
			if err != nil {
				log.Errorf("failed signaling candidate to the remote peer %s %s", p.config.RemoteKey, err)
			}
		}()
	}
}

// onICEConnectionStateChange registers callback of an ICE Agent to track connection state
func (p *Conn) onICEConnectionStateChange(state ice.ConnectionState) {
	log.Debugf("ICE ConnectionState has changed to %s", state.String())
	if state == ice.ConnectionStateDisconnected || state == ice.ConnectionStateFailed {
		err := p.Close()
		if err != nil {
			log.Errorf("error while closing peer %s connecytion", p.config.RemoteKey)
			return
		}
	}
}

// sendOffer prepares local user credentials and signals them to the remote peer
func (p *Conn) sendOffer() error {

	p.mu.Lock()
	defer p.mu.Unlock()

	localUFrag, localPwd, err := p.agent.GetLocalUserCredentials()
	if err != nil {
		return err
	}

	err = p.signalOffer(localUFrag, localPwd)
	if err != nil {
		return err
	}
	return nil
}

// Close closes this peer Conn issuing a close event to the Conn closeCh
func (p *Conn) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.closeCh <- struct{}{}
	return nil
}

// ConnStatus returns current status of the Conn
func (p *Conn) Status() ConnStatus {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.status
}

// OnRemoteOffer handles an offer from the remote peer
// can block until Conn restarts
func (p *Conn) OnRemoteOffer(remoteAuth IceCredentials) {
	p.mu.Lock()
	defer p.mu.Unlock()

	log.Debugf("OnRemoteOffer from peer %s on status %s", p.config.RemoteKey, p.status.String())

	if p.status == StatusConnected {
		return
	}

	if p.remoteAuthCh == nil {
		log.Warnf("nil remoteAuthCh for peer %s", p.config.RemoteKey)
		return
	}

	p.remoteAuthCh <- remoteAuth
	close(p.remoteAuthCh)
	p.remoteAuthCh = nil
}

// OnRemoteCandidate Handles ICE connection Candidate provided by the remote peer.
func (p *Conn) OnRemoteCandidate(candidate ice.Candidate) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	log.Debugf("OnRemoteCandidate from peer %s -> %s", p.config.RemoteKey, candidate.String())

	err := p.agent.AddRemoteCandidate(candidate)
	if err != nil {
		return err
	}

	return nil
}
