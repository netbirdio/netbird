package peer

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"net"
	"net/netip"
	"runtime"
	"sync/atomic"
	"time"

	"github.com/pion/ice/v3"
	"github.com/pion/stun/v2"
	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/internal"
	"github.com/netbirdio/netbird/client/internal/stdnet"
	"github.com/netbirdio/netbird/iface"
	"github.com/netbirdio/netbird/iface/bind"
	"github.com/netbirdio/netbird/route"
)

const (
	iceKeepAliveDefault           = 4 * time.Second
	iceDisconnectedTimeoutDefault = 6 * time.Second
	// iceRelayAcceptanceMinWaitDefault is the same as in the Pion ICE package
	iceRelayAcceptanceMinWaitDefault = 2 * time.Second
)

type ICEConfig struct {
	// StunTurn is a list of STUN and TURN URLs
	StunTurn atomic.Value // []*stun.URI

	// InterfaceBlackList is a list of machine interfaces that should be filtered out by ICE Candidate gathering
	// (e.g. if eth0 is in the list, host candidate of this interface won't be used)
	InterfaceBlackList   []string
	DisableIPv6Discovery bool

	UDPMux      ice.UDPMux
	UDPMuxSrflx ice.UniversalUDPMux

	NATExternalIPs []string
}

type OnICEConnReadyCallback func(ConnPriority, ICEConnInfo)

type ICEConnInfo struct {
	RemoteConn                 net.Conn
	RosenpassPubKey            []byte
	RosenpassAddr              string
	LocalIceCandidateType      string
	RemoteIceCandidateType     string
	RemoteIceCandidateEndpoint string
	LocalIceCandidateEndpoint  string
	Direct                     bool
	Relayed                    bool
	RelayedOnLocal             bool
}

type ConnectorICE struct {
	ctx            context.Context
	log            *log.Entry
	config         ConnConfig
	configICE      ICEConfig
	signaler       *internal.Signaler
	iFaceDiscover  stdnet.ExternalIFaceDiscover
	statusRecorder *Status
	onICEConnReady OnICEConnReadyCallback
	doHandshakeFn  DoHandshake

	connPriority ConnPriority

	agent *ice.Agent

	StunTurn []*stun.URI

	sentExtraSrflx bool
}

func NewConnectorICE(ctx context.Context, log *log.Entry, config ConnConfig, configICE ICEConfig, signaler *internal.Signaler, ifaceDiscover stdnet.ExternalIFaceDiscover, statusRecorder *Status, onICEConnReady OnICEConnReadyCallback, doHandshakeFn DoHandshake) *ConnectorICE {
	cice := &ConnectorICE{
		ctx:            ctx,
		log:            log,
		config:         config,
		configICE:      configICE,
		signaler:       signaler,
		iFaceDiscover:  ifaceDiscover,
		statusRecorder: statusRecorder,
		onICEConnReady: onICEConnReady,
		doHandshakeFn:  doHandshakeFn,
	}
	return cice
}

// SetupICEConnection sets up an ICE connection with the remote peer.
// If the relay mode is supported then try to connect in p2p way only.
// It is trying to reconnection in a loop until the context is canceled.
// In case of success connection it will call the onICEConnReady callback.
func (conn *ConnectorICE) SetupICEConnection(relayMode bool) {
	var preferredCandidateTypes []ice.CandidateType
	if relayMode {
		conn.connPriority = connPriorityICEP2P
		preferredCandidateTypes = candidateTypesP2P()
	} else {
		conn.connPriority = connPriorityICETurn
		preferredCandidateTypes = candidateTypes()
	}

	for {
		if !conn.waitForReconnectTry() {
			return
		}

		remoteOfferAnswer, err := conn.doHandshakeFn()
		if err != nil {
			if errors.Is(err, ErrSignalIsNotReady) {
				conn.log.Infof("signal client isn't ready, skipping connection attempt")
			}
			continue
		}

		ctx, ctxCancel := context.WithCancel(conn.ctx)
		agent, err := conn.reCreateAgent(ctxCancel, preferredCandidateTypes)
		if err != nil {
			ctxCancel()
			continue
		}
		conn.agent = agent

		err = conn.agent.GatherCandidates()
		if err != nil {
			ctxCancel()
			continue
		}

		// will block until connection succeeded
		// but it won't release if ICE Agent went into Disconnected or Failed state,
		// so we have to cancel it with the provided context once agent detected a broken connection
		remoteConn, err := conn.turnAgentDial(remoteOfferAnswer)
		if err != nil {
			ctxCancel()
			continue
		}

		pair, err := conn.agent.GetSelectedCandidatePair()
		if err != nil {
			ctxCancel()
			continue
		}

		if !isRelayCandidate(pair.Local) {
			// dynamically set remote WireGuard port if other side specified a different one from the default one
			remoteWgPort := iface.DefaultWgPort
			if remoteOfferAnswer.WgListenPort != 0 {
				remoteWgPort = remoteOfferAnswer.WgListenPort
			}

			// To support old version's with direct mode we attempt to punch an additional role with the remote WireGuard port
			go conn.punchRemoteWGPort(pair, remoteWgPort)
		}

		ci := ICEConnInfo{
			RemoteConn:                 remoteConn,
			RosenpassPubKey:            remoteOfferAnswer.RosenpassPubKey,
			RosenpassAddr:              remoteOfferAnswer.RosenpassAddr,
			LocalIceCandidateType:      pair.Local.Type().String(),
			RemoteIceCandidateType:     pair.Remote.Type().String(),
			LocalIceCandidateEndpoint:  fmt.Sprintf("%s:%d", pair.Local.Address(), pair.Local.Port()),
			RemoteIceCandidateEndpoint: fmt.Sprintf("%s:%d", pair.Remote.Address(), pair.Remote.Port()),
			Direct:                     !isRelayCandidate(pair.Local),
			Relayed:                    isRelayed(pair),
			RelayedOnLocal:             isRelayCandidate(pair.Local),
		}
		go conn.onICEConnReady(conn.connPriority, ci)

		<-ctx.Done()
		ctxCancel()
		_ = conn.agent.Close()
	}
}

// OnRemoteCandidate Handles ICE connection Candidate provided by the remote peer.
func (conn *ConnectorICE) OnRemoteCandidate(candidate ice.Candidate, haRoutes route.HAMap) {
	conn.log.Debugf("OnRemoteCandidate from peer %s -> %s", conn.config.Key, candidate.String())
	if conn.agent == nil {
		return
	}

	if candidateViaRoutes(candidate, haRoutes) {
		return
	}

	err := conn.agent.AddRemoteCandidate(candidate)
	if err != nil {
		conn.log.Errorf("error while handling remote candidate")
		return
	}
}

func (conn *ConnectorICE) GetLocalUserCredentials() (frag string, pwd string, err error) {
	if conn.agent == nil {
		return "", "", errors.New("ICE Agent is not initialized")
	}
	return conn.agent.GetLocalUserCredentials()
}

func (conn *ConnectorICE) reCreateAgent(ctxCancel context.CancelFunc, relaySupport []ice.CandidateType) (*ice.Agent, error) {
	failedTimeout := 6 * time.Second
	transportNet, err := conn.newStdNet()
	if err != nil {
		conn.log.Errorf("failed to create pion's stdnet: %s", err)
	}

	iceKeepAlive := iceKeepAlive()
	iceDisconnectedTimeout := iceDisconnectedTimeout()
	iceRelayAcceptanceMinWait := iceRelayAcceptanceMinWait()

	agentConfig := &ice.AgentConfig{
		MulticastDNSMode:       ice.MulticastDNSModeDisabled,
		NetworkTypes:           []ice.NetworkType{ice.NetworkTypeUDP4, ice.NetworkTypeUDP6},
		Urls:                   conn.configICE.StunTurn.Load().([]*stun.URI),
		CandidateTypes:         relaySupport,
		FailedTimeout:          &failedTimeout,
		InterfaceFilter:        stdnet.InterfaceFilter(conn.configICE.InterfaceBlackList),
		UDPMux:                 conn.configICE.UDPMux,
		UDPMuxSrflx:            conn.configICE.UDPMuxSrflx,
		NAT1To1IPs:             conn.configICE.NATExternalIPs,
		Net:                    transportNet,
		DisconnectedTimeout:    &iceDisconnectedTimeout,
		KeepaliveInterval:      &iceKeepAlive,
		RelayAcceptanceMinWait: &iceRelayAcceptanceMinWait,
	}

	if conn.configICE.DisableIPv6Discovery {
		agentConfig.NetworkTypes = []ice.NetworkType{ice.NetworkTypeUDP4}
	}

	conn.sentExtraSrflx = false
	agent, err := ice.NewAgent(agentConfig)
	if err != nil {
		return nil, err
	}

	err = agent.OnCandidate(conn.onICECandidate)
	if err != nil {
		return nil, err
	}

	err = agent.OnConnectionStateChange(func(state ice.ConnectionState) {
		conn.log.Debugf("ICE ConnectionState has changed to %s", state.String())
		if state == ice.ConnectionStateFailed || state == ice.ConnectionStateDisconnected {
			ctxCancel()
		}
	})
	if err != nil {
		return nil, err
	}

	err = agent.OnSelectedCandidatePairChange(conn.onICESelectedCandidatePair)
	if err != nil {
		return nil, err
	}

	err = agent.OnSuccessfulSelectedPairBindingResponse(func(p *ice.CandidatePair) {
		err := conn.statusRecorder.UpdateLatency(conn.config.Key, p.Latency())
		if err != nil {
			conn.log.Debugf("failed to update latency for peer: %s", err)
			return
		}
	})
	if err != nil {
		return nil, fmt.Errorf("failed setting binding response callback: %w", err)
	}

	return agent, nil
}

func (conn *ConnectorICE) punchRemoteWGPort(pair *ice.CandidatePair, remoteWgPort int) {
	// wait local endpoint configuration
	time.Sleep(time.Second)
	addr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", pair.Remote.Address(), remoteWgPort))
	if err != nil {
		conn.log.Warnf("got an error while resolving the udp address, err: %s", err)
		return
	}

	mux, ok := conn.configICE.UDPMuxSrflx.(*bind.UniversalUDPMuxDefault)
	if !ok {
		conn.log.Warn("invalid udp mux conversion")
		return
	}
	_, err = mux.GetSharedConn().WriteTo([]byte{0x6e, 0x62}, addr)
	if err != nil {
		conn.log.Warnf("got an error while sending the punch packet, err: %s", err)
	}
}

// onICECandidate is a callback attached to an ICE Agent to receive new local connection candidates
// and then signals them to the remote peer
func (conn *ConnectorICE) onICECandidate(candidate ice.Candidate) {
	// nil means candidate gathering has been ended
	if candidate == nil {
		return
	}

	// TODO: reported port is incorrect for CandidateTypeHost, makes understanding ICE use via logs confusing as port is ignored
	conn.log.Debugf("discovered local candidate %s", candidate.String())
	go func() {
		err := conn.signaler.SignalICECandidate(candidate, conn.config.Key)
		if err != nil {
			conn.log.Errorf("failed signaling candidate to the remote peer %s %s", conn.config.Key, err)
		}
	}()

	if !conn.shouldSendExtraSrflxCandidate(candidate) {
		return
	}

	// sends an extra server reflexive candidate to the remote peer with our related port (usually the wireguard port)
	// this is useful when network has an existing port forwarding rule for the wireguard port and this peer
	extraSrflx, err := extraSrflxCandidate(candidate)
	if err != nil {
		conn.log.Errorf("failed creating extra server reflexive candidate %s", err)
		return
	}
	conn.sentExtraSrflx = true

	go func() {
		err = conn.signaler.SignalICECandidate(extraSrflx, conn.config.Key)
		if err != nil {
			conn.log.Errorf("failed signaling the extra server reflexive candidate: %s", err)
		}
	}()
}

func (conn *ConnectorICE) onICESelectedCandidatePair(c1 ice.Candidate, c2 ice.Candidate) {
	conn.log.Debugf("selected candidate pair [local <-> remote] -> [%s <-> %s], peer %s", c1.String(), c2.String(),
		conn.config.Key)
}

func (conn *ConnectorICE) shouldSendExtraSrflxCandidate(candidate ice.Candidate) bool {
	if !conn.sentExtraSrflx && candidate.Type() == ice.CandidateTypeServerReflexive && candidate.Port() != candidate.RelatedAddress().Port {
		return true
	}
	return false
}

func (conn *ConnectorICE) turnAgentDial(remoteOfferAnswer *OfferAnswer) (*ice.Conn, error) {
	isControlling := conn.config.LocalKey > conn.config.Key
	if isControlling {
		return conn.agent.Dial(conn.ctx, remoteOfferAnswer.IceCredentials.UFrag, remoteOfferAnswer.IceCredentials.Pwd)
	} else {
		return conn.agent.Accept(conn.ctx, remoteOfferAnswer.IceCredentials.UFrag, remoteOfferAnswer.IceCredentials.Pwd)
	}
}

// waitForReconnectTry waits for a random duration before trying to reconnect
func (conn *ConnectorICE) waitForReconnectTry() bool {
	minWait := 500
	maxWait := 2000
	duration := time.Duration(rand.Intn(maxWait-minWait)+minWait) * time.Millisecond
	select {
	case <-conn.ctx.Done():
		return false
	case <-time.After(duration):
		return true
	}
}

func extraSrflxCandidate(candidate ice.Candidate) (*ice.CandidateServerReflexive, error) {
	relatedAdd := candidate.RelatedAddress()
	return ice.NewCandidateServerReflexive(&ice.CandidateServerReflexiveConfig{
		Network:   candidate.NetworkType().String(),
		Address:   candidate.Address(),
		Port:      relatedAdd.Port,
		Component: candidate.Component(),
		RelAddr:   relatedAdd.Address,
		RelPort:   relatedAdd.Port,
	})
}

func candidateViaRoutes(candidate ice.Candidate, clientRoutes route.HAMap) bool {
	var routePrefixes []netip.Prefix
	for _, routes := range clientRoutes {
		if len(routes) > 0 && routes[0] != nil {
			routePrefixes = append(routePrefixes, routes[0].Network)
		}
	}

	addr, err := netip.ParseAddr(candidate.Address())
	if err != nil {
		log.Errorf("Failed to parse IP address %s: %v", candidate.Address(), err)
		return false
	}

	for _, prefix := range routePrefixes {
		// default route is
		if prefix.Bits() == 0 {
			continue
		}

		if prefix.Contains(addr) {
			log.Debugf("Ignoring candidate [%s], its address is part of routed network %s", candidate.String(), prefix)
			return true
		}
	}
	return false
}

func candidateTypes() []ice.CandidateType {
	if hasICEForceRelayConn() {
		return []ice.CandidateType{ice.CandidateTypeRelay}
	}
	// TODO: remove this once we have refactored userspace proxy into the bind package
	if runtime.GOOS == "ios" {
		return []ice.CandidateType{ice.CandidateTypeHost, ice.CandidateTypeServerReflexive}
	}
	return []ice.CandidateType{ice.CandidateTypeHost, ice.CandidateTypeServerReflexive, ice.CandidateTypeRelay}
}

func candidateTypesP2P() []ice.CandidateType {
	return []ice.CandidateType{ice.CandidateTypeHost, ice.CandidateTypeServerReflexive}
}

func isRelayCandidate(candidate ice.Candidate) bool {
	return candidate.Type() == ice.CandidateTypeRelay
}

func isRelayed(pair *ice.CandidatePair) bool {
	if pair.Local.Type() == ice.CandidateTypeRelay || pair.Remote.Type() == ice.CandidateTypeRelay {
		return true
	}
	return false
}
