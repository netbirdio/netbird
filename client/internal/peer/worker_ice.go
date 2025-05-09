package peer

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/pion/ice/v3"
	"github.com/pion/stun/v2"
	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/iface"
	"github.com/netbirdio/netbird/client/iface/bind"
	"github.com/netbirdio/netbird/client/internal/peer/conntype"
	icemaker "github.com/netbirdio/netbird/client/internal/peer/ice"
	"github.com/netbirdio/netbird/client/internal/stdnet"
	"github.com/netbirdio/netbird/route"
)

type ICEConnInfo struct {
	RemoteConn                 net.Conn
	RosenpassPubKey            []byte
	RosenpassAddr              string
	LocalIceCandidateType      string
	RemoteIceCandidateType     string
	RemoteIceCandidateEndpoint string
	LocalIceCandidateEndpoint  string
	Relayed                    bool
	RelayedOnLocal             bool
}

type WorkerICE struct {
	ctx               context.Context
	log               *log.Entry
	config            ConnConfig
	conn              *Conn
	signaler          *Signaler
	iFaceDiscover     stdnet.ExternalIFaceDiscover
	statusRecorder    *Status
	hasRelayOnLocally bool

	agent    *ice.Agent
	muxAgent sync.Mutex

	StunTurn []*stun.URI

	sentExtraSrflx bool

	localUfrag string
	localPwd   string

	// we record the last known state of the ICE agent to avoid duplicate on disconnected events
	lastKnownState ice.ConnectionState
}

func NewWorkerICE(ctx context.Context, log *log.Entry, config ConnConfig, conn *Conn, signaler *Signaler, ifaceDiscover stdnet.ExternalIFaceDiscover, statusRecorder *Status, hasRelayOnLocally bool) (*WorkerICE, error) {
	w := &WorkerICE{
		ctx:               ctx,
		log:               log,
		config:            config,
		conn:              conn,
		signaler:          signaler,
		iFaceDiscover:     ifaceDiscover,
		statusRecorder:    statusRecorder,
		hasRelayOnLocally: hasRelayOnLocally,
		lastKnownState:    ice.ConnectionStateDisconnected,
	}

	localUfrag, localPwd, err := icemaker.GenerateICECredentials()
	if err != nil {
		return nil, err
	}
	w.localUfrag = localUfrag
	w.localPwd = localPwd
	return w, nil
}

func (w *WorkerICE) OnNewOffer(remoteOfferAnswer *OfferAnswer) {
	w.log.Debugf("OnNewOffer for ICE")
	w.muxAgent.Lock()

	if w.agent != nil {
		w.log.Debugf("agent already exists, skipping the offer")
		w.muxAgent.Unlock()
		return
	}

	var preferredCandidateTypes []ice.CandidateType
	if w.hasRelayOnLocally && remoteOfferAnswer.RelaySrvAddress != "" {
		preferredCandidateTypes = icemaker.CandidateTypesP2P()
	} else {
		preferredCandidateTypes = icemaker.CandidateTypes()
	}

	w.log.Debugf("recreate ICE agent")
	agentCtx, agentCancel := context.WithCancel(w.ctx)
	agent, err := w.reCreateAgent(agentCancel, preferredCandidateTypes)
	if err != nil {
		w.log.Errorf("failed to recreate ICE Agent: %s", err)
		w.muxAgent.Unlock()
		return
	}
	w.agent = agent
	w.muxAgent.Unlock()

	w.log.Debugf("gather candidates")
	err = w.agent.GatherCandidates()
	if err != nil {
		w.log.Debugf("failed to gather candidates: %s", err)
		return
	}

	// will block until connection succeeded
	// but it won't release if ICE Agent went into Disconnected or Failed state,
	// so we have to cancel it with the provided context once agent detected a broken connection
	w.log.Debugf("turn agent dial")
	remoteConn, err := w.turnAgentDial(agentCtx, remoteOfferAnswer)
	if err != nil {
		w.log.Debugf("failed to dial the remote peer: %s", err)
		return
	}
	w.log.Debugf("agent dial succeeded")

	pair, err := w.agent.GetSelectedCandidatePair()
	if err != nil {
		return
	}

	if !isRelayCandidate(pair.Local) {
		// dynamically set remote WireGuard port if other side specified a different one from the default one
		remoteWgPort := iface.DefaultWgPort
		if remoteOfferAnswer.WgListenPort != 0 {
			remoteWgPort = remoteOfferAnswer.WgListenPort
		}

		// To support old version's with direct mode we attempt to punch an additional role with the remote WireGuard port
		go w.punchRemoteWGPort(pair, remoteWgPort)
	}

	ci := ICEConnInfo{
		RemoteConn:                 remoteConn,
		RosenpassPubKey:            remoteOfferAnswer.RosenpassPubKey,
		RosenpassAddr:              remoteOfferAnswer.RosenpassAddr,
		LocalIceCandidateType:      pair.Local.Type().String(),
		RemoteIceCandidateType:     pair.Remote.Type().String(),
		LocalIceCandidateEndpoint:  fmt.Sprintf("%s:%d", pair.Local.Address(), pair.Local.Port()),
		RemoteIceCandidateEndpoint: fmt.Sprintf("%s:%d", pair.Remote.Address(), pair.Remote.Port()),
		Relayed:                    isRelayed(pair),
		RelayedOnLocal:             isRelayCandidate(pair.Local),
	}
	w.log.Debugf("on ICE conn is ready to use")
	go w.conn.onICEConnectionIsReady(selectedPriority(pair), ci)
}

// OnRemoteCandidate Handles ICE connection Candidate provided by the remote peer.
func (w *WorkerICE) OnRemoteCandidate(candidate ice.Candidate, haRoutes route.HAMap) {
	w.muxAgent.Lock()
	defer w.muxAgent.Unlock()
	w.log.Debugf("OnRemoteCandidate from peer %s -> %s", w.config.Key, candidate.String())
	if w.agent == nil {
		w.log.Warnf("ICE Agent is not initialized yet")
		return
	}

	if candidateViaRoutes(candidate, haRoutes) {
		return
	}

	err := w.agent.AddRemoteCandidate(candidate)
	if err != nil {
		w.log.Errorf("error while handling remote candidate")
		return
	}
}

func (w *WorkerICE) GetLocalUserCredentials() (frag string, pwd string) {
	w.muxAgent.Lock()
	defer w.muxAgent.Unlock()
	return w.localUfrag, w.localPwd
}

func (w *WorkerICE) Close() {
	w.muxAgent.Lock()
	defer w.muxAgent.Unlock()

	if w.agent == nil {
		return
	}

	if err := w.agent.Close(); err != nil {
		w.log.Warnf("failed to close ICE agent: %s", err)
	}
}

func (w *WorkerICE) reCreateAgent(agentCancel context.CancelFunc, candidates []ice.CandidateType) (*ice.Agent, error) {
	w.sentExtraSrflx = false

	agent, err := icemaker.NewAgent(w.iFaceDiscover, w.config.ICEConfig, candidates, w.localUfrag, w.localPwd)
	if err != nil {
		return nil, fmt.Errorf("create agent: %w", err)
	}

	err = agent.OnCandidate(w.onICECandidate)
	if err != nil {
		return nil, err
	}

	err = agent.OnConnectionStateChange(func(state ice.ConnectionState) {
		w.log.Debugf("ICE ConnectionState has changed to %s", state.String())
		switch state {
		case ice.ConnectionStateConnected:
			w.lastKnownState = ice.ConnectionStateConnected
			return
		case ice.ConnectionStateFailed, ice.ConnectionStateDisconnected:
			if w.lastKnownState == ice.ConnectionStateConnected {
				w.lastKnownState = ice.ConnectionStateDisconnected
				w.conn.onICEStateDisconnected()
			}
			w.closeAgent(agentCancel)
		default:
			return
		}
	})
	if err != nil {
		return nil, err
	}

	err = agent.OnSelectedCandidatePairChange(w.onICESelectedCandidatePair)
	if err != nil {
		return nil, err
	}

	err = agent.OnSuccessfulSelectedPairBindingResponse(func(p *ice.CandidatePair) {
		err := w.statusRecorder.UpdateLatency(w.config.Key, p.Latency())
		if err != nil {
			w.log.Debugf("failed to update latency for peer: %s", err)
			return
		}
	})
	if err != nil {
		return nil, fmt.Errorf("failed setting binding response callback: %w", err)
	}

	return agent, nil
}

func (w *WorkerICE) closeAgent(cancel context.CancelFunc) {
	w.muxAgent.Lock()
	defer w.muxAgent.Unlock()

	cancel()
	if w.agent == nil {
		return
	}

	if err := w.agent.Close(); err != nil {
		w.log.Warnf("failed to close ICE agent: %s", err)
	}
	w.agent = nil
}

func (w *WorkerICE) punchRemoteWGPort(pair *ice.CandidatePair, remoteWgPort int) {
	// wait local endpoint configuration
	time.Sleep(time.Second)
	addrString := pair.Remote.Address()
	parsed, err := netip.ParseAddr(addrString)
	if (err == nil) && (parsed.Is6()) {
		addrString = fmt.Sprintf("[%s]", addrString)
		//IPv6 Literals need to be wrapped in brackets for Resolve*Addr()
	}
	addr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", addrString, remoteWgPort))
	if err != nil {
		w.log.Warnf("got an error while resolving the udp address, err: %s", err)
		return
	}

	mux, ok := w.config.ICEConfig.UDPMuxSrflx.(*bind.UniversalUDPMuxDefault)
	if !ok {
		w.log.Warn("invalid udp mux conversion")
		return
	}
	_, err = mux.GetSharedConn().WriteTo([]byte{0x6e, 0x62}, addr)
	if err != nil {
		w.log.Warnf("got an error while sending the punch packet, err: %s", err)
	}
}

// onICECandidate is a callback attached to an ICE Agent to receive new local connection candidates
// and then signals them to the remote peer
func (w *WorkerICE) onICECandidate(candidate ice.Candidate) {
	// nil means candidate gathering has been ended
	if candidate == nil {
		return
	}

	// TODO: reported port is incorrect for CandidateTypeHost, makes understanding ICE use via logs confusing as port is ignored
	w.log.Debugf("discovered local candidate %s", candidate.String())
	go func() {
		err := w.signaler.SignalICECandidate(candidate, w.config.Key)
		if err != nil {
			w.log.Errorf("failed signaling candidate to the remote peer %s %s", w.config.Key, err)
		}
	}()

	if !w.shouldSendExtraSrflxCandidate(candidate) {
		return
	}

	// sends an extra server reflexive candidate to the remote peer with our related port (usually the wireguard port)
	// this is useful when network has an existing port forwarding rule for the wireguard port and this peer
	extraSrflx, err := extraSrflxCandidate(candidate)
	if err != nil {
		w.log.Errorf("failed creating extra server reflexive candidate %s", err)
		return
	}
	w.sentExtraSrflx = true

	go func() {
		err = w.signaler.SignalICECandidate(extraSrflx, w.config.Key)
		if err != nil {
			w.log.Errorf("failed signaling the extra server reflexive candidate: %s", err)
		}
	}()
}

func (w *WorkerICE) onICESelectedCandidatePair(c1 ice.Candidate, c2 ice.Candidate) {
	w.log.Debugf("selected candidate pair [local <-> remote] -> [%s <-> %s], peer %s", c1.String(), c2.String(),
		w.config.Key)
}

func (w *WorkerICE) shouldSendExtraSrflxCandidate(candidate ice.Candidate) bool {
	if !w.sentExtraSrflx && candidate.Type() == ice.CandidateTypeServerReflexive && candidate.Port() != candidate.RelatedAddress().Port {
		return true
	}
	return false
}

func (w *WorkerICE) turnAgentDial(ctx context.Context, remoteOfferAnswer *OfferAnswer) (*ice.Conn, error) {
	isControlling := w.config.LocalKey > w.config.Key
	if isControlling {
		return w.agent.Dial(ctx, remoteOfferAnswer.IceCredentials.UFrag, remoteOfferAnswer.IceCredentials.Pwd)
	} else {
		return w.agent.Accept(ctx, remoteOfferAnswer.IceCredentials.UFrag, remoteOfferAnswer.IceCredentials.Pwd)
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
	addr, err := netip.ParseAddr(candidate.Address())
	if err != nil {
		log.Errorf("Failed to parse IP address %s: %v", candidate.Address(), err)
		return false
	}

	var routePrefixes []netip.Prefix
	for _, routes := range clientRoutes {
		if len(routes) > 0 && routes[0] != nil {
			routePrefixes = append(routePrefixes, routes[0].Network)
		}
	}

	for _, prefix := range routePrefixes {
		// default route is handled by route exclusion / ip rules
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

func isRelayCandidate(candidate ice.Candidate) bool {
	return candidate.Type() == ice.CandidateTypeRelay
}

func isRelayed(pair *ice.CandidatePair) bool {
	if pair.Local.Type() == ice.CandidateTypeRelay || pair.Remote.Type() == ice.CandidateTypeRelay {
		return true
	}
	return false
}

func selectedPriority(pair *ice.CandidatePair) conntype.ConnPriority {
	if isRelayed(pair) {
		return conntype.ICETurn
	} else {
		return conntype.ICEP2P
	}
}
