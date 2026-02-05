package peer

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"time"

	"github.com/pion/ice/v4"
	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/iface"
	"github.com/netbirdio/netbird/client/iface/udpmux"
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

	agent             *icemaker.ThreadSafeAgent
	agentDialerCancel context.CancelFunc
	agentConnecting   bool      // while it is true, drop all incoming offers
	lastSuccess       time.Time // with this avoid the too frequent ICE agent recreation
	// remoteSessionID represents the peer's session identifier from the latest remote offer.
	remoteSessionID ICESessionID
	// sessionID is used to track the current session ID of the ICE agent
	// increase by one when disconnecting the agent
	// with it the remote peer can discard the already deprecated offer/answer
	// Without it the remote peer may recreate a workable ICE connection
	sessionID ICESessionID
	muxAgent  sync.Mutex

	localUfrag string
	localPwd   string

	// we record the last known state of the ICE agent to avoid duplicate on disconnected events
	lastKnownState ice.ConnectionState
}

func NewWorkerICE(ctx context.Context, log *log.Entry, config ConnConfig, conn *Conn, signaler *Signaler, ifaceDiscover stdnet.ExternalIFaceDiscover, statusRecorder *Status, hasRelayOnLocally bool) (*WorkerICE, error) {
	sessionID, err := NewICESessionID()
	if err != nil {
		return nil, err
	}

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
		sessionID:         sessionID,
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
	w.log.Debugf("OnNewOffer for ICE, serial: %s", remoteOfferAnswer.SessionIDString())
	w.muxAgent.Lock()
	defer w.muxAgent.Unlock()

	if w.agent != nil || w.agentConnecting {
		// backward compatibility with old clients that do not send session ID
		if remoteOfferAnswer.SessionID == nil {
			w.log.Debugf("agent already exists, skipping the offer")
			return
		}
		if w.remoteSessionID == *remoteOfferAnswer.SessionID {
			w.log.Debugf("agent already exists and session ID matches, skipping the offer: %s", remoteOfferAnswer.SessionIDString())
			return
		}
		w.log.Debugf("agent already exists, recreate the connection")
		w.agentDialerCancel()
		if w.agent != nil {
			if err := w.agent.Close(); err != nil {
				w.log.Warnf("failed to close ICE agent: %s", err)
			}
		}

		sessionID, err := NewICESessionID()
		if err != nil {
			w.log.Errorf("failed to create new session ID: %s", err)
		}
		w.sessionID = sessionID
		w.agent = nil
	}

	var preferredCandidateTypes []ice.CandidateType
	if w.hasRelayOnLocally && remoteOfferAnswer.RelaySrvAddress != "" {
		preferredCandidateTypes = icemaker.CandidateTypesP2P()
	} else {
		preferredCandidateTypes = icemaker.CandidateTypes()
	}

	if remoteOfferAnswer.SessionID != nil {
		w.log.Debugf("recreate ICE agent: %s / %s", w.sessionID, *remoteOfferAnswer.SessionID)
	}
	dialerCtx, dialerCancel := context.WithCancel(w.ctx)
	agent, err := w.reCreateAgent(dialerCancel, preferredCandidateTypes)
	if err != nil {
		w.log.Errorf("failed to recreate ICE Agent: %s", err)
		return
	}
	w.agent = agent
	w.agentDialerCancel = dialerCancel
	w.agentConnecting = true
	if remoteOfferAnswer.SessionID != nil {
		w.remoteSessionID = *remoteOfferAnswer.SessionID
	} else {
		w.remoteSessionID = ""
	}

	go w.connect(dialerCtx, agent, remoteOfferAnswer)
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

	if err := w.agent.AddRemoteCandidate(candidate); err != nil {
		w.log.Errorf("error while handling remote candidate")
		return
	}

	if shouldAddExtraCandidate(candidate) {
		// sends an extra server reflexive candidate to the remote peer with our related port (usually the wireguard port)
		// this is useful when network has an existing port forwarding rule for the wireguard port and this peer
		extraSrflx, err := extraSrflxCandidate(candidate)
		if err != nil {
			w.log.Errorf("failed creating extra server reflexive candidate %s", err)
			return
		}

		if err := w.agent.AddRemoteCandidate(extraSrflx); err != nil {
			w.log.Errorf("error while handling remote candidate")
			return
		}
	}
}

func (w *WorkerICE) GetLocalUserCredentials() (frag string, pwd string) {
	return w.localUfrag, w.localPwd
}

func (w *WorkerICE) InProgress() bool {
	w.muxAgent.Lock()
	defer w.muxAgent.Unlock()

	return w.agentConnecting
}

func (w *WorkerICE) Close() {
	w.muxAgent.Lock()
	defer w.muxAgent.Unlock()

	if w.agent == nil {
		return
	}

	w.agentDialerCancel()
	if err := w.agent.Close(); err != nil {
		w.log.Warnf("failed to close ICE agent: %s", err)
	}

	w.agent = nil
}

func (w *WorkerICE) reCreateAgent(dialerCancel context.CancelFunc, candidates []ice.CandidateType) (*icemaker.ThreadSafeAgent, error) {
	agent, err := icemaker.NewAgent(w.ctx, w.iFaceDiscover, w.config.ICEConfig, candidates, w.localUfrag, w.localPwd)
	if err != nil {
		return nil, fmt.Errorf("create agent: %w", err)
	}

	if err := agent.OnCandidate(w.onICECandidate); err != nil {
		return nil, err
	}

	if err := agent.OnConnectionStateChange(w.onConnectionStateChange(agent, dialerCancel)); err != nil {
		return nil, err
	}

	if err := agent.OnSelectedCandidatePairChange(func(c1, c2 ice.Candidate) {
		w.onICESelectedCandidatePair(agent, c1, c2)
	}); err != nil {
		return nil, err
	}

	return agent, nil
}

func (w *WorkerICE) SessionID() ICESessionID {
	w.muxAgent.Lock()
	defer w.muxAgent.Unlock()

	return w.sessionID
}

// will block until connection succeeded
// but it won't release if ICE Agent went into Disconnected or Failed state,
// so we have to cancel it with the provided context once agent detected a broken connection
func (w *WorkerICE) connect(ctx context.Context, agent *icemaker.ThreadSafeAgent, remoteOfferAnswer *OfferAnswer) {
	w.log.Debugf("gather candidates")
	if err := agent.GatherCandidates(); err != nil {
		w.log.Warnf("failed to gather candidates: %s", err)
		w.closeAgent(agent, w.agentDialerCancel)
		return
	}

	w.log.Debugf("turn agent dial")
	remoteConn, err := w.turnAgentDial(ctx, agent, remoteOfferAnswer)
	if err != nil {
		w.log.Debugf("failed to dial the remote peer: %s", err)
		w.closeAgent(agent, w.agentDialerCancel)
		return
	}
	w.log.Debugf("agent dial succeeded")

	pair, err := agent.GetSelectedCandidatePair()
	if err != nil {
		w.closeAgent(agent, w.agentDialerCancel)
		return
	}
	if pair == nil {
		w.log.Warnf("selected candidate pair is nil, cannot proceed")
		w.closeAgent(agent, w.agentDialerCancel)
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
		LocalIceCandidateEndpoint:  net.JoinHostPort(pair.Local.Address(), strconv.Itoa(pair.Local.Port())),
		RemoteIceCandidateEndpoint: net.JoinHostPort(pair.Remote.Address(), strconv.Itoa(pair.Remote.Port())),
		Relayed:                    isRelayed(pair),
		RelayedOnLocal:             isRelayCandidate(pair.Local),
	}
	w.log.Debugf("on ICE conn is ready to use")

	w.log.Infof("connection succeeded with offer session: %s", remoteOfferAnswer.SessionIDString())
	w.muxAgent.Lock()
	w.agentConnecting = false
	w.lastSuccess = time.Now()
	w.muxAgent.Unlock()

	// todo: the potential problem is a race between the onConnectionStateChange
	w.conn.onICEConnectionIsReady(selectedPriority(pair), ci)
}

func (w *WorkerICE) closeAgent(agent *icemaker.ThreadSafeAgent, cancel context.CancelFunc) {
	cancel()
	if err := agent.Close(); err != nil {
		w.log.Warnf("failed to close ICE agent: %s", err)
	}

	w.muxAgent.Lock()

	if w.agent == agent {
		// consider to remove from here and move to the OnNewOffer
		sessionID, err := NewICESessionID()
		if err != nil {
			w.log.Errorf("failed to create new session ID: %s", err)
		}
		w.sessionID = sessionID
		w.agent = nil
		w.agentConnecting = false
		w.remoteSessionID = ""
	}
	w.muxAgent.Unlock()
}

func (w *WorkerICE) punchRemoteWGPort(pair *ice.CandidatePair, remoteWgPort int) {
	// wait local endpoint configuration
	time.Sleep(time.Second)
	addr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(pair.Remote.Address(), strconv.Itoa(remoteWgPort)))
	if err != nil {
		w.log.Warnf("got an error while resolving the udp address, err: %s", err)
		return
	}

	mux, ok := w.config.ICEConfig.UDPMuxSrflx.(*udpmux.UniversalUDPMuxDefault)
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
}

func (w *WorkerICE) onICESelectedCandidatePair(agent *icemaker.ThreadSafeAgent, c1, c2 ice.Candidate) {
	w.log.Debugf("selected candidate pair [local <-> remote] -> [%s <-> %s], peer %s", c1.String(), c2.String(),
		w.config.Key)

	pairStat, ok := agent.GetSelectedCandidatePairStats()
	if !ok {
		w.log.Warnf("failed to get selected candidate pair stats")
		return
	}

	duration := time.Duration(pairStat.CurrentRoundTripTime * float64(time.Second))
	if err := w.statusRecorder.UpdateLatency(w.config.Key, duration); err != nil {
		w.log.Debugf("failed to update latency for peer: %s", err)
		return
	}
}

func (w *WorkerICE) logSuccessfulPaths(agent *icemaker.ThreadSafeAgent) {
	sessionID := w.SessionID()
	stats := agent.GetCandidatePairsStats()
	localCandidates, _ := agent.GetLocalCandidates()
	remoteCandidates, _ := agent.GetRemoteCandidates()

	localMap := make(map[string]ice.Candidate)
	for _, c := range localCandidates {
		localMap[c.ID()] = c
	}
	remoteMap := make(map[string]ice.Candidate)
	for _, c := range remoteCandidates {
		remoteMap[c.ID()] = c
	}

	for _, stat := range stats {
		if stat.State == ice.CandidatePairStateSucceeded {
			local, lok := localMap[stat.LocalCandidateID]
			remote, rok := remoteMap[stat.RemoteCandidateID]
			if !lok || !rok {
				continue
			}
			w.log.Debugf("successful ICE path %s: [%s %s %s] <-> [%s %s %s] rtt=%.3fms",
				sessionID,
				local.NetworkType(), local.Type(), local.Address(),
				remote.NetworkType(), remote.Type(), remote.Address(),
				stat.CurrentRoundTripTime*1000)
		}
	}
}

func (w *WorkerICE) onConnectionStateChange(agent *icemaker.ThreadSafeAgent, dialerCancel context.CancelFunc) func(ice.ConnectionState) {
	return func(state ice.ConnectionState) {
		w.log.Debugf("ICE ConnectionState has changed to %s", state.String())
		switch state {
		case ice.ConnectionStateConnected:
			w.lastKnownState = ice.ConnectionStateConnected
			w.logSuccessfulPaths(agent)
			return
		case ice.ConnectionStateFailed, ice.ConnectionStateDisconnected, ice.ConnectionStateClosed:
			// ice.ConnectionStateClosed happens when we recreate the agent. For the P2P to TURN switch important to
			// notify the conn.onICEStateDisconnected changes to update the current used priority

			w.closeAgent(agent, dialerCancel)

			if w.lastKnownState == ice.ConnectionStateConnected {
				w.lastKnownState = ice.ConnectionStateDisconnected
				w.conn.onICEStateDisconnected()
			}
		default:
			return
		}
	}
}

func (w *WorkerICE) turnAgentDial(ctx context.Context, agent *icemaker.ThreadSafeAgent, remoteOfferAnswer *OfferAnswer) (*ice.Conn, error) {
	if isController(w.config) {
		return agent.Dial(ctx, remoteOfferAnswer.IceCredentials.UFrag, remoteOfferAnswer.IceCredentials.Pwd)
	} else {
		return agent.Accept(ctx, remoteOfferAnswer.IceCredentials.UFrag, remoteOfferAnswer.IceCredentials.Pwd)
	}
}

func shouldAddExtraCandidate(candidate ice.Candidate) bool {
	if candidate.Type() != ice.CandidateTypeServerReflexive {
		return false
	}

	if candidate.Port() == candidate.RelatedAddress().Port {
		return false
	}

	// in the older version when we didn't set candidate ID extension the remote peer sent the extra candidates
	// in newer version we generate locally the extra candidate
	if _, ok := candidate.GetExtension(ice.ExtensionKeyCandidateID); !ok {
		return false
	}
	return true
}

func extraSrflxCandidate(candidate ice.Candidate) (*ice.CandidateServerReflexive, error) {
	relatedAdd := candidate.RelatedAddress()
	ec, err := ice.NewCandidateServerReflexive(&ice.CandidateServerReflexiveConfig{
		Network:   candidate.NetworkType().String(),
		Address:   candidate.Address(),
		Port:      relatedAdd.Port,
		Component: candidate.Component(),
		RelAddr:   relatedAdd.Address,
		RelPort:   relatedAdd.Port,
	})
	if err != nil {
		return nil, err
	}

	for _, e := range candidate.Extensions() {
		// overwrite the original candidate ID with the new one to avoid candidate duplication
		if e.Key == ice.ExtensionKeyCandidateID {
			e.Value = candidate.ID()
		}
		if err := ec.AddExtension(e); err != nil {
			return nil, err
		}
	}

	return ec, nil
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
