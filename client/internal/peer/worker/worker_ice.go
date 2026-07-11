package worker

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/pion/ice/v4"
	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/iface"
	"github.com/netbirdio/netbird/client/iface/udpmux"
	icemaker "github.com/netbirdio/netbird/client/internal/peer/ice"
	"github.com/netbirdio/netbird/client/internal/peer/signaling"
	"github.com/netbirdio/netbird/client/internal/peer/status"
	"github.com/netbirdio/netbird/client/internal/portforward"
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

type ICEDependencies struct {
	Signaler           *signaling.Signaler
	IFaceDiscover      stdnet.ExternalIFaceDiscover
	StatusRecorder     *status.Recorder
	PortForwardManager *portforward.Manager
}

type ICE struct {
	log                *log.Entry
	key                string
	iceConfig          icemaker.Config
	isController       bool
	onConnReady        func(priority ConnPriority, iceConnInfo ICEConnInfo)
	onStatusDisconnect func(sessionChanged bool)
	signaler           *signaling.Signaler
	iFaceDiscover      stdnet.ExternalIFaceDiscover
	statusRecorder     *status.Recorder
	portForwardManager *portforward.Manager
	hasRelayOnLocally  bool

	agent             *icemaker.ThreadSafeAgent
	agentDialerCancel context.CancelFunc
	agentConnecting   bool      // while it is true, drop all incoming offers
	lastSuccess       time.Time // with this avoid the too frequent ICE agent recreation
	// connectedAgent is the agent whose connection was last reported ready; guarded by muxAgent
	connectedAgent *icemaker.ThreadSafeAgent
	// remoteSessionID represents the peer's session identifier from the latest remote offer.
	remoteSessionID icemaker.SessionID
	// sessionID is used to track the current session ID of the ICE agent
	// increase by one when disconnecting the agent
	// with it the remote peer can discard the already deprecated offer/answer
	// Without it the remote peer may recreate a workable ICE connection
	sessionID            icemaker.SessionID
	remoteSessionChanged bool
	muxAgent             sync.Mutex

	localUfrag string
	localPwd   string

	// portForwardAttempted tracks if we've already tried port forwarding this session
	portForwardAttempted bool
}

func NewICE(log *log.Entry, key string, iceConfig icemaker.Config, isController bool, onConnReady func(ConnPriority, ICEConnInfo), onStatusDisconnect func(bool), services ICEDependencies, hasRelayOnLocally bool) (*ICE, error) {
	sessionID, err := icemaker.NewSessionID()
	if err != nil {
		return nil, err
	}

	w := &ICE{
		log:                log,
		key:                key,
		iceConfig:          iceConfig,
		isController:       isController,
		onConnReady:        onConnReady,
		onStatusDisconnect: onStatusDisconnect,
		signaler:           services.Signaler,
		iFaceDiscover:      services.IFaceDiscover,
		statusRecorder:     services.StatusRecorder,
		portForwardManager: services.PortForwardManager,
		hasRelayOnLocally:  hasRelayOnLocally,
		sessionID:          sessionID,
	}

	localUfrag, localPwd, err := icemaker.GenerateICECredentials()
	if err != nil {
		return nil, err
	}
	w.localUfrag = localUfrag
	w.localPwd = localPwd
	return w, nil
}

func (w *ICE) OnNewOffer(ctx context.Context, remoteOfferAnswer *signaling.OfferAnswer) {
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
		w.remoteSessionChanged = true
		w.agentDialerCancel()
		if w.agent != nil {
			if err := w.agent.Close(); err != nil {
				w.log.Warnf("failed to close ICE agent: %s", err)
			}
		}

		sessionID, err := icemaker.NewSessionID()
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
	dialerCtx, dialerCancel := context.WithCancel(ctx)
	agent, err := w.reCreateAgent(ctx, dialerCancel, preferredCandidateTypes)
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

	go w.connect(dialerCtx, dialerCancel, agent, remoteOfferAnswer)
}

// OnRemoteCandidate Handles ICE connection Candidate provided by the remote peer.
func (w *ICE) OnRemoteCandidate(candidate ice.Candidate, haRoutes route.HAMap) {
	w.muxAgent.Lock()
	defer w.muxAgent.Unlock()
	w.log.Debugf("OnRemoteCandidate from peer %s -> %s", w.key, candidate.String())
	if w.agent == nil {
		w.log.Warnf("ICE Agent is not initialized yet")
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

func (w *ICE) Credentials() signaling.Credentials {
	w.muxAgent.Lock()
	defer w.muxAgent.Unlock()
	return signaling.Credentials{
		UFrag:     w.localUfrag,
		Pwd:       w.localPwd,
		SessionID: w.sessionID,
	}
}

func (w *ICE) InProgress() bool {
	w.muxAgent.Lock()
	defer w.muxAgent.Unlock()

	return w.agentConnecting
}

func (w *ICE) Close() {
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

func (w *ICE) reCreateAgent(ctx context.Context, dialerCancel context.CancelFunc, candidates []ice.CandidateType) (*icemaker.ThreadSafeAgent, error) {
	w.portForwardAttempted = false

	agent, err := icemaker.NewAgent(ctx, w.iFaceDiscover, w.iceConfig, candidates, w.localUfrag, w.localPwd)
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

func (w *ICE) getSessionID() icemaker.SessionID {
	w.muxAgent.Lock()
	defer w.muxAgent.Unlock()

	return w.sessionID
}

// will block until connection succeeded
// but it won't release if ICE Agent went into Disconnected or Failed state,
// so we have to cancel it with the provided context once agent detected a broken connection
func (w *ICE) connect(ctx context.Context, dialerCancel context.CancelFunc, agent *icemaker.ThreadSafeAgent, remoteOfferAnswer *signaling.OfferAnswer) {
	w.log.Debugf("gather candidates")
	if err := agent.GatherCandidates(); err != nil {
		w.log.Warnf("failed to gather candidates: %s", err)
		w.closeAgent(agent, dialerCancel)
		return
	}

	w.log.Debugf("turn agent dial")
	remoteConn, err := w.turnAgentDial(ctx, agent, remoteOfferAnswer)
	if err != nil {
		w.log.Debugf("failed to dial the remote peer: %s", err)
		w.closeAgent(agent, dialerCancel)
		return
	}
	w.log.Debugf("agent dial succeeded")

	pair, err := agent.GetSelectedCandidatePair()
	if err != nil {
		w.closeAgent(agent, dialerCancel)
		return
	}
	if pair == nil {
		w.log.Warnf("selected candidate pair is nil, cannot proceed")
		w.closeAgent(agent, dialerCancel)
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

	w.muxAgent.Lock()
	if w.agent != agent {
		w.muxAgent.Unlock()
		w.log.Debugf("agent has been replaced during connect, dropping obsolete connection")
		return
	}
	w.agentConnecting = false
	w.lastSuccess = time.Now()
	w.connectedAgent = agent
	w.muxAgent.Unlock()

	w.log.Infof("connection succeeded with offer session: %s", remoteOfferAnswer.SessionIDString())
	w.onConnReady(selectedPriority(pair), ci)
}

func (w *ICE) closeAgent(agent *icemaker.ThreadSafeAgent, cancel context.CancelFunc) bool {
	cancel()
	if err := agent.Close(); err != nil {
		w.log.Warnf("failed to close ICE agent: %s", err)
	}

	w.muxAgent.Lock()
	defer w.muxAgent.Unlock()

	sessionChanged := w.remoteSessionChanged
	w.remoteSessionChanged = false

	if w.agent == agent {
		// consider to remove from here and move to the OnNewOffer
		sessionID, err := icemaker.NewSessionID()
		if err != nil {
			w.log.Errorf("failed to create new session ID: %s", err)
		}
		w.sessionID = sessionID
		w.agent = nil
		w.agentConnecting = false
		w.remoteSessionID = ""
	}
	return sessionChanged
}

func (w *ICE) punchRemoteWGPort(pair *ice.CandidatePair, remoteWgPort int) {
	// wait local endpoint configuration
	time.Sleep(time.Second)
	addr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(pair.Remote.Address(), strconv.Itoa(remoteWgPort)))
	if err != nil {
		w.log.Warnf("got an error while resolving the udp address, err: %s", err)
		return
	}

	mux, ok := w.iceConfig.UDPMuxSrflx.(*udpmux.UniversalUDPMuxDefault)
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
func (w *ICE) onICECandidate(candidate ice.Candidate) {
	// nil means candidate gathering has been ended
	if candidate == nil {
		return
	}

	// TODO: reported port is incorrect for CandidateTypeHost, makes understanding ICE use via logs confusing as port is ignored
	w.log.Debugf("discovered local candidate %s", candidate.String())
	go func() {
		err := w.signaler.SignalICECandidate(candidate, w.key)
		if err != nil {
			w.log.Errorf("failed signaling candidate to the remote peer %s %s", w.key, err)
		}
	}()

	if candidate.Type() == ice.CandidateTypeServerReflexive {
		w.injectPortForwardedCandidate(candidate)
	}
}

// injectPortForwardedCandidate signals an additional candidate using the pre-created port mapping.
func (w *ICE) injectPortForwardedCandidate(srflxCandidate ice.Candidate) {
	pfManager := w.portForwardManager
	if pfManager == nil {
		return
	}

	mapping := pfManager.GetMapping()
	if mapping == nil {
		return
	}

	w.muxAgent.Lock()
	if w.portForwardAttempted {
		w.muxAgent.Unlock()
		return
	}
	w.portForwardAttempted = true
	w.muxAgent.Unlock()

	forwardedCandidate, err := w.createForwardedCandidate(srflxCandidate, mapping)
	if err != nil {
		w.log.Warnf("create forwarded candidate: %v", err)
		return
	}

	w.log.Debugf("injecting port-forwarded candidate: %s (mapping: %d -> %d via %s, priority: %d)",
		forwardedCandidate.String(), mapping.InternalPort, mapping.ExternalPort, mapping.NATType, forwardedCandidate.Priority())

	go func() {
		if err := w.signaler.SignalICECandidate(forwardedCandidate, w.key); err != nil {
			w.log.Errorf("signal port-forwarded candidate: %v", err)
		}
	}()
}

// createForwardedCandidate creates a new server reflexive candidate with the forwarded port.
// It uses the NAT gateway's external IP with the forwarded port.
func (w *ICE) createForwardedCandidate(srflxCandidate ice.Candidate, mapping *portforward.Mapping) (ice.Candidate, error) {
	var externalIP string
	if mapping.ExternalIP != nil && !mapping.ExternalIP.IsUnspecified() {
		externalIP = mapping.ExternalIP.String()
	} else {
		// Fallback to STUN-discovered address if NAT didn't provide external IP
		externalIP = srflxCandidate.Address()
	}

	// Per RFC 8445, the related address for srflx is the base (host candidate address).
	// If the original srflx has unspecified related address, use its own address as base.
	relAddr := srflxCandidate.RelatedAddress().Address
	if relAddr == "" || relAddr == "0.0.0.0" || relAddr == "::" {
		relAddr = srflxCandidate.Address()
	}

	// Arbitrary +1000 boost on top of RFC 8445 priority to favor port-forwarded candidates
	// over regular srflx during ICE connectivity checks.
	priority := srflxCandidate.Priority() + 1000

	candidate, err := ice.NewCandidateServerReflexive(&ice.CandidateServerReflexiveConfig{
		Network:   srflxCandidate.NetworkType().String(),
		Address:   externalIP,
		Port:      int(mapping.ExternalPort),
		Component: srflxCandidate.Component(),
		Priority:  priority,
		RelAddr:   relAddr,
		RelPort:   int(mapping.InternalPort),
	})
	if err != nil {
		return nil, fmt.Errorf("create candidate: %w", err)
	}

	for _, e := range srflxCandidate.Extensions() {
		if e.Key == ice.ExtensionKeyCandidateID {
			e.Value = srflxCandidate.ID()
		}
		if err := candidate.AddExtension(e); err != nil {
			return nil, fmt.Errorf("add extension: %w", err)
		}
	}

	return candidate, nil
}

func (w *ICE) onICESelectedCandidatePair(agent *icemaker.ThreadSafeAgent, c1, c2 ice.Candidate) {
	w.log.Debugf("selected candidate pair [local <-> remote] -> [%s <-> %s], peer %s", c1.String(), c2.String(),
		w.key)

	pairStat, ok := agent.GetSelectedCandidatePairStats()
	if !ok {
		w.log.Warnf("failed to get selected candidate pair stats")
		return
	}

	duration := time.Duration(pairStat.CurrentRoundTripTime * float64(time.Second))
	if err := w.statusRecorder.UpdateLatency(w.key, duration); err != nil {
		w.log.Debugf("failed to update latency for peer: %s", err)
		return
	}
}

func (w *ICE) logSuccessfulPaths(agent *icemaker.ThreadSafeAgent) {
	sessionID := w.getSessionID()
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
			w.log.Debugf("successful ICE path %s: [%s %s %s:%d] <-> [%s %s %s:%d] rtt=%.3fms",
				sessionID,
				local.NetworkType(), local.Type(), local.Address(), local.Port(),
				remote.NetworkType(), remote.Type(), remote.Address(), remote.Port(),
				stat.CurrentRoundTripTime*1000)
		}
	}
}

func (w *ICE) onConnectionStateChange(agent *icemaker.ThreadSafeAgent, dialerCancel context.CancelFunc) func(ice.ConnectionState) {
	// per-agent state; pion delivers callbacks of one agent sequentially
	var connected bool
	return func(state ice.ConnectionState) {
		w.log.Debugf("ICE ConnectionState has changed to %s", state.String())
		switch state {
		case ice.ConnectionStateConnected:
			connected = true
			w.logSuccessfulPaths(agent)
		case ice.ConnectionStateFailed, ice.ConnectionStateDisconnected, ice.ConnectionStateClosed:
			// ice.ConnectionStateClosed happens when we recreate the agent. For the P2P to TURN switch important to
			// notify the conn.onICEStateDisconnected changes to update the current used priority

			sessionChanged := w.closeAgent(agent, dialerCancel)

			if !connected {
				return
			}
			connected = false

			w.muxAgent.Lock()
			stale := w.connectedAgent != agent
			if !stale {
				w.connectedAgent = nil
			}
			w.muxAgent.Unlock()

			if stale {
				w.log.Debugf("suppress disconnected event of replaced ICE agent")
				return
			}
			w.onStatusDisconnect(sessionChanged)
		}
	}
}

func (w *ICE) turnAgentDial(ctx context.Context, agent *icemaker.ThreadSafeAgent, remoteOfferAnswer *signaling.OfferAnswer) (*ice.Conn, error) {
	if w.isController {
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

func isRelayCandidate(candidate ice.Candidate) bool {
	return candidate.Type() == ice.CandidateTypeRelay
}

func isRelayed(pair *ice.CandidatePair) bool {
	if pair.Local.Type() == ice.CandidateTypeRelay || pair.Remote.Type() == ice.CandidateTypeRelay {
		return true
	}
	return false
}

func selectedPriority(pair *ice.CandidatePair) ConnPriority {
	if isRelayed(pair) {
		return ICETurn
	} else {
		return ICEP2P
	}
}
