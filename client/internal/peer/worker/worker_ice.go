package worker

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"sync/atomic"
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

type iceDialFunc func(context.Context, *icemaker.ThreadSafeAgent, *signaling.OfferAnswer) (net.Conn, error)

// ICE is owned by the Conn event loop. Pion callbacks and the dial goroutine
// only post events. Credentials and InProgress expose atomic snapshots to
// signaling and the reconnection guard.
type ICE struct {
	log                *log.Entry
	key                string
	iceConfig          icemaker.Config
	isController       bool
	postEvent          func(any) bool
	signaler           *signaling.Signaler
	iFaceDiscover      stdnet.ExternalIFaceDiscover
	statusRecorder     *status.Recorder
	portForwardManager *portforward.Manager
	hasRelayOnLocally  bool

	agent             *icemaker.ThreadSafeAgent
	agentDialerCancel context.CancelFunc
	agentConnecting   atomic.Bool
	// connectedAgent is the agent whose connection was last reported ready.
	connectedAgent *icemaker.ThreadSafeAgent
	// remoteSessionID represents the peer's session identifier from the latest remote offer.
	remoteSessionID      icemaker.SessionID
	remoteSessionChanged bool
	credentials          atomic.Pointer[signaling.Credentials]

	// portForwardAttempted tracks if we've already tried port forwarding this session
	portForwardAttempted bool

	// Captured before starting connect; only tests replace the dial operation.
	dialFunc iceDialFunc
}

// NewICE creates an event-loop-owned worker publishing to the current Open's mailbox.
func NewICE(log *log.Entry, key string, iceConfig icemaker.Config, isController bool, postEvent func(any) bool, services ICEDependencies, hasRelayOnLocally bool) (*ICE, error) {
	sessionID, err := icemaker.NewSessionID()
	if err != nil {
		return nil, err
	}
	localUfrag, localPwd, err := icemaker.GenerateICECredentials()
	if err != nil {
		return nil, err
	}

	w := &ICE{
		log:                log,
		key:                key,
		iceConfig:          iceConfig,
		isController:       isController,
		postEvent:          postEvent,
		signaler:           services.Signaler,
		iFaceDiscover:      services.IFaceDiscover,
		statusRecorder:     services.StatusRecorder,
		portForwardManager: services.PortForwardManager,
		hasRelayOnLocally:  hasRelayOnLocally,
	}
	w.credentials.Store(&signaling.Credentials{UFrag: localUfrag, Pwd: localPwd, SessionID: sessionID})
	return w, nil
}

// OnNewOffer starts a negotiation on the event loop.
func (w *ICE) OnNewOffer(ctx context.Context, remoteOfferAnswer *signaling.OfferAnswer) {
	w.log.Debugf("OnNewOffer for ICE, serial: %s", remoteOfferAnswer.SessionIDString())

	if w.agent != nil || w.agentConnecting.Load() {
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
		creds := w.Credentials()
		creds.SessionID = sessionID
		w.credentials.Store(&creds)
		w.abandonNegotiation()
	}

	var preferredCandidateTypes []ice.CandidateType
	if w.hasRelayOnLocally && remoteOfferAnswer.RelaySrvAddress != "" {
		preferredCandidateTypes = icemaker.CandidateTypesP2P()
	} else {
		preferredCandidateTypes = icemaker.CandidateTypes()
	}

	if remoteOfferAnswer.SessionID != nil {
		w.log.Debugf("recreate ICE agent: %s / %s", w.Credentials().SessionID, *remoteOfferAnswer.SessionID)
	}
	dialerCtx, dialerCancel := context.WithCancel(ctx)
	agent, err := w.reCreateAgent(ctx, preferredCandidateTypes)
	if err != nil {
		dialerCancel()
		w.log.Errorf("failed to recreate ICE Agent: %s", err)
		return
	}
	w.agent = agent
	w.agentDialerCancel = dialerCancel
	w.agentConnecting.Store(true)
	if remoteOfferAnswer.SessionID != nil {
		w.remoteSessionID = *remoteOfferAnswer.SessionID
	} else {
		w.remoteSessionID = ""
	}

	dial := w.dialFunc
	if dial == nil {
		dial = w.agentDial
	}
	go w.connect(dialerCtx, agent, *remoteOfferAnswer, dial)
}

// OnRemoteCandidate Handles ICE connection Candidate provided by the remote peer.
func (w *ICE) OnRemoteCandidate(candidate ice.Candidate, haRoutes route.HAMap) {
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

// Credentials returns a consistent snapshot for asynchronous signaling.
func (w *ICE) Credentials() signaling.Credentials {
	return *w.credentials.Load()
}

// InProgress returns the negotiation state published by the event loop.
func (w *ICE) InProgress() bool {
	return w.agentConnecting.Load()
}

// Close releases the current agent on the event loop. Repeated calls are harmless.
func (w *ICE) Close() {
	if w.agent != nil {
		w.agentDialerCancel()
		if err := w.agent.Close(); err != nil {
			w.log.Warnf("failed to close ICE agent: %s", err)
		}
	}
	// A later dial result no longer owns the agent, so Close must clear the
	// connecting state before the reconnection guard reads it.
	w.abandonNegotiation()
}

func (w *ICE) reCreateAgent(ctx context.Context, candidates []ice.CandidateType) (*icemaker.ThreadSafeAgent, error) {
	w.portForwardAttempted = false
	creds := w.Credentials()
	agent, err := icemaker.NewAgent(ctx, w.iFaceDiscover, w.iceConfig, candidates, creds.UFrag, creds.Pwd)
	if err != nil {
		return nil, fmt.Errorf("create agent: %w", err)
	}
	configured := false
	defer func() {
		if !configured {
			if err := agent.Close(); err != nil {
				w.log.Warnf("failed to close unconfigured ICE agent: %s", err)
			}
		}
	}()

	post := w.postEvent
	if err := agent.OnCandidate(func(candidate ice.Candidate) {
		post(ICECandidate{Candidate: candidate})
	}); err != nil {
		return nil, err
	}
	if err := agent.OnConnectionStateChange(func(state ice.ConnectionState) {
		post(ICEStateChanged{Agent: agent, State: state})
	}); err != nil {
		return nil, err
	}
	if err := agent.OnSelectedCandidatePairChange(func(local, remote ice.Candidate) {
		post(ICESelectedPair{Agent: agent, Local: local, Remote: remote})
	}); err != nil {
		return nil, err
	}
	configured = true
	return agent, nil
}

// connect performs blocking ICE I/O without reading or changing negotiation state.
func (w *ICE) connect(ctx context.Context, agent *icemaker.ThreadSafeAgent, offer signaling.OfferAnswer, dial iceDialFunc) {
	result := ICEDialDone{Agent: agent, Offer: offer}
	result.Err = agent.GatherCandidates()
	if result.Err == nil {
		result.Conn, result.Err = dial(ctx, agent, &offer)
	}
	if !w.postEvent(result) {
		w.closeUnusedConn(result.Conn)
	}
}

// OnDialDone consumes the dial result on the event loop. Rejected results are
// released here; accepted results transfer their connection to the caller.
func (w *ICE) OnDialDone(e ICEDialDone) (ConnPriority, ICEConnInfo, bool) {
	if e.Err != nil {
		w.log.Debugf("ICE dial did not establish a connection: %v", e.Err)
		w.closeUnusedConn(e.Conn)
		w.closeAgent(e.Agent)
		return None, ICEConnInfo{}, false
	}

	// A newer negotiation may have replaced this agent during the dial.
	if w.agent != e.Agent {
		w.closeUnusedConn(e.Conn)
		w.log.Warnf("discarding connection from a stale ICE negotiation")
		return None, ICEConnInfo{}, false
	}

	pair, err := e.Agent.GetSelectedCandidatePair()
	if err != nil || pair == nil {
		w.log.Debugf("ICE dial has no selected candidate pair: %v", err)
		w.closeUnusedConn(e.Conn)
		w.closeAgent(e.Agent)
		return None, ICEConnInfo{}, false
	}

	if !isRelayCandidate(pair.Local) {
		remoteWgPort := iface.DefaultWgPort
		if e.Offer.WgListenPort != 0 {
			remoteWgPort = e.Offer.WgListenPort
		}
		go w.punchRemoteWGPort(pair, remoteWgPort)
	}
	info := ICEConnInfo{
		RemoteConn:                 e.Conn,
		RosenpassPubKey:            e.Offer.RosenpassPubKey,
		RosenpassAddr:              e.Offer.RosenpassAddr,
		LocalIceCandidateType:      pair.Local.Type().String(),
		RemoteIceCandidateType:     pair.Remote.Type().String(),
		LocalIceCandidateEndpoint:  net.JoinHostPort(pair.Local.Address(), strconv.Itoa(pair.Local.Port())),
		RemoteIceCandidateEndpoint: net.JoinHostPort(pair.Remote.Address(), strconv.Itoa(pair.Remote.Port())),
		Relayed:                    isRelayed(pair),
		RelayedOnLocal:             isRelayCandidate(pair.Local),
	}
	w.agentConnecting.Store(false)
	w.connectedAgent = e.Agent
	w.log.Infof("connection succeeded with offer session: %s", e.Offer.SessionIDString())
	return selectedPriority(pair), info, true
}

func (w *ICE) closeUnusedConn(conn net.Conn) {
	if conn != nil {
		if err := conn.Close(); err != nil {
			w.log.Debugf("close unused ICE connection: %v", err)
		}
	}
}

func (w *ICE) closeAgent(agent *icemaker.ThreadSafeAgent) bool {
	// Superseded agents had their dial context cancelled when replaced.
	if w.agent == agent {
		w.agentDialerCancel()
	}
	if err := agent.Close(); err != nil {
		w.log.Warnf("failed to close ICE agent: %s", err)
	}

	sessionChanged := w.remoteSessionChanged
	w.remoteSessionChanged = false

	// Only the owner of the current session may reset its state.
	if w.agent == agent {
		sessionID, err := icemaker.NewSessionID()
		if err != nil {
			w.log.Errorf("failed to create new session ID: %s", err)
		}
		creds := w.Credentials()
		creds.SessionID = sessionID
		w.credentials.Store(&creds)
		w.abandonNegotiation()
	}
	return sessionChanged
}

// Clearing the agent and connecting flag together keeps retries from stalling.
// Callers run on the event loop and must dispose of the agent first.
func (w *ICE) abandonNegotiation() {
	w.agent = nil
	w.agentDialerCancel = nil
	w.agentConnecting.Store(false)
	w.remoteSessionID = ""
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

// OnLocalCandidate signals a gathered candidate from the event loop.
func (w *ICE) OnLocalCandidate(e ICECandidate) {
	candidate := e.Candidate
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

	// A forwarded candidate only makes sense for an IPv4 mapping, which
	// translates a port on the gateway's address. An IPv6 pinhole translates
	// nothing: it unblocks the address ICE already gathers as a host candidate,
	// so there is no second address to advertise. Injecting one here would also
	// paste an IPv6 address onto whichever server-reflexive candidate arrived
	// first, which is usually IPv4.
	if mapping.ExternalIP != nil && mapping.ExternalIP.To4() == nil {
		w.log.Debugf("skipping port-forwarded candidate: %s mapping is IPv6-only", mapping.NATType)
		return
	}

	if w.portForwardAttempted {
		return
	}
	w.portForwardAttempted = true

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

// OnSelectedCandidatePair records the selected pair on the event loop.
func (w *ICE) OnSelectedCandidatePair(e ICESelectedPair) {
	agent, c1, c2 := e.Agent, e.Local, e.Remote
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
	sessionID := w.Credentials().SessionID
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

// OnConnectionStateChange processes Pion state on the event loop and reports
// whether the last ready connection disconnected and the remote session changed.
func (w *ICE) OnConnectionStateChange(e ICEStateChanged) (disconnected, sessionChanged bool) {
	w.log.Debugf("ICE ConnectionState has changed to %s", e.State.String())
	switch e.State {
	case ice.ConnectionStateConnected:
		w.logSuccessfulPaths(e.Agent)
	case ice.ConnectionStateFailed, ice.ConnectionStateDisconnected, ice.ConnectionStateClosed:
		sessionChanged = w.closeAgent(e.Agent)
		if w.connectedAgent != e.Agent {
			return false, sessionChanged
		}
		w.connectedAgent = nil
		return true, sessionChanged
	}
	return false, false
}

func (w *ICE) agentDial(ctx context.Context, agent *icemaker.ThreadSafeAgent, remoteOfferAnswer *signaling.OfferAnswer) (net.Conn, error) {
	dial := agent.Accept
	if w.isController {
		dial = agent.Dial
	}
	conn, err := dial(ctx, remoteOfferAnswer.IceCredentials.UFrag, remoteOfferAnswer.IceCredentials.Pwd)
	if err != nil {
		return nil, err
	}
	return conn, nil
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
