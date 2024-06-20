package peer

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"net"
	"net/netip"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pion/ice/v3"
	"github.com/pion/randutil"
	"github.com/pion/stun/v2"
	log "github.com/sirupsen/logrus"

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

	lenUFrag   = 16
	lenPwd     = 32
	runesAlpha = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
)

var (
	failedTimeout = 6 * time.Second
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

type WorkerICECallbacks struct {
	OnConnReady     func(ConnPriority, ICEConnInfo)
	OnStatusChanged func(ConnStatus)
	DoHandshake     func() (*OfferAnswer, error)
}

type WorkerICE struct {
	ctx            context.Context
	log            *log.Entry
	config         ConnConfig
	configICE      ICEConfig
	signaler       *Signaler
	iFaceDiscover  stdnet.ExternalIFaceDiscover
	statusRecorder *Status
	conn           WorkerICECallbacks

	selectedPriority ConnPriority

	agent    *ice.Agent
	muxAgent sync.Mutex

	StunTurn []*stun.URI

	sentExtraSrflx bool
	localUfrag     string
	localPwd       string
}

func NewWorkerICE(ctx context.Context, log *log.Entry, config ConnConfig, configICE ICEConfig, signaler *Signaler, ifaceDiscover stdnet.ExternalIFaceDiscover, statusRecorder *Status, callBacks WorkerICECallbacks) *WorkerICE {
	cice := &WorkerICE{
		ctx:            ctx,
		log:            log,
		config:         config,
		configICE:      configICE,
		signaler:       signaler,
		iFaceDiscover:  ifaceDiscover,
		statusRecorder: statusRecorder,
		conn:           callBacks,
	}
	return cice
}

// SetupICEConnection sets up an ICE connection with the remote peer.
// If the relay mode is supported then try to connect in p2p way only.
// It is trying to reconnection in a loop until the context is canceled.
// In case of success connection it will call the onICEConnReady callback.
func (w *WorkerICE) SetupICEConnection(hasRelayOnLocally bool) {
	time.Sleep(20 * time.Second)
	for {
		if !w.waitForReconnectTry() {
			return
		}

		w.conn.OnStatusChanged(StatusConnecting)

		w.log.Debugf("trying to establish ICE connection with peer %s", w.config.Key)

		remoteOfferAnswer, err := w.conn.DoHandshake()
		if err != nil {
			if errors.Is(err, ErrSignalIsNotReady) {
				w.log.Infof("signal client isn't ready, skipping connection attempt")
			}
			continue
		}

		var preferredCandidateTypes []ice.CandidateType
		if hasRelayOnLocally && remoteOfferAnswer.RelaySrvAddress != "" {
			w.selectedPriority = connPriorityICEP2P
			preferredCandidateTypes = candidateTypesP2P()
		} else {
			w.selectedPriority = connPriorityICETurn
			preferredCandidateTypes = candidateTypes()
		}

		ctx, ctxCancel := context.WithCancel(w.ctx)
		w.muxAgent.Lock()
		agent, err := w.reCreateAgent(ctxCancel, preferredCandidateTypes)
		if err != nil {
			ctxCancel()
			w.muxAgent.Unlock()
			continue
		}
		w.agent = agent
		// generate credentials for the next loop. Important the credentials are generated before handshake, because
		// the handshake could provide a cached offer-answer
		w.localUfrag, w.localPwd, err = generateICECredentials()
		if err != nil {
			ctxCancel()
			w.muxAgent.Unlock()
			continue
		}
		w.muxAgent.Unlock()

		err = w.agent.GatherCandidates()
		if err != nil {
			ctxCancel()
			continue
		}

		// will block until connection succeeded
		// but it won't release if ICE Agent went into Disconnected or Failed state,
		// so we have to cancel it with the provided context once agent detected a broken connection
		remoteConn, err := w.turnAgentDial(remoteOfferAnswer)
		if err != nil {
			ctxCancel()
			continue
		}

		pair, err := w.agent.GetSelectedCandidatePair()
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
			Direct:                     !isRelayCandidate(pair.Local),
			Relayed:                    isRelayed(pair),
			RelayedOnLocal:             isRelayCandidate(pair.Local),
		}
		go w.conn.OnConnReady(w.selectedPriority, ci)

		<-ctx.Done()
		ctxCancel()
		_ = w.agent.Close()
		w.conn.OnStatusChanged(StatusDisconnected)
	}
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

func (w *WorkerICE) GetLocalUserCredentials() (frag string, pwd string, err error) {
	w.muxAgent.Lock()
	defer w.muxAgent.Unlock()

	if w.localUfrag != "" && w.localPwd != "" {
		return w.localUfrag, w.localPwd, nil
	}

	w.localUfrag, w.localPwd, err = generateICECredentials()
	return w.localUfrag, w.localPwd, err
}

func (w *WorkerICE) reCreateAgent(ctxCancel context.CancelFunc, relaySupport []ice.CandidateType) (*ice.Agent, error) {
	transportNet, err := w.newStdNet()
	if err != nil {
		w.log.Errorf("failed to create pion's stdnet: %s", err)
	}

	iceKeepAlive := iceKeepAlive()
	iceDisconnectedTimeout := iceDisconnectedTimeout()
	iceRelayAcceptanceMinWait := iceRelayAcceptanceMinWait()

	agentConfig := &ice.AgentConfig{
		MulticastDNSMode:       ice.MulticastDNSModeDisabled,
		NetworkTypes:           []ice.NetworkType{ice.NetworkTypeUDP4, ice.NetworkTypeUDP6},
		Urls:                   w.configICE.StunTurn.Load().([]*stun.URI),
		CandidateTypes:         relaySupport,
		InterfaceFilter:        stdnet.InterfaceFilter(w.configICE.InterfaceBlackList),
		UDPMux:                 w.configICE.UDPMux,
		UDPMuxSrflx:            w.configICE.UDPMuxSrflx,
		NAT1To1IPs:             w.configICE.NATExternalIPs,
		Net:                    transportNet,
		FailedTimeout:          &failedTimeout,
		DisconnectedTimeout:    &iceDisconnectedTimeout,
		KeepaliveInterval:      &iceKeepAlive,
		RelayAcceptanceMinWait: &iceRelayAcceptanceMinWait,
		LocalUfrag:             w.localUfrag,
		LocalPwd:               w.localPwd,
	}

	if w.configICE.DisableIPv6Discovery {
		agentConfig.NetworkTypes = []ice.NetworkType{ice.NetworkTypeUDP4}
	}

	w.sentExtraSrflx = false
	agent, err := ice.NewAgent(agentConfig)
	if err != nil {
		return nil, err
	}

	err = agent.OnCandidate(w.onICECandidate)
	if err != nil {
		return nil, err
	}

	err = agent.OnConnectionStateChange(func(state ice.ConnectionState) {
		w.log.Debugf("ICE ConnectionState has changed to %s", state.String())
		if state == ice.ConnectionStateFailed || state == ice.ConnectionStateDisconnected {
			ctxCancel()
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

func (w *WorkerICE) punchRemoteWGPort(pair *ice.CandidatePair, remoteWgPort int) {
	// wait local endpoint configuration
	time.Sleep(time.Second)
	addr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", pair.Remote.Address(), remoteWgPort))
	if err != nil {
		w.log.Warnf("got an error while resolving the udp address, err: %s", err)
		return
	}

	mux, ok := w.configICE.UDPMuxSrflx.(*bind.UniversalUDPMuxDefault)
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

func (w *WorkerICE) turnAgentDial(remoteOfferAnswer *OfferAnswer) (*ice.Conn, error) {
	isControlling := w.config.LocalKey > w.config.Key
	if isControlling {
		return w.agent.Dial(w.ctx, remoteOfferAnswer.IceCredentials.UFrag, remoteOfferAnswer.IceCredentials.Pwd)
	} else {
		return w.agent.Accept(w.ctx, remoteOfferAnswer.IceCredentials.UFrag, remoteOfferAnswer.IceCredentials.Pwd)
	}
}

// waitForReconnectTry waits for a random duration before trying to reconnect
func (w *WorkerICE) waitForReconnectTry() bool {
	minWait := 500
	maxWait := 2000
	duration := time.Duration(rand.Intn(maxWait-minWait)+minWait) * time.Millisecond

	timeout := time.NewTimer(duration)
	defer timeout.Stop()

	select {
	case <-w.ctx.Done():
		return false
	case <-timeout.C:
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

func generateICECredentials() (string, string, error) {
	ufrag, err := randutil.GenerateCryptoRandomString(lenUFrag, runesAlpha)
	if err != nil {
		return "", "", err
	}

	pwd, err := randutil.GenerateCryptoRandomString(lenPwd, runesAlpha)
	if err != nil {
		return "", "", err
	}
	return ufrag, pwd, nil

}
