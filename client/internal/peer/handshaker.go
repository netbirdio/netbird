package peer

import (
	"context"
	"errors"
	"net/netip"
	"sync"
	"sync/atomic"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/version"
)

var (
	ErrSignalIsNotReady = errors.New("signal is not ready")
)

// IceCredentials ICE protocol credentials struct
type IceCredentials struct {
	UFrag string
	Pwd   string
}

// OfferAnswer represents a session establishment offer or answer
type OfferAnswer struct {
	IceCredentials IceCredentials
	// WgListenPort is a remote WireGuard listen port.
	// This field is used when establishing a direct WireGuard connection without any proxy.
	// We can set the remote peer's endpoint with this port.
	WgListenPort int

	// Version of NetBird Agent
	Version string
	// RosenpassPubKey is the Rosenpass public key of the remote peer when receiving this message
	// This value is the local Rosenpass server public key when sending the message
	RosenpassPubKey []byte
	// RosenpassAddr is the Rosenpass server address (IP:port) of the remote peer when receiving this message
	// This value is the local Rosenpass server address when sending the message
	RosenpassAddr string

	// MlkemPayload carries the post-quantum X25519MLKEM768 handshake message
	// (pqkem-framed offer on an OFFER, answer on an ANSWER) that seeds the
	// WireGuard PSK. Opaque here — the pqkem library frames and parses it. Nil
	// when the peer does not run the ML-KEM PQ exchange.
	MlkemPayload []byte

	// MlkemPort is the peer's ML-KEM PQ service UDP port (bound on its WG overlay
	// IP) where data-path rekey messages are sent. Zero when not running the exchange.
	MlkemPort int

	// relay server address
	RelaySrvAddress string
	// RelaySrvIP is the IP the remote peer is connected to on its
	// relay server. Used as a dial target if DNS for RelaySrvAddress
	// fails. Zero value if the peer did not advertise an IP.
	RelaySrvIP netip.Addr
	// SessionID is the unique identifier of the session, used to discard old messages
	SessionID *ICESessionID
}

func (o *OfferAnswer) hasICECredentials() bool {
	return o.IceCredentials.UFrag != "" && o.IceCredentials.Pwd != ""
}

type Handshaker struct {
	mu            sync.Mutex
	log           *log.Entry
	config        ConnConfig
	signaler      *Signaler
	ice           *WorkerICE
	relay         *WorkerRelay
	metricsStages *MetricsStages
	// relayListener is not blocking because the listener is using a goroutine to process the messages
	// and it will only keep the latest message if multiple offers are received in a short time
	// this is to avoid blocking the handshaker if the listener is doing some heavy processing
	// and also to avoid processing old offers if multiple offers are received in a short time
	// the listener will always process the latest offer
	relayListener *AsyncOfferListener
	iceListener   func(remoteOfferAnswer *OfferAnswer)

	// remoteICESupported tracks whether the remote peer includes ICE credentials in its offers/answers.
	// When false, the local side skips ICE listener dispatch and suppresses ICE credentials in responses.
	remoteICESupported atomic.Bool

	// remoteOffersCh is a channel used to wait for remote credentials to proceed with the connection
	remoteOffersCh chan OfferAnswer
	// remoteAnswerCh is a channel used to wait for remote credentials answer (confirmation of our offer) to proceed with the connection
	remoteAnswerCh chan OfferAnswer
}

func NewHandshaker(log *log.Entry, config ConnConfig, signaler *Signaler, ice *WorkerICE, relay *WorkerRelay, metricsStages *MetricsStages) *Handshaker {
	h := &Handshaker{
		log:           log,
		config:        config,
		signaler:      signaler,
		ice:           ice,
		relay:         relay,
		metricsStages: metricsStages,
		// Buffered by 1: the single Listen goroutine can be busy handling an offer
		// (sendAnswer does a blocking signal send) exactly when the matching answer
		// arrives on the other channel. Unbuffered, that answer would hit the
		// non-blocking send's default and be dropped — fatal for the post-quantum
		// exchange, which needs the answer to converge. A 1-slot cushion lets it wait
		// until Listen loops back, without ever blocking the signal receiver.
		remoteOffersCh: make(chan OfferAnswer, 1),
		remoteAnswerCh: make(chan OfferAnswer, 1),
	}
	// assume remote supports ICE until we learn otherwise from received offers
	h.remoteICESupported.Store(ice != nil)
	return h
}

func (h *Handshaker) RemoteICESupported() bool {
	return h.remoteICESupported.Load()
}

func (h *Handshaker) AddRelayListener(offer func(remoteOfferAnswer *OfferAnswer)) {
	h.relayListener = NewAsyncOfferListener(offer)
}

func (h *Handshaker) AddICEListener(offer func(remoteOfferAnswer *OfferAnswer)) {
	h.iceListener = offer
}

func (h *Handshaker) Listen(ctx context.Context) {
	for {
		select {
		case remoteOfferAnswer := <-h.remoteOffersCh:
			h.log.Infof("received offer, running version %s, remote WireGuard listen port %d, session id: %s, remote ICE supported: %t", remoteOfferAnswer.Version, remoteOfferAnswer.WgListenPort, remoteOfferAnswer.SessionIDString(), remoteOfferAnswer.hasICECredentials())

			// Record signaling received for reconnection attempts
			if h.metricsStages != nil {
				h.metricsStages.RecordSignalingReceived()
			}

			h.updateRemoteICEState(&remoteOfferAnswer)

			h.pqRegisterEndpoint(remoteOfferAnswer.MlkemPort)

			// Derive+store the KEM PSK (inside sendAnswer's AnswerPayload) BEFORE bringing
			// up the connection: the relay/ICE workers configure the WG endpoint, which
			// pulls the PSK for the first handshake. Notifying them first would race the
			// KEM exchange and hand the first handshake a not-yet-derived key.
			if err := h.sendAnswer(&remoteOfferAnswer); err != nil {
				h.log.Errorf("failed to send remote offer confirmation: %s", err)
				continue
			}

			if h.relayListener != nil {
				h.relayListener.Notify(&remoteOfferAnswer)
			}

			if h.iceListener != nil && h.RemoteICESupported() {
				h.iceListener(&remoteOfferAnswer)
			}
		case remoteOfferAnswer := <-h.remoteAnswerCh:
			h.log.Infof("received answer, running version %s, remote WireGuard listen port %d, session id: %s, remote ICE supported: %t", remoteOfferAnswer.Version, remoteOfferAnswer.WgListenPort, remoteOfferAnswer.SessionIDString(), remoteOfferAnswer.hasICECredentials())

			// Record signaling received for reconnection attempts
			if h.metricsStages != nil {
				h.metricsStages.RecordSignalingReceived()
			}

			h.updateRemoteICEState(&remoteOfferAnswer)

			h.pqRegisterEndpoint(remoteOfferAnswer.MlkemPort)

			// Feed the KEM answer (derive+store PSK) BEFORE bringing up the connection so
			// the WG endpoint config pulls the real PSK for the first handshake instead of
			// racing ahead of the KEM exchange.
			if h.config.PQ != nil {
				h.config.PQ.OnAnswer(h.config.Key, remoteOfferAnswer.MlkemPayload)
			}

			if h.relayListener != nil {
				h.relayListener.Notify(&remoteOfferAnswer)
			}

			if h.iceListener != nil && h.RemoteICESupported() {
				h.iceListener(&remoteOfferAnswer)
			}
		case <-ctx.Done():
			h.log.Infof("stop listening for remote offers and answers")
			return
		}
	}
}

// pqRegisterEndpoint feeds the post-quantum handshaker the peer's data-path endpoint
// (its WG overlay IP plus the advertised pq UDP port) learned from a remote offer/answer.
func (h *Handshaker) pqRegisterEndpoint(remotePort int) {
	if h.config.PQ == nil || remotePort < 0 || remotePort > 65535 || len(h.config.WgConfig.AllowedIps) == 0 {
		return
	}
	// remotePort may be 0 (the peer omitted it, meaning the default port); the adapter
	// resolves 0 to DefaultPort.
	addr := netip.AddrPortFrom(h.config.WgConfig.AllowedIps[0].Addr(), uint16(remotePort))
	h.config.PQ.SetRemoteAddr(h.config.Key, addr)
}

func (h *Handshaker) SendOffer() error {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.sendOffer()
}

// OnRemoteOffer handles an offer from the remote peer and returns true if the message was accepted, false otherwise
// doesn't block, discards the message if connection wasn't ready
func (h *Handshaker) OnRemoteOffer(offer OfferAnswer) {
	select {
	case h.remoteOffersCh <- offer:
		return
	default:
		h.log.Warnf("skipping remote offer message because receiver not ready")
		// connection might not be ready yet to receive so we ignore the message
		return
	}
}

// OnRemoteAnswer handles an offer from the remote peer and returns true if the message was accepted, false otherwise
// doesn't block, discards the message if connection wasn't ready
func (h *Handshaker) OnRemoteAnswer(answer OfferAnswer) {
	select {
	case h.remoteAnswerCh <- answer:
		return
	default:
		// connection might not be ready yet to receive so we ignore the message
		h.log.Warnf("skipping remote answer message because receiver not ready")
		return
	}
}

// sendOffer prepares local user credentials and signals them to the remote peer
func (h *Handshaker) sendOffer() error {
	if !h.signaler.Ready() {
		return ErrSignalIsNotReady
	}

	offer := h.buildOfferAnswer()
	if h.config.PQ != nil {
		offer.MlkemPayload, offer.MlkemPort = h.config.PQ.OfferPayload(h.config.Key)
	}
	h.log.Debugf("sending offer with serial: %s", offer.SessionIDString())

	return h.signaler.SignalOffer(offer, h.config.Key)
}

func (h *Handshaker) sendAnswer(remoteOffer *OfferAnswer) error {
	answer := h.buildOfferAnswer()
	if h.config.PQ != nil {
		var recvOffer []byte
		if remoteOffer != nil {
			recvOffer = remoteOffer.MlkemPayload
		}
		answer.MlkemPayload, answer.MlkemPort = h.config.PQ.AnswerPayload(h.config.Key, recvOffer)
	}
	h.log.Debugf("sending answer with serial: %s", answer.SessionIDString())

	return h.signaler.SignalAnswer(answer, h.config.Key)
}

func (h *Handshaker) buildOfferAnswer() OfferAnswer {
	answer := OfferAnswer{
		WgListenPort:    h.config.LocalWgPort,
		Version:         version.NetbirdVersion(),
		RosenpassPubKey: h.config.RosenpassConfig.PubKey,
		RosenpassAddr:   h.config.RosenpassConfig.Addr,
	}

	if h.ice != nil && h.RemoteICESupported() {
		uFrag, pwd := h.ice.GetLocalUserCredentials()
		sid := h.ice.SessionID()
		answer.IceCredentials = IceCredentials{uFrag, pwd}
		answer.SessionID = &sid
	}

	if addr, ip, err := h.relay.RelayInstanceAddress(); err == nil {
		answer.RelaySrvAddress = addr
		answer.RelaySrvIP = ip
	}

	return answer
}

func (h *Handshaker) updateRemoteICEState(offer *OfferAnswer) {
	hasICE := offer.hasICECredentials()
	prev := h.remoteICESupported.Swap(hasICE)
	if prev != hasICE {
		if hasICE {
			h.log.Infof("remote peer started sending ICE credentials")
		} else {
			h.log.Infof("remote peer stopped sending ICE credentials")
			if h.ice != nil {
				h.ice.Close()
			}
		}
	}
}
