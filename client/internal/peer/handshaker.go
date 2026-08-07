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
	MlkemPort uint16

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
		// Buffered by one so an offer or answer that arrives between Open launching
		// the Listen goroutine and it reaching its receive is held rather than
		// dropped. A peer activated by an incoming signal receives the remote's
		// message in that window; an unbuffered channel skips it as "receiver not
		// ready", and the connection cannot proceed until the remote re-sends.
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
			h.handleRemoteOffer(remoteOfferAnswer)
		case remoteOfferAnswer := <-h.remoteAnswerCh:
			h.handleRemoteAnswer(remoteOfferAnswer)
		case <-ctx.Done():
			h.log.Infof("stop listening for remote offers and answers")
			return
		}
	}
}

// onSignalReceived runs the common preamble for a received offer/answer: record the
// signalling metric, refresh the remote ICE state, and register the peer's post-quantum
// data-path endpoint learned from the message.
func (h *Handshaker) onSignalReceived(remoteOfferAnswer *OfferAnswer) {
	if h.metricsStages != nil {
		h.metricsStages.RecordSignalingReceived()
	}
	h.updateRemoteICEState(remoteOfferAnswer)
	h.pqRegisterEndpoint(remoteOfferAnswer.MlkemPort)
}

// notifyListeners hands the offer/answer to the relay and ICE workers so they bring the
// connection up.
func (h *Handshaker) notifyListeners(remoteOfferAnswer *OfferAnswer) {
	if h.relayListener != nil {
		h.relayListener.Notify(remoteOfferAnswer)
	}
	if h.iceListener != nil && h.RemoteICESupported() {
		h.iceListener(remoteOfferAnswer)
	}
}

func (h *Handshaker) handleRemoteOffer(remoteOfferAnswer OfferAnswer) {
	h.log.Infof("received offer, running version %s, remote WireGuard listen port %d, session id: %s, remote ICE supported: %t", remoteOfferAnswer.Version, remoteOfferAnswer.WgListenPort, remoteOfferAnswer.SessionIDString(), remoteOfferAnswer.hasICECredentials())
	h.onSignalReceived(&remoteOfferAnswer)

	// If we are the controller running the KEM, a responder's offer is handled by
	// replying with our own KEM offer, not by answering it (see pqControllerReoffer).
	if h.pqControllerReoffer() {
		return
	}

	// Derive+store the KEM PSK (inside sendAnswer's AnswerPayload) BEFORE bringing up the
	// connection: the relay/ICE workers configure the WG endpoint, which pulls the PSK
	// for the first handshake. Notifying them first would race the KEM exchange and hand
	// the first handshake a not-yet-derived key.
	if err := h.sendAnswer(&remoteOfferAnswer); err != nil {
		h.log.Errorf("failed to send remote offer confirmation: %s", err)
		return
	}
	h.notifyListeners(&remoteOfferAnswer)
}

func (h *Handshaker) handleRemoteAnswer(remoteOfferAnswer OfferAnswer) {
	h.log.Infof("received answer, running version %s, remote WireGuard listen port %d, session id: %s, remote ICE supported: %t", remoteOfferAnswer.Version, remoteOfferAnswer.WgListenPort, remoteOfferAnswer.SessionIDString(), remoteOfferAnswer.hasICECredentials())
	h.onSignalReceived(&remoteOfferAnswer)

	// Feed the KEM answer (derive+store PSK) BEFORE bringing up the connection so the WG
	// endpoint config pulls the real PSK for the first handshake instead of racing ahead
	// of the KEM exchange.
	if h.config.PQ != nil {
		h.config.PQ.OnAnswer(h.config.Key, remoteOfferAnswer.MlkemPayload)
	}
	h.notifyListeners(&remoteOfferAnswer)
}

// pqControllerReoffer handles a responder's offer when we are the controller running the
// KEM. The KEM material rides only the controller's offer, so the two peers derive a
// single shared PSK (a bidirectional KEM would yield two different PSKs and WireGuard
// would pick misaligned ones). Rather than answer the responder's (KEM-less) offer —
// which would bring WireGuard up on a pre-PQ key before the KEM completes — we reply with
// our own KEM offer, so the only transaction that establishes the tunnel is the one that
// also derives the PSK. It also guarantees a responder-initiated wake still triggers a
// KEM offer (no stuck responder). Sent exactly once per exchange; further offers while
// one is in flight are ignored (re-sending on every responder offer would be a runaway).
// The re-offer reuses our stable ICE session id, so the peer dedups repeats.
//
// Returns true when it took ownership of the offer (the caller must not answer it).
func (h *Handshaker) pqControllerReoffer() bool {
	if h.config.PQ == nil || !isController(h.config) {
		return false
	}
	if h.config.PQ.ShouldSendBootstrapOffer(h.config.Key) {
		h.log.Debugf("pqkem: controller received a responder offer, replying with our KEM offer instead of an answer")
		if err := h.sendOffer(); err != nil {
			h.log.Errorf("failed to send KEM offer in response to peer offer: %s", err)
		}
	} else {
		h.log.Debugf("pqkem: controller received a responder offer but a KEM exchange is already in flight, ignoring")
	}
	return true
}

// pqRegisterEndpoint feeds the post-quantum handshaker the peer's data-path endpoint
// (its WG overlay IP plus the advertised pq UDP port) learned from a remote offer/answer.
func (h *Handshaker) pqRegisterEndpoint(remotePort uint16) {
	if h.config.PQ == nil {
		return
	}
	overlay, ok := h.pqPeerOverlayAddr()
	if !ok {
		return
	}
	// remotePort may be 0 (the peer omitted it, meaning the default port); the adapter
	// resolves 0 to DefaultPort.
	h.config.PQ.SetRemoteAddr(h.config.Key, netip.AddrPortFrom(overlay, remotePort))
}

// pqPeerOverlayAddr returns the peer's IPv4 overlay address for the pq data path. A
// RemotePeerConfig carries only the peer overlay (v4 /32, optionally v6 /128) — served
// routes are programmed on WireGuard separately and never land in WgConfig.AllowedIps —
// so AllowedIps[0] is the v4 overlay, matching conn.AllowedIP(). The transport is v4
// (the overlay always has v4; v6 is additive). Returns false when no v4 overlay exists.
func (h *Handshaker) pqPeerOverlayAddr() (netip.Addr, bool) {
	if len(h.config.WgConfig.AllowedIps) == 0 {
		return netip.Addr{}, false
	}
	if a := h.config.WgConfig.AllowedIps[0].Addr().Unmap(); a.Is4() {
		return a, true
	}
	return netip.Addr{}, false
}

func (h *Handshaker) SendOffer() error {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.sendOffer()
}

// OnRemoteOffer hands an offer to Listen without blocking, keeping only the most
// recent one if several arrive before Listen reads them.
func (h *Handshaker) OnRemoteOffer(offer OfferAnswer) {
	enqueueLatest(h.remoteOffersCh, offer)
}

// OnRemoteAnswer hands an answer to Listen without blocking, keeping only the most
// recent one if several arrive before Listen reads them.
func (h *Handshaker) OnRemoteAnswer(answer OfferAnswer) {
	enqueueLatest(h.remoteAnswerCh, answer)
}

// enqueueLatest delivers msg on a one-slot channel without blocking. When the slot
// already holds an unread message the older one is discarded in favor of msg, so a
// message arriving before Listen starts reading is held rather than dropped, and
// the newest wins if several arrive first. Safe because there is a single producer
// (the engine loop): after draining the stale value the send always has room.
func enqueueLatest(ch chan OfferAnswer, msg OfferAnswer) {
	select {
	case ch <- msg:
		return
	default:
	}

	select {
	case <-ch:
	default:
	}

	select {
	case ch <- msg:
	default:
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
