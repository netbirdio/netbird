package peer

import (
	"context"
	"errors"
	"sync"

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

	// relay server address
	RelaySrvAddress string
	// SessionID is the unique identifier of the session, used to discard old messages
	SessionID *ICESessionID
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

	// remoteOffersCh is a channel used to wait for remote credentials to proceed with the connection
	remoteOffersCh chan OfferAnswer
	// remoteAnswerCh is a channel used to wait for remote credentials answer (confirmation of our offer) to proceed with the connection
	remoteAnswerCh chan OfferAnswer
}

func NewHandshaker(log *log.Entry, config ConnConfig, signaler *Signaler, ice *WorkerICE, relay *WorkerRelay, metricsStages *MetricsStages) *Handshaker {
	return &Handshaker{
		log:            log,
		config:         config,
		signaler:       signaler,
		ice:            ice,
		relay:          relay,
		metricsStages:  metricsStages,
		remoteOffersCh: make(chan OfferAnswer),
		remoteAnswerCh: make(chan OfferAnswer),
	}
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
			h.log.Infof("received offer, running version %s, remote WireGuard listen port %d, session id: %s", remoteOfferAnswer.Version, remoteOfferAnswer.WgListenPort, remoteOfferAnswer.SessionIDString())

			// Record signaling received for reconnection attempts
			if h.metricsStages != nil {
				h.metricsStages.RecordSignalingReceived()
			}

			if h.relayListener != nil {
				h.relayListener.Notify(&remoteOfferAnswer)
			}

			if h.iceListener != nil {
				h.iceListener(&remoteOfferAnswer)
			}

			if err := h.sendAnswer(); err != nil {
				h.log.Errorf("failed to send remote offer confirmation: %s", err)
				continue
			}
		case remoteOfferAnswer := <-h.remoteAnswerCh:
			h.log.Infof("received answer, running version %s, remote WireGuard listen port %d, session id: %s", remoteOfferAnswer.Version, remoteOfferAnswer.WgListenPort, remoteOfferAnswer.SessionIDString())

			// Record signaling received for reconnection attempts
			if h.metricsStages != nil {
				h.metricsStages.RecordSignalingReceived()
			}

			if h.relayListener != nil {
				h.relayListener.Notify(&remoteOfferAnswer)
			}

			if h.iceListener != nil {
				h.iceListener(&remoteOfferAnswer)
			}
		case <-ctx.Done():
			h.log.Infof("stop listening for remote offers and answers")
			return
		}
	}
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
	h.log.Infof("sending offer with serial: %s", offer.SessionIDString())

	return h.signaler.SignalOffer(offer, h.config.Key)
}

func (h *Handshaker) sendAnswer() error {
	answer := h.buildOfferAnswer()
	h.log.Infof("sending answer with serial: %s", answer.SessionIDString())

	return h.signaler.SignalAnswer(answer, h.config.Key)
}

func (h *Handshaker) buildOfferAnswer() OfferAnswer {
	uFrag, pwd := h.ice.GetLocalUserCredentials()
	sid := h.ice.SessionID()
	answer := OfferAnswer{
		IceCredentials:  IceCredentials{uFrag, pwd},
		WgListenPort:    h.config.LocalWgPort,
		Version:         version.NetbirdVersion(),
		RosenpassPubKey: h.config.RosenpassConfig.PubKey,
		RosenpassAddr:   h.config.RosenpassConfig.Addr,
		SessionID:       &sid,
	}

	if addr, err := h.relay.RelayInstanceAddress(); err == nil {
		answer.RelaySrvAddress = addr
	}

	return answer
}
