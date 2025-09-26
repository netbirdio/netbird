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
	mu                  sync.Mutex
	log                 *log.Entry
	config              ConnConfig
	signaler            *Signaler
	ice                 *WorkerICE
	relay               *WorkerRelay
	onNewOfferListeners []*OfferListener

	// remoteOffersCh is a channel used to wait for remote credentials to proceed with the connection
	remoteOffersCh chan OfferAnswer
	// remoteAnswerCh is a channel used to wait for remote credentials answer (confirmation of our offer) to proceed with the connection
	remoteAnswerCh chan OfferAnswer
}

func NewHandshaker(log *log.Entry, config ConnConfig, signaler *Signaler, ice *WorkerICE, relay *WorkerRelay) *Handshaker {
	return &Handshaker{
		log:            log,
		config:         config,
		signaler:       signaler,
		ice:            ice,
		relay:          relay,
		remoteOffersCh: make(chan OfferAnswer),
		remoteAnswerCh: make(chan OfferAnswer),
	}
}

func (h *Handshaker) AddOnNewOfferListener(offer func(remoteOfferAnswer *OfferAnswer)) {
	l := NewOfferListener(offer)
	h.onNewOfferListeners = append(h.onNewOfferListeners, l)
}

func (h *Handshaker) Listen(ctx context.Context) {
	for {
		select {
		case remoteOfferAnswer := <-h.remoteOffersCh:
			h.log.Infof("received offer, running version %s, remote WireGuard listen port %d, session id: %s", remoteOfferAnswer.Version, remoteOfferAnswer.WgListenPort, remoteOfferAnswer.SessionIDString())
			if err := h.sendAnswer(); err != nil {
				h.log.Errorf("failed to send remote offer confirmation: %s", err)
				continue
			}

			for _, listener := range h.onNewOfferListeners {
				listener.Notify(&remoteOfferAnswer)
			}
		case remoteOfferAnswer := <-h.remoteAnswerCh:
			h.log.Infof("received answer, running version %s, remote WireGuard listen port %d, session id: %s", remoteOfferAnswer.Version, remoteOfferAnswer.WgListenPort, remoteOfferAnswer.SessionIDString())
			for _, listener := range h.onNewOfferListeners {
				listener.Notify(&remoteOfferAnswer)
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
