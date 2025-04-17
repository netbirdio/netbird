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
}

type Handshaker struct {
	mu                  sync.Mutex
	log                 *log.Entry
	config              ConnConfig
	signaler            *Signaler
	ice                 *WorkerICE
	relay               *WorkerRelay
	onNewOfferListeners []func(*OfferAnswer)

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
	h.onNewOfferListeners = append(h.onNewOfferListeners, offer)
}

func (h *Handshaker) Listen(ctx context.Context) {
	for {
		h.log.Info("wait for remote offer confirmation")
		remoteOfferAnswer, err := h.waitForRemoteOfferConfirmation(ctx)
		if err != nil {
			var connectionClosedError *ConnectionClosedError
			if errors.As(err, &connectionClosedError) {
				h.log.Info("exit from handshaker")
				return
			}
			h.log.Errorf("failed to received remote offer confirmation: %s", err)
			continue
		}

		h.log.Infof("received connection confirmation, running version %s and with remote WireGuard listen port %d", remoteOfferAnswer.Version, remoteOfferAnswer.WgListenPort)
		for _, listener := range h.onNewOfferListeners {
			go listener(remoteOfferAnswer)
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
func (h *Handshaker) OnRemoteOffer(offer OfferAnswer) bool {
	select {
	case h.remoteOffersCh <- offer:
		return true
	default:
		h.log.Warnf("OnRemoteOffer skipping message because is not ready")
		// connection might not be ready yet to receive so we ignore the message
		return false
	}
}

// OnRemoteAnswer handles an offer from the remote peer and returns true if the message was accepted, false otherwise
// doesn't block, discards the message if connection wasn't ready
func (h *Handshaker) OnRemoteAnswer(answer OfferAnswer) bool {
	select {
	case h.remoteAnswerCh <- answer:
		return true
	default:
		// connection might not be ready yet to receive so we ignore the message
		h.log.Debugf("OnRemoteAnswer skipping message because is not ready")
		return false
	}
}

func (h *Handshaker) waitForRemoteOfferConfirmation(ctx context.Context) (*OfferAnswer, error) {
	select {
	case remoteOfferAnswer := <-h.remoteOffersCh:
		// received confirmation from the remote peer -> ready to proceed
		if err := h.sendAnswer(); err != nil {
			return nil, err
		}
		return &remoteOfferAnswer, nil
	case remoteOfferAnswer := <-h.remoteAnswerCh:
		return &remoteOfferAnswer, nil
	case <-ctx.Done():
		// closed externally
		return nil, NewConnectionClosedError(h.config.Key)
	}
}

// sendOffer prepares local user credentials and signals them to the remote peer
func (h *Handshaker) sendOffer() error {
	if !h.signaler.Ready() {
		return ErrSignalIsNotReady
	}

	iceUFrag, icePwd := h.ice.GetLocalUserCredentials()
	offer := OfferAnswer{
		IceCredentials:  IceCredentials{iceUFrag, icePwd},
		WgListenPort:    h.config.LocalWgPort,
		Version:         version.NetbirdVersion(),
		RosenpassPubKey: h.config.RosenpassConfig.PubKey,
		RosenpassAddr:   h.config.RosenpassConfig.Addr,
	}

	addr, err := h.relay.RelayInstanceAddress()
	if err == nil {
		offer.RelaySrvAddress = addr
	}

	return h.signaler.SignalOffer(offer, h.config.Key)
}

func (h *Handshaker) sendAnswer() error {
	h.log.Infof("sending answer")
	uFrag, pwd := h.ice.GetLocalUserCredentials()

	answer := OfferAnswer{
		IceCredentials:  IceCredentials{uFrag, pwd},
		WgListenPort:    h.config.LocalWgPort,
		Version:         version.NetbirdVersion(),
		RosenpassPubKey: h.config.RosenpassConfig.PubKey,
		RosenpassAddr:   h.config.RosenpassConfig.Addr,
	}
	addr, err := h.relay.RelayInstanceAddress()
	if err == nil {
		answer.RelaySrvAddress = addr
	}

	err = h.signaler.SignalAnswer(answer, h.config.Key)
	if err != nil {
		return err
	}

	return nil
}
