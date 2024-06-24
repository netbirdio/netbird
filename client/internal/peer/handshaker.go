package peer

import (
	"context"
	"errors"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/version"
)

const (
	handshakeCacheTimeout = 3 * time.Second
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

type HandshakeArgs struct {
	IceUFrag  string
	IcePwd    string
	RelayAddr string
}

type Handshaker struct {
	mu                  sync.Mutex
	ctx                 context.Context
	log                 *log.Entry
	config              ConnConfig
	signaler            *Signaler
	onNewOfferListeners []func(*OfferAnswer)

	// remoteOffersCh is a channel used to wait for remote credentials to proceed with the connection
	remoteOffersCh chan OfferAnswer
	// remoteAnswerCh is a channel used to wait for remote credentials answer (confirmation of our offer) to proceed with the connection
	remoteAnswerCh chan OfferAnswer

	remoteOfferAnswer        *OfferAnswer
	remoteOfferAnswerCreated time.Time

	lastOfferArgs HandshakeArgs
}

func NewHandshaker(ctx context.Context, log *log.Entry, config ConnConfig, signaler *Signaler) *Handshaker {
	return &Handshaker{
		ctx:            ctx,
		log:            log,
		config:         config,
		signaler:       signaler,
		remoteOffersCh: make(chan OfferAnswer),
		remoteAnswerCh: make(chan OfferAnswer),
	}
}

func (h *Handshaker) AddOnNewOfferListener(offer func(remoteOfferAnswer *OfferAnswer)) {
	h.onNewOfferListeners = append(h.onNewOfferListeners, offer)
}

func (h *Handshaker) Listen() {
	for {
		remoteOfferAnswer, err := h.waitForRemoteOfferConfirmation()
		if err != nil {
			if _, ok := err.(*ConnectionClosedError); ok {
				log.Tracef("stop handshaker")
				return
			}
			log.Errorf("failed to received remote offer confirmation: %s", err)
			continue
		}

		h.log.Debugf("received connection confirmation, running version %s and with remote WireGuard listen port %d", remoteOfferAnswer.Version, remoteOfferAnswer.WgListenPort)
		for _, listener := range h.onNewOfferListeners {
			go listener(remoteOfferAnswer)
		}
	}
}

func (h *Handshaker) SendOffer(args HandshakeArgs) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	err := h.sendOffer(args)
	if err != nil {
		return err
	}

	h.lastOfferArgs = args
	return nil
}

// OnRemoteOffer handles an offer from the remote peer and returns true if the message was accepted, false otherwise
// doesn't block, discards the message if connection wasn't ready
func (h *Handshaker) OnRemoteOffer(offer OfferAnswer) bool {
	// todo remove this if signaling can support relay
	if ForcedRelayAddress() != "" {
		offer.RelaySrvAddress = ForcedRelayAddress()
	}
	select {
	case h.remoteOffersCh <- offer:
		return true
	default:
		h.log.Debugf("OnRemoteOffer skipping message because is not ready")
		// connection might not be ready yet to receive so we ignore the message
		return false
	}
}

// OnRemoteAnswer handles an offer from the remote peer and returns true if the message was accepted, false otherwise
// doesn't block, discards the message if connection wasn't ready
func (h *Handshaker) OnRemoteAnswer(answer OfferAnswer) bool {
	// todo remove this if signaling can support relay
	if ForcedRelayAddress() != "" {
		answer.RelaySrvAddress = ForcedRelayAddress()
	}
	select {
	case h.remoteAnswerCh <- answer:
		return true
	default:
		// connection might not be ready yet to receive so we ignore the message
		h.log.Debugf("OnRemoteAnswer skipping message because is not ready")
		return false
	}
}

func (h *Handshaker) waitForRemoteOfferConfirmation() (*OfferAnswer, error) {
	select {
	case remoteOfferAnswer := <-h.remoteOffersCh:
		// received confirmation from the remote peer -> ready to proceed
		err := h.sendAnswer()
		if err != nil {
			return nil, err
		}
		return &remoteOfferAnswer, nil
	case remoteOfferAnswer := <-h.remoteAnswerCh:
		return &remoteOfferAnswer, nil
	case <-h.ctx.Done():
		// closed externally
		return nil, NewConnectionClosedError(h.config.Key)
	}
}

// sendOffer prepares local user credentials and signals them to the remote peer
func (h *Handshaker) sendOffer(args HandshakeArgs) error {
	offer := OfferAnswer{
		IceCredentials:  IceCredentials{args.IceUFrag, args.IcePwd},
		WgListenPort:    h.config.LocalWgPort,
		Version:         version.NetbirdVersion(),
		RosenpassPubKey: h.config.RosenpassPubKey,
		RosenpassAddr:   h.config.RosenpassAddr,
		RelaySrvAddress: args.RelayAddr,
	}

	return h.signaler.SignalOffer(offer, h.config.Key)
}

func (h *Handshaker) sendAnswer() error {
	h.log.Debugf("sending answer")
	answer := OfferAnswer{
		IceCredentials:  IceCredentials{h.lastOfferArgs.IceUFrag, h.lastOfferArgs.IcePwd},
		WgListenPort:    h.config.LocalWgPort,
		Version:         version.NetbirdVersion(),
		RosenpassPubKey: h.config.RosenpassPubKey,
		RosenpassAddr:   h.config.RosenpassAddr,
		RelaySrvAddress: h.lastOfferArgs.RelayAddr,
	}
	err := h.signaler.SignalAnswer(answer, h.config.Key)
	if err != nil {
		return err
	}

	return nil
}
