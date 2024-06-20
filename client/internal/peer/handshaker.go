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

type DoHandshake func() (*OfferAnswer, error)

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
	mu       sync.Mutex
	ctx      context.Context
	log      *log.Entry
	config   ConnConfig
	signaler *Signaler

	// remoteOffersCh is a channel used to wait for remote credentials to proceed with the connection
	remoteOffersCh chan OfferAnswer
	// remoteAnswerCh is a channel used to wait for remote credentials answer (confirmation of our offer) to proceed with the connection
	remoteAnswerCh chan OfferAnswer

	remoteOfferAnswer        *OfferAnswer
	remoteOfferAnswerCreated time.Time

	handshakeArgs HandshakeArgs
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

func (h *Handshaker) Handshake(args HandshakeArgs) (*OfferAnswer, error) {
	h.mu.Lock()
	defer h.mu.Unlock()

	h.log.Infof("start handshake with remote peer")
	h.handshakeArgs = args

	cachedOfferAnswer, ok := h.cachedHandshake()
	if ok {
		return cachedOfferAnswer, nil
	}

	err := h.sendOffer(args)
	if err != nil {
		return nil, err
	}

	// Only continue once we got a connection confirmation from the remote peer.
	// The connection timeout could have happened before a confirmation received from the remote.
	// The connection could have also been closed externally (e.g. when we received an update from the management that peer shouldn't be connected)
	remoteOfferAnswer, err := h.waitForRemoteOfferConfirmation()
	if err != nil {
		return nil, err
	}
	h.storeRemoteOfferAnswer(remoteOfferAnswer)

	h.log.Debugf("received connection confirmation, running version %s and with remote WireGuard listen port %d",
		remoteOfferAnswer.Version, remoteOfferAnswer.WgListenPort)

	return remoteOfferAnswer, nil
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
		IceCredentials:  IceCredentials{h.handshakeArgs.IceUFrag, h.handshakeArgs.IcePwd},
		WgListenPort:    h.config.LocalWgPort,
		Version:         version.NetbirdVersion(),
		RosenpassPubKey: h.config.RosenpassPubKey,
		RosenpassAddr:   h.config.RosenpassAddr,
		RelaySrvAddress: h.handshakeArgs.RelayAddr,
	}
	err := h.signaler.SignalAnswer(answer, h.config.Key)
	if err != nil {
		return err
	}

	return nil
}

func (h *Handshaker) waitForRemoteOfferConfirmation() (*OfferAnswer, error) {
	timeout := time.NewTimer(h.config.Timeout)
	defer timeout.Stop()

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
	case <-timeout.C:
		h.log.Debugf("handshake timeout")
		return nil, NewConnectionTimeoutError(h.config.Key, h.config.Timeout)
	case <-h.ctx.Done():
		// closed externally
		return nil, NewConnectionClosedError(h.config.Key)
	}
}

func (h *Handshaker) storeRemoteOfferAnswer(answer *OfferAnswer) {
	h.remoteOfferAnswer = answer
	h.remoteOfferAnswerCreated = time.Now()
}

func (h *Handshaker) cachedHandshake() (*OfferAnswer, bool) {
	if h.remoteOfferAnswer == nil {
		return nil, false
	}

	if time.Since(h.remoteOfferAnswerCreated) > handshakeCacheTimeout {
		return nil, false
	}

	return h.remoteOfferAnswer, true
}
