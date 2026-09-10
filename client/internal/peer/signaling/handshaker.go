package signaling

import (
	"errors"
	"net/netip"
	"sync"
	"sync/atomic"

	log "github.com/sirupsen/logrus"

	icemaker "github.com/netbirdio/netbird/client/internal/peer/ice"
	relayClient "github.com/netbirdio/netbird/shared/relay/client"
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
	// RelaySrvIP is the IP the remote peer is connected to on its
	// relay server. Used as a dial target if DNS for RelaySrvAddress
	// fails. Zero value if the peer did not advertise an IP.
	RelaySrvIP netip.Addr
	// SessionID is the unique identifier of the session, used to discard old messages
	SessionID *icemaker.SessionID
}

func (o *OfferAnswer) HasICECredentials() bool {
	return o.IceCredentials.UFrag != "" && o.IceCredentials.Pwd != ""
}

func (o *OfferAnswer) SessionIDString() string {
	if o.SessionID == nil {
		return "unknown"
	}
	return o.SessionID.String()
}

// Config carries the peer-specific values the Handshaker embeds into offers
// and answers.
type Config struct {
	Key             string
	LocalWgPort     int
	RosenpassPubKey []byte
	RosenpassAddr   string
}

// Credentials are the local ICE credentials and session id the Handshaker embeds in offers.
type Credentials struct {
	UFrag     string
	Pwd       string
	SessionID icemaker.SessionID
}

// ICEWorker is the subset of the ICE worker the Handshaker needs to build offers.
type ICEWorker interface {
	Credentials() Credentials
	Close()
}

// Handshaker keeps the signaling protocol logic: building and sending offers
// and answers and tracking whether the remote peer supports ICE. Incoming
// message processing is driven by the Conn event loop.
type Handshaker struct {
	mu           sync.Mutex
	log          *log.Entry
	config       Config
	signaler     *Signaler
	ice          ICEWorker
	relayManager *relayClient.Manager

	// remoteICESupported tracks whether the remote peer includes ICE credentials in its offers/answers.
	// When false, the local side skips ICE dispatch and suppresses ICE credentials in responses.
	remoteICESupported atomic.Bool
}

func NewHandshaker(log *log.Entry, config Config, signaler *Signaler, ice ICEWorker, relayManager *relayClient.Manager) *Handshaker {
	h := &Handshaker{
		log:          log,
		config:       config,
		signaler:     signaler,
		ice:          ice,
		relayManager: relayManager,
	}
	// assume remote supports ICE until we learn otherwise from received offers
	h.remoteICESupported.Store(ice != nil)
	return h
}

func (h *Handshaker) RemoteICESupported() bool {
	return h.remoteICESupported.Load()
}

func (h *Handshaker) SendOffer() error {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.sendOffer()
}

func (h *Handshaker) SendAnswer() error {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.sendAnswer()
}

// sendOffer prepares local user credentials and signals them to the remote peer
func (h *Handshaker) sendOffer() error {
	if !h.signaler.Ready() {
		return ErrSignalIsNotReady
	}

	offer := h.buildOfferAnswer()
	h.log.Debugf("sending offer with serial: %s", offer.SessionIDString())

	return h.signaler.SignalOffer(offer, h.config.Key)
}

func (h *Handshaker) sendAnswer() error {
	answer := h.buildOfferAnswer()
	h.log.Debugf("sending answer with serial: %s", answer.SessionIDString())

	return h.signaler.SignalAnswer(answer, h.config.Key)
}

func (h *Handshaker) buildOfferAnswer() OfferAnswer {
	answer := OfferAnswer{
		WgListenPort:    h.config.LocalWgPort,
		Version:         version.NetbirdVersion(),
		RosenpassPubKey: h.config.RosenpassPubKey,
		RosenpassAddr:   h.config.RosenpassAddr,
	}

	if h.ice != nil && h.RemoteICESupported() {
		creds := h.ice.Credentials()
		answer.IceCredentials = IceCredentials{creds.UFrag, creds.Pwd}
		sid := creds.SessionID
		answer.SessionID = &sid
	}

	if addr, ip, err := h.relayManager.RelayInstanceAddress(); err == nil {
		answer.RelaySrvAddress = addr
		answer.RelaySrvIP = ip
	}

	return answer
}

// UpdateRemoteICEState refreshes the remote ICE support flag from a received
// offer or answer and closes the ICE worker when the remote peer stopped
// sending ICE credentials. Runs on the Conn event loop.
func (h *Handshaker) UpdateRemoteICEState(offer *OfferAnswer) {
	hasICE := offer.HasICECredentials()
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
