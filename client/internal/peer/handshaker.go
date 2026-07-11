package peer

import (
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

func (o *OfferAnswer) SessionIDString() string {
	if o.SessionID == nil {
		return "unknown"
	}
	return o.SessionID.String()
}

// Handshaker keeps the signaling protocol logic: building and sending offers
// and answers and tracking whether the remote peer supports ICE. Incoming
// message processing is driven by the Conn event loop.
type Handshaker struct {
	mu       sync.Mutex
	log      *log.Entry
	config   ConnConfig
	signaler *Signaler
	ice      *WorkerICE
	relay    *WorkerRelay

	// remoteICESupported tracks whether the remote peer includes ICE credentials in its offers/answers.
	// When false, the local side skips ICE dispatch and suppresses ICE credentials in responses.
	remoteICESupported atomic.Bool
}

func NewHandshaker(log *log.Entry, config ConnConfig, signaler *Signaler, ice *WorkerICE, relay *WorkerRelay) *Handshaker {
	h := &Handshaker{
		log:      log,
		config:   config,
		signaler: signaler,
		ice:      ice,
		relay:    relay,
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

// updateRemoteICEState refreshes the remote ICE support flag from a received
// offer or answer and closes the ICE worker when the remote peer stopped
// sending ICE credentials. Runs on the Conn event loop.
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
