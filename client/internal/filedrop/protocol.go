package filedrop

import (
	"errors"
	"fmt"
	"time"
)

// Port is the file drop port over the tunnel. It stays fixed whatever the
// receiver ends up binding locally: a receiver that cannot take this port binds
// another one and redirects this port to it, so senders never negotiate.
const Port uint16 = 22042

// EnvPort overrides the local listen port; the tunnel-side port stays Port.
const EnvPort = "NB_FILEDROP_PORT"

// HeaderReceivedBytes carries the receiver's confirmed byte count in a HEAD response.
const HeaderReceivedBytes = "Netbird-Received-Bytes"

// DefaultOfferTTL bounds how long an offer waits for the receiver's decision.
const DefaultOfferTTL = 5 * time.Minute

// MaxOfferFiles bounds the number of items a single offer may announce.
const MaxOfferFiles = 512

// MaxInlineTextSize bounds an inline text snippet, which is held in memory.
const MaxInlineTextSize = 64 * 1024

const maxOfferBodySize = 1 << 20

const (
	pathOffers      = "/v1/offers"
	pathOffersSlash = pathOffers + "/"

	segmentFiles = "files"
)

// The decisions an offer can carry. Pending is the only non-final one.
const (
	DecisionPending Decision = iota
	DecisionAccepted
	DecisionDeclined
	DecisionExpired
)

// The receiving modes a profile can be in.
const (
	ModeOff Mode = iota
	ModeAsk
	ModeAutoAccept
)

// The payload kinds an offer can announce.
const (
	KindFile Kind = iota
	KindText
)

// The states a transfer moves through.
const (
	StatePending State = iota
	StateTransferring
	StateCompleted
	StateDeclined
	StateExpired
	StateCancelled
	StateFailed
)

var (
	ErrOfferNotFound = errors.New("offer not found")
	ErrRefused       = errors.New("offer refused by receiver")
	ErrDeclined      = errors.New("offer declined")
	ErrExpired       = errors.New("offer expired")
	ErrNotAccepted   = errors.New("offer not accepted")
	ErrUnknownPeer   = errors.New("unknown peer")
	ErrInvalidOffer  = errors.New("invalid offer")
)

// OfferID identifies a single transfer offer on the receiving peer.
type OfferID string

// PeerKey is the remote peer's public key, used as the identity for per-sender policy.
type PeerKey string

// Decision is the receiver's answer to an offer.
type Decision uint8

// Mode is the receiver's profile-local policy for incoming offers.
type Mode uint8

// Kind distinguishes payloads that are written to the spool from inline text snippets.
type Kind uint8

// State is the lifecycle state of a transfer, on either side.
type State uint8

// FileMeta describes one payload item announced in an offer.
type FileMeta struct {
	Name        string `json:"name"`
	Size        int64  `json:"size"`
	ContentType string `json:"contentType,omitempty"`
	Kind        Kind   `json:"kind,omitempty"`
	Text        string `json:"text,omitempty"`
}

// OfferRequest is the JSON body of POST /v1/offers. It carries metadata only.
type OfferRequest struct {
	SenderName string     `json:"senderName,omitempty"`
	Files      []FileMeta `json:"files"`
}

// OfferResponse is returned for an offer and for every poll of its status.
type OfferResponse struct {
	ID       OfferID  `json:"id"`
	Decision Decision `json:"decision"`
}

// String implements fmt.Stringer.
func (d Decision) String() string {
	switch d {
	case DecisionPending:
		return "pending"
	case DecisionAccepted:
		return "accepted"
	case DecisionDeclined:
		return "declined"
	case DecisionExpired:
		return "expired"
	default:
		return fmt.Sprintf("unknown(%d)", uint8(d))
	}
}

func (d Decision) valid() bool {
	switch d {
	case DecisionPending, DecisionAccepted, DecisionDeclined, DecisionExpired:
		return true
	default:
		return false
	}
}

// String implements fmt.Stringer.
func (m Mode) String() string {
	switch m {
	case ModeOff:
		return "off"
	case ModeAsk:
		return "ask"
	case ModeAutoAccept:
		return "auto"
	default:
		return fmt.Sprintf("unknown(%d)", uint8(m))
	}
}

func (m Mode) valid() bool {
	switch m {
	case ModeOff, ModeAsk, ModeAutoAccept:
		return true
	default:
		return false
	}
}

// String implements fmt.Stringer.
func (k Kind) String() string {
	switch k {
	case KindFile:
		return "file"
	case KindText:
		return "text"
	default:
		return fmt.Sprintf("unknown(%d)", uint8(k))
	}
}

func (k Kind) valid() bool {
	return k == KindFile || k == KindText
}

// String implements fmt.Stringer.
func (s State) String() string {
	switch s {
	case StatePending:
		return "pending"
	case StateTransferring:
		return "transferring"
	case StateCompleted:
		return "completed"
	case StateDeclined:
		return "declined"
	case StateExpired:
		return "expired"
	case StateCancelled:
		return "cancelled"
	case StateFailed:
		return "failed"
	default:
		return fmt.Sprintf("unknown(%d)", uint8(s))
	}
}
