package pqkem

import (
	"crypto/mlkem"
	"fmt"
)

// Wire framing for the PQ-KEM exchange. Messages are self-contained, versioned,
// transport-agnostic byte blobs: the same bytes ride the signalling channel
// (initial bootstrap) or a data-tunnel packet (rekey). The library only ever sees
// opaque []byte at the transport seam.
//
// Layout (all messages): [type:1][version:1][exchangeID:16][payload...]
//
// There is no confirm message: an exchange is acknowledged by the NEXT offer, which
// carries the acked exchange's id (see OfferMsg.AckID) and — riding the data path
// under the freshly adopted key — proves that key works.

const (
	// ProtocolVersion is bumped on any wire-incompatible change; a peer rejects
	// messages it does not understand rather than misparsing them.
	ProtocolVersion uint8 = 1

	// ExchangeIDSize identifies one exchange so answers/acks correlate and stale
	// messages are dropped.
	ExchangeIDSize = 16

	headerSize = 1 + 1 + ExchangeIDSize
)

// MsgType tags the two message kinds of the exchange.
type MsgType uint8

const (
	MsgOffer MsgType = iota + 1
	MsgAnswer
)

// ExchangeID is the per-exchange correlator. The zero value means "none" (an offer
// that acknowledges nothing, i.e. the first exchange of a connection).
type ExchangeID [ExchangeIDSize]byte

// OfferMsg carries the initiator's public material (ML-KEM encap key ‖ X25519 pub)
// and AckID, the id of the previous exchange this offer acknowledges (zero if none).
type OfferMsg struct {
	ExchangeID ExchangeID
	AckID      ExchangeID
	// KEMOffer is the raw Initiator.Offer() blob (OfferSize bytes).
	KEMOffer []byte
}

// AnswerMsg carries the responder's reply (ML-KEM ciphertext ‖ X25519 pub) for the
// round identified by ExchangeID.
type AnswerMsg struct {
	ExchangeID ExchangeID
	// KEMAnswer is the raw Respond() answer blob (AnswerSize bytes).
	KEMAnswer []byte
}

// Encode serialises the offer with its framed header (payload = AckID ‖ KEMOffer).
func (m *OfferMsg) Encode() ([]byte, error) {
	if len(m.KEMOffer) != OfferSize {
		return nil, fmt.Errorf("offer payload: got %d, want %d", len(m.KEMOffer), OfferSize)
	}
	payload := make([]byte, 0, ExchangeIDSize+OfferSize)
	payload = append(payload, m.AckID[:]...)
	payload = append(payload, m.KEMOffer...)
	return frame(MsgOffer, m.ExchangeID, payload), nil
}

// Encode serialises the answer with its framed header.
func (m *AnswerMsg) Encode() ([]byte, error) {
	if len(m.KEMAnswer) != AnswerSize {
		return nil, fmt.Errorf("answer payload: got %d, want %d", len(m.KEMAnswer), AnswerSize)
	}
	return frame(MsgAnswer, m.ExchangeID, m.KEMAnswer), nil
}

// Decode parses a framed message into one of *OfferMsg / *AnswerMsg.
func Decode(buf []byte) (MsgType, any, error) {
	if len(buf) < headerSize {
		return 0, nil, fmt.Errorf("message too short: %d bytes", len(buf))
	}
	typ := MsgType(buf[0])
	if ver := buf[1]; ver != ProtocolVersion {
		return typ, nil, fmt.Errorf("unsupported protocol version %d (want %d)", ver, ProtocolVersion)
	}

	var id ExchangeID
	copy(id[:], buf[2:headerSize])
	payload := buf[headerSize:]

	switch typ {
	case MsgOffer:
		if len(payload) != ExchangeIDSize+OfferSize {
			return typ, nil, fmt.Errorf("offer payload: got %d, want %d", len(payload), ExchangeIDSize+OfferSize)
		}
		var ack ExchangeID
		copy(ack[:], payload[:ExchangeIDSize])
		return typ, &OfferMsg{ExchangeID: id, AckID: ack, KEMOffer: payload[ExchangeIDSize:]}, nil
	case MsgAnswer:
		if len(payload) != AnswerSize {
			return typ, nil, fmt.Errorf("answer payload: got %d, want %d", len(payload), AnswerSize)
		}
		return typ, &AnswerMsg{ExchangeID: id, KEMAnswer: payload}, nil
	default:
		return typ, nil, fmt.Errorf("unknown message type %d", typ)
	}
}

func frame(typ MsgType, id ExchangeID, payload []byte) []byte {
	buf := make([]byte, headerSize+len(payload))
	buf[0] = byte(typ)
	buf[1] = ProtocolVersion
	copy(buf[2:], id[:])
	copy(buf[headerSize:], payload)
	return buf
}

// compile-time assurance the KEM blob sizes referenced here stay in sync with kem.go.
var _ = [1]struct{}{}[OfferSize-(32+mlkem.EncapsulationKeySize768)]
