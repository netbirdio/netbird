package pqkem

import (
	"crypto/mlkem"
	"fmt"
)

// Wire framing for the PQ-KEM exchange. Messages are self-contained, versioned,
// transport-agnostic byte blobs: the same bytes ride the Signal offer/answer
// (initial, pre-tunnel) or a WireGuard-tunnel packet (rekey). They are NOT a gRPC
// service — the network layer only sees opaque []byte.
//
// Layout (all messages): [type:1][version:1][exchangeID:16][payload...]

const (
	// ProtocolVersion is bumped on any wire-incompatible change; a peer rejects
	// messages it does not understand rather than misparsing them.
	ProtocolVersion uint8 = 1

	// ExchangeIDSize identifies one offer/answer/confirm round so stale answers
	// (e.g. an answer to a pre-restart offer) are dropped instead of applied.
	ExchangeIDSize = 16

	headerSize = 1 + 1 + ExchangeIDSize
)

// MsgType tags the three message kinds of the exchange.
type MsgType uint8

const (
	MsgOffer MsgType = iota + 1
	MsgAnswer
	MsgConfirm
)

// ExchangeID is the per-round correlator echoed by the answer and the confirm.
type ExchangeID [ExchangeIDSize]byte

// OfferMsg carries the initiator's public material (X25519 pub ‖ ML-KEM encap key).
type OfferMsg struct {
	ExchangeID ExchangeID
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

// ConfirmMsg is sent ONE WAY, initiator -> responder, over the tunnel under the
// NEW PSK, for the round identified by ExchangeID. It carries no key material.
//
// It is one-way because of the knowledge asymmetry of a KEM: the initiator learns
// the responder holds the key simply by receiving the answer (the responder had to
// derive it to encapsulate), so the initiator needs no confirmation. Only the
// responder is left unsure whether the initiator received the answer and committed
// the key — this message resolves that. As a bonus, being sent under the new PSK it
// triggers the WireGuard handshake with the new key: the responder converges on
// receiving it, and the initiator converges by observing that handshake succeed
// (which fails on a PSK mismatch, so success proves the responder also committed).
type ConfirmMsg struct {
	ExchangeID ExchangeID
}

// Encode serialises the offer with its framed header.
func (m *OfferMsg) Encode() ([]byte, error) {
	if len(m.KEMOffer) != OfferSize {
		return nil, fmt.Errorf("offer payload: got %d, want %d", len(m.KEMOffer), OfferSize)
	}
	return frame(MsgOffer, m.ExchangeID, m.KEMOffer), nil
}

// Encode serialises the answer with its framed header.
func (m *AnswerMsg) Encode() ([]byte, error) {
	if len(m.KEMAnswer) != AnswerSize {
		return nil, fmt.Errorf("answer payload: got %d, want %d", len(m.KEMAnswer), AnswerSize)
	}
	return frame(MsgAnswer, m.ExchangeID, m.KEMAnswer), nil
}

// Encode serialises the confirm with its framed header. It returns an error only
// for signature uniformity with the other messages; it never actually fails.
func (m *ConfirmMsg) Encode() ([]byte, error) {
	return frame(MsgConfirm, m.ExchangeID, nil), nil
}

// Decode parses a framed message into one of *OfferMsg / *AnswerMsg / *ConfirmMsg.
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
		if len(payload) != OfferSize {
			return typ, nil, fmt.Errorf("offer payload: got %d, want %d", len(payload), OfferSize)
		}
		return typ, &OfferMsg{ExchangeID: id, KEMOffer: payload}, nil
	case MsgAnswer:
		if len(payload) != AnswerSize {
			return typ, nil, fmt.Errorf("answer payload: got %d, want %d", len(payload), AnswerSize)
		}
		return typ, &AnswerMsg{ExchangeID: id, KEMAnswer: payload}, nil
	case MsgConfirm:
		if len(payload) != 0 {
			return typ, nil, fmt.Errorf("confirm payload must be empty, got %d bytes", len(payload))
		}
		return typ, &ConfirmMsg{ExchangeID: id}, nil
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
