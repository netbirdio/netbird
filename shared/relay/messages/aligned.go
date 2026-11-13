package messages

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// Auth envelope extension area: a list of fields, each one byte type, a two byte
// big endian length and the value. Receivers skip types they do not know.
const (
	// ExtTypePeriod carries the aligned heartbeat period in seconds, uint16 big endian.
	ExtTypePeriod byte = 1
	// ExtTypeSignedPhase carries the phase signed by Management: phase ms uint32,
	// day int64 and the signature bytes, integers big endian.
	ExtTypeSignedPhase byte = 2

	extHeaderSize      = 1 + 2
	extPeriodSize      = 2
	extSignedPhaseHead = 4 + 8
	// MaxPhaseSignatureSize bounds the signature in the signed phase field.
	MaxPhaseSignatureSize = 64

	sizeOfHealthcheckPhase = 4
)

var (
	ErrInvalidExtension = errors.New("invalid auth extension")
)

// AuthSignedPhase is the phase Management signed for the peer.
type AuthSignedPhase struct {
	PhaseMs   uint32
	Day       int64
	Signature []byte
}

// AuthExtension holds the known fields of the auth envelope extension area.
type AuthExtension struct {
	// PeriodSeconds is zero when the field is absent.
	PeriodSeconds uint16
	SignedPhase   *AuthSignedPhase
}

// HealthcheckEchoMsg is a parsed client health check answer.
type HealthcheckEchoMsg struct {
	// PhaseMs is the phase the client wants, valid only when HasPhase is set.
	PhaseMs  uint32
	HasPhase bool
	// Ext holds the fields of the extension that followed the phase.
	Ext AuthExtension
}

// MarshalAuthExtension encodes the set fields of ext.
func MarshalAuthExtension(ext AuthExtension) ([]byte, error) {
	var out []byte
	if ext.PeriodSeconds != 0 {
		out = appendExtHeader(out, ExtTypePeriod, extPeriodSize)
		out = binary.BigEndian.AppendUint16(out, ext.PeriodSeconds)
	}
	if sp := ext.SignedPhase; sp != nil {
		if len(sp.Signature) == 0 || len(sp.Signature) > MaxPhaseSignatureSize {
			return nil, fmt.Errorf("signature length %d: %w", len(sp.Signature), ErrInvalidExtension)
		}
		out = appendExtHeader(out, ExtTypeSignedPhase, extSignedPhaseHead+len(sp.Signature))
		out = binary.BigEndian.AppendUint32(out, sp.PhaseMs)
		out = binary.BigEndian.AppendUint64(out, uint64(sp.Day))
		out = append(out, sp.Signature...)
	}
	return out, nil
}

// UnmarshalAuthExtension parses an extension area. Unknown field types are skipped.
// A truncated field, a known field with a wrong length or value, or a repeated known
// field is an error. The result does not alias b.
func UnmarshalAuthExtension(b []byte) (AuthExtension, error) {
	var ext AuthExtension
	var seenPeriod bool
	for len(b) > 0 {
		if len(b) < extHeaderSize {
			return AuthExtension{}, fmt.Errorf("truncated field header: %w", ErrInvalidExtension)
		}
		typ := b[0]
		length := int(binary.BigEndian.Uint16(b[1:extHeaderSize]))
		b = b[extHeaderSize:]
		if length > len(b) {
			return AuthExtension{}, fmt.Errorf("field %d length %d exceeds the area: %w", typ, length, ErrInvalidExtension)
		}
		value := b[:length]
		b = b[length:]

		switch typ {
		case ExtTypePeriod:
			if seenPeriod {
				return AuthExtension{}, fmt.Errorf("repeated period: %w", ErrInvalidExtension)
			}
			period, err := parseExtPeriod(value)
			if err != nil {
				return AuthExtension{}, err
			}
			ext.PeriodSeconds, seenPeriod = period, true
		case ExtTypeSignedPhase:
			if ext.SignedPhase != nil {
				return AuthExtension{}, fmt.Errorf("repeated signed phase: %w", ErrInvalidExtension)
			}
			sp, err := parseExtSignedPhase(value)
			if err != nil {
				return AuthExtension{}, err
			}
			ext.SignedPhase = sp
		}
	}
	return ext, nil
}

// HealthcheckPhase creates a health check message that carries a phase in ms. On a
// v2 connection the server sends the phase it uses, and the client echo carries the
// phase it wants.
func (e Encoder) HealthcheckPhase(phaseMs uint32) []byte {
	msg := make([]byte, sizeOfProtoHeader, sizeOfProtoHeader+sizeOfHealthcheckPhase)
	msg[0] = byte(e.version)
	msg[1] = byte(MsgTypeHealthCheck)
	return binary.BigEndian.AppendUint32(msg, phaseMs)
}

// UnmarshalHealthcheckPhase returns the phase a health check message carries. ok is
// false for a message without payload. Any other payload size is an error.
func UnmarshalHealthcheckPhase(msg []byte) (phaseMs uint32, ok bool, err error) {
	switch len(msg) {
	case sizeOfProtoHeader:
		return 0, false, nil
	case sizeOfProtoHeader + sizeOfHealthcheckPhase:
		return binary.BigEndian.Uint32(msg[sizeOfProtoHeader:]), true, nil
	default:
		return 0, false, ErrInvalidMessageLength
	}
}

// HealthcheckEcho creates the client answer to a v2 health check: the phase the
// client wants, followed by ext in the auth extension format when the client has
// a new signed phase for the server.
func (e Encoder) HealthcheckEcho(phaseMs uint32, ext []byte) []byte {
	msg := make([]byte, sizeOfProtoHeader, sizeOfProtoHeader+sizeOfHealthcheckPhase+len(ext))
	msg[0] = byte(e.version)
	msg[1] = byte(MsgTypeHealthCheck)
	msg = binary.BigEndian.AppendUint32(msg, phaseMs)
	return append(msg, ext...)
}

// UnmarshalHealthcheckEcho parses a client health check answer. A message
// without payload is a plain v1 style answer. A payload shorter than a phase or
// a malformed extension is an error.
func UnmarshalHealthcheckEcho(msg []byte) (HealthcheckEchoMsg, error) {
	if len(msg) < sizeOfProtoHeader {
		return HealthcheckEchoMsg{}, ErrInvalidMessageLength
	}
	payload := msg[sizeOfProtoHeader:]
	if len(payload) == 0 {
		return HealthcheckEchoMsg{}, nil
	}
	if len(payload) < sizeOfHealthcheckPhase {
		return HealthcheckEchoMsg{}, ErrInvalidMessageLength
	}
	ext, err := UnmarshalAuthExtension(payload[sizeOfHealthcheckPhase:])
	if err != nil {
		return HealthcheckEchoMsg{}, err
	}
	return HealthcheckEchoMsg{
		PhaseMs:  binary.BigEndian.Uint32(payload[:sizeOfHealthcheckPhase]),
		HasPhase: true,
		Ext:      ext,
	}, nil
}

func appendExtHeader(out []byte, typ byte, length int) []byte {
	out = append(out, typ)
	return binary.BigEndian.AppendUint16(out, uint16(length))
}

func parseExtPeriod(value []byte) (uint16, error) {
	if len(value) != extPeriodSize {
		return 0, fmt.Errorf("period length %d: %w", len(value), ErrInvalidExtension)
	}
	period := binary.BigEndian.Uint16(value)
	if period == 0 {
		return 0, fmt.Errorf("zero period: %w", ErrInvalidExtension)
	}
	return period, nil
}

func parseExtSignedPhase(value []byte) (*AuthSignedPhase, error) {
	sigLen := len(value) - extSignedPhaseHead
	if sigLen < 1 || sigLen > MaxPhaseSignatureSize {
		return nil, fmt.Errorf("signed phase length %d: %w", len(value), ErrInvalidExtension)
	}
	day := int64(binary.BigEndian.Uint64(value[4:extSignedPhaseHead]))
	if day < 0 {
		return nil, fmt.Errorf("negative day: %w", ErrInvalidExtension)
	}
	return &AuthSignedPhase{
		PhaseMs:   binary.BigEndian.Uint32(value[:4]),
		Day:       day,
		Signature: append([]byte(nil), value[extSignedPhaseHead:]...),
	}, nil
}
