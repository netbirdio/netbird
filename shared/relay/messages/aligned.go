package messages

import "encoding/binary"

// sizeOfHealthcheckPeriod is the size of the period payload of an aligned
// health check frame: seconds, uint16 big endian.
const sizeOfHealthcheckPeriod = 2

// HealthcheckWithPeriod creates a health check message that carries the
// aligned heartbeat period in seconds as its payload. The same layout is
// used in both directions: the client sends it right after the auth response
// and in every health check answer, and an aligned server sends its health
// checks with it. A period of zero creates the plain stock health check.
//
// The frame stays protocol v1 with the stock handshake. A stock server only
// calls OnHCResponse for a health check and ignores the payload.
func (e Encoder) HealthcheckWithPeriod(periodSeconds uint16) []byte {
	if periodSeconds == 0 {
		return e.Healthcheck()
	}
	msg := make([]byte, sizeOfProtoHeader, sizeOfProtoHeader+sizeOfHealthcheckPeriod)
	msg[0] = byte(e.version)
	msg[1] = byte(MsgTypeHealthCheck)
	return binary.BigEndian.AppendUint16(msg, periodSeconds)
}

// MarshalHealthcheckWithPeriod creates a health check message that carries
// the aligned heartbeat period in seconds, at CurrentProtocolVersion.
func MarshalHealthcheckWithPeriod(periodSeconds uint16) []byte {
	return NewEncoder(CurrentProtocolVersion, MaxMessageSize).HealthcheckWithPeriod(periodSeconds)
}

// UnmarshalHealthcheckPeriod returns the period a health check message
// carries in the first 2 bytes of its payload. Bytes after the period are
// ignored, so a later release can add fields there. ok is false for a message
// without a payload and for a zero period: both stay stock. A 1-byte payload
// is an error, and the caller then also stays stock. The period is returned
// raw; the caller clamps it.
func UnmarshalHealthcheckPeriod(msg []byte) (periodSeconds uint16, ok bool, err error) {
	if len(msg) < sizeOfProtoHeader {
		return 0, false, ErrInvalidMessageLength
	}
	payload := msg[sizeOfProtoHeader:]
	switch {
	case len(payload) == 0:
		return 0, false, nil
	case len(payload) < sizeOfHealthcheckPeriod:
		return 0, false, ErrInvalidMessageLength
	}
	periodSeconds = binary.BigEndian.Uint16(payload)
	return periodSeconds, periodSeconds != 0, nil
}
