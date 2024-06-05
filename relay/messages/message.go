package messages

import (
	"fmt"

	log "github.com/sirupsen/logrus"
)

const (
	MsgTypeHello         MsgType = 0
	MsgTypeHelloResponse MsgType = 1
	MsgTypeTransport     MsgType = 2
	MsgClose             MsgType = 3
)

var (
	ErrInvalidMessageLength = fmt.Errorf("invalid message length")
)

type MsgType byte

func (m MsgType) String() string {
	switch m {
	case MsgTypeHello:
		return "hello"
	case MsgTypeHelloResponse:
		return "hello response"
	case MsgTypeTransport:
		return "transport"
	case MsgClose:
		return "close"
	default:
		return "unknown"
	}
}

func DetermineClientMsgType(msg []byte) (MsgType, error) {
	// todo: validate magic byte
	msgType := MsgType(msg[0])
	switch msgType {
	case MsgTypeHello:
		return msgType, nil
	case MsgTypeTransport:
		return msgType, nil
	case MsgClose:
		return msgType, nil
	default:
		return 0, fmt.Errorf("invalid msg type, len: %d", len(msg))
	}
}

func DetermineServerMsgType(msg []byte) (MsgType, error) {
	// todo: validate magic byte
	msgType := MsgType(msg[0])
	switch msgType {
	case MsgTypeHelloResponse:
		return msgType, nil
	case MsgTypeTransport:
		return msgType, nil
	case MsgClose:
		return msgType, nil
	default:
		return 0, fmt.Errorf("invalid msg type (len: %d)", len(msg))
	}
}

// MarshalHelloMsg initial hello message
func MarshalHelloMsg(peerID []byte) ([]byte, error) {
	if len(peerID) != IDSize {
		return nil, fmt.Errorf("invalid peerID length")
	}
	msg := make([]byte, 1, 1+len(peerID))
	msg[0] = byte(MsgTypeHello)
	msg = append(msg, peerID...)
	return msg, nil
}

func UnmarshalHelloMsg(msg []byte) ([]byte, error) {
	if len(msg) < 2 {
		return nil, fmt.Errorf("invalid 'hello' messge")
	}
	return msg[1:], nil
}

func MarshalHelloResponse() []byte {
	msg := make([]byte, 1)
	msg[0] = byte(MsgTypeHelloResponse)
	return msg
}

// Close message

func MarshalCloseMsg() []byte {
	msg := make([]byte, 1)
	msg[0] = byte(MsgClose)
	return msg
}

// Transport message

func MarshalTransportMsg(peerID []byte, payload []byte) []byte {
	if len(peerID) != IDSize {
		return nil
	}

	msg := make([]byte, 1+IDSize, 1+IDSize+len(payload))
	msg[0] = byte(MsgTypeTransport)
	copy(msg[1:], peerID)
	msg = append(msg, payload...)
	return msg
}

func UnmarshalTransportPayload(buf []byte) ([]byte, error) {
	headerSize := 1 + IDSize
	if len(buf) < headerSize {
		return nil, ErrInvalidMessageLength
	}
	return buf[headerSize:], nil
}

func UnmarshalTransportID(buf []byte) ([]byte, error) {
	headerSize := 1 + IDSize
	if len(buf) < headerSize {
		log.Debugf("invalid message length: %d, expected: %d, %x", len(buf), headerSize, buf)
		return nil, ErrInvalidMessageLength
	}
	return buf[1:headerSize], nil
}

func UpdateTransportMsg(msg []byte, peerID []byte) error {
	if len(msg) < 1+len(peerID) {
		return ErrInvalidMessageLength
	}
	copy(msg[1:], peerID)
	return nil
}
