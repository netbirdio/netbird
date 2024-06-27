package messages

import (
	"bytes"
	"fmt"

	log "github.com/sirupsen/logrus"
)

const (
	MsgTypeHello         MsgType = 0
	MsgTypeHelloResponse MsgType = 1
	MsgTypeTransport     MsgType = 2
	MsgTypeClose         MsgType = 3
	MsgTypeHealthCheck   MsgType = 4

	headerSizeTransport = 1 + IDSize     // 1 byte for msg type, IDSize for peerID
	headerSizeHello     = 1 + 4 + IDSize // 1 byte for msg type, 4 byte for magic header, IDSize for peerID

	MaxHandshakeSize = 90
)

var (
	ErrInvalidMessageLength = fmt.Errorf("invalid message length")

	magicHeader = []byte{0x21, 0x12, 0xA4, 0x42}

	healthCheckMsg = []byte{byte(MsgTypeHealthCheck)}
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
	case MsgTypeClose:
		return "close"
	default:
		return "unknown"
	}
}

func DetermineClientMsgType(msg []byte) (MsgType, error) {
	msgType := MsgType(msg[0])
	switch msgType {
	case MsgTypeHello:
		return msgType, nil
	case MsgTypeTransport:
		return msgType, nil
	case MsgTypeClose:
		return msgType, nil
	case MsgTypeHealthCheck:
		return msgType, nil
	default:
		return 0, fmt.Errorf("invalid msg type, len: %d", len(msg))
	}
}

func DetermineServerMsgType(msg []byte) (MsgType, error) {
	msgType := MsgType(msg[0])
	switch msgType {
	case MsgTypeHelloResponse:
		return msgType, nil
	case MsgTypeTransport:
		return msgType, nil
	case MsgTypeClose:
		return msgType, nil
	case MsgTypeHealthCheck:
		return msgType, nil
	default:
		return 0, fmt.Errorf("invalid msg type (len: %d)", len(msg))
	}
}

// MarshalHelloMsg initial hello message
func MarshalHelloMsg(peerID []byte) ([]byte, error) {
	if len(peerID) != IDSize {
		return nil, fmt.Errorf("invalid peerID length: %d", len(peerID))
	}
	msg := make([]byte, 5, headerSizeHello)
	msg[0] = byte(MsgTypeHello)
	copy(msg[1:5], magicHeader)
	msg = append(msg, peerID...)
	return msg, nil
}

func UnmarshalHelloMsg(msg []byte) ([]byte, error) {
	if len(msg) < headerSizeHello {
		return nil, fmt.Errorf("invalid 'hello' messge")
	}
	bytes.Equal(msg[1:5], magicHeader)
	return msg[5:], nil
}

func MarshalHelloResponse() []byte {
	msg := make([]byte, 1)
	msg[0] = byte(MsgTypeHelloResponse)
	return msg
}

// Close message

func MarshalCloseMsg() []byte {
	msg := make([]byte, 1)
	msg[0] = byte(MsgTypeClose)
	return healthCheckMsg
}

// Transport message

func MarshalTransportMsg(peerID []byte, payload []byte) ([]byte, error) {
	if len(peerID) != IDSize {
		return nil, fmt.Errorf("invalid peerID length: %d", len(peerID))
	}

	msg := make([]byte, headerSizeTransport, headerSizeTransport+len(payload))
	msg[0] = byte(MsgTypeTransport)
	copy(msg[1:], peerID)
	msg = append(msg, payload...)
	return msg, nil
}

func UnmarshalTransportMsg(buf []byte) ([]byte, []byte, error) {
	if len(buf) < headerSizeTransport {
		return nil, nil, ErrInvalidMessageLength
	}

	return buf[1:headerSizeTransport], buf[headerSizeTransport:], nil
}

func UnmarshalTransportID(buf []byte) ([]byte, error) {
	if len(buf) < headerSizeTransport {
		log.Debugf("invalid message length: %d, expected: %d, %x", len(buf), headerSizeTransport, buf)
		return nil, ErrInvalidMessageLength
	}
	return buf[1:headerSizeTransport], nil
}

func UpdateTransportMsg(msg []byte, peerID []byte) error {
	if len(msg) < 1+len(peerID) {
		return ErrInvalidMessageLength
	}
	copy(msg[1:], peerID)
	return nil
}

// health check message

func MarshalHealthcheck() []byte {
	return healthCheckMsg
}
