package messages

import (
	"bytes"
	"encoding/gob"
	"fmt"

	log "github.com/sirupsen/logrus"
)

const (
	MsgTypeHello         MsgType = 0
	MsgTypeHelloResponse MsgType = 1
	MsgTypeTransport     MsgType = 2
	MsgTypeClose         MsgType = 3
	MsgTypeHealthCheck   MsgType = 4

	sizeOfMsgType       = 1
	sizeOfMagicBye      = 4
	headerSizeTransport = sizeOfMsgType + IDSize                  // 1 byte for msg type, IDSize for peerID
	headerSizeHello     = sizeOfMsgType + sizeOfMagicBye + IDSize // 1 byte for msg type, 4 byte for magic header, IDSize for peerID

	MaxHandshakeSize = 8192
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
	case MsgTypeHealthCheck:
		return "health check"
	default:
		return "unknown"
	}
}

type HelloResponse struct {
	InstanceAddress string
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
func MarshalHelloMsg(peerID []byte, additions []byte) ([]byte, error) {
	if len(peerID) != IDSize {
		return nil, fmt.Errorf("invalid peerID length: %d", len(peerID))
	}

	// 5 = 1 byte for msg type, 4 byte for magic header
	msg := make([]byte, 5, headerSizeHello+len(additions))
	msg[0] = byte(MsgTypeHello)
	copy(msg[1:5], magicHeader)
	msg = append(msg, peerID...)
	msg = append(msg, additions...)
	return msg, nil
}

func UnmarshalHelloMsg(msg []byte) ([]byte, []byte, error) {
	if len(msg) < headerSizeHello {
		return nil, nil, fmt.Errorf("invalid 'hello' messge")
	}
	if !bytes.Equal(msg[1:5], magicHeader) {
		return nil, nil, fmt.Errorf("invalid magic header")
	}
	return msg[5 : 5+IDSize], msg[headerSizeHello:], nil
}

func MarshalHelloResponse(DomainAddress string) ([]byte, error) {
	payload := HelloResponse{
		InstanceAddress: DomainAddress,
	}

	buf := new(bytes.Buffer)
	enc := gob.NewEncoder(buf)

	err := enc.Encode(payload)
	if err != nil {
		log.Errorf("failed to gob encode hello response: %s", err)
		return nil, err
	}

	msg := make([]byte, 1, 1+buf.Len())
	msg[0] = byte(MsgTypeHelloResponse)
	msg = append(msg, buf.Bytes()...)
	return msg, nil
}

func UnmarshalHelloResponse(msg []byte) (string, error) {
	if len(msg) < 2 {
		return "", fmt.Errorf("invalid 'hello response' message")
	}
	payload := HelloResponse{}
	buf := bytes.NewBuffer(msg[1:])
	dec := gob.NewDecoder(buf)

	err := dec.Decode(&payload)
	if err != nil {
		log.Errorf("failed to gob decode hello response: %s", err)
		return "", err
	}
	return payload.InstanceAddress, nil
}

// Close message

func MarshalCloseMsg() []byte {
	msg := make([]byte, 1)
	msg[0] = byte(MsgTypeClose)
	return msg
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
