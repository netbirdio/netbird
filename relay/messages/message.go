package messages

import (
	"bytes"
	"encoding/gob"
	"errors"
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
	sizeOfMagicByte     = 4
	headerSizeTransport = sizeOfMsgType + IDSize                   // 1 byte for msg type, IDSize for peerID
	headerSizeHello     = sizeOfMsgType + sizeOfMagicByte + IDSize // 1 byte for msg type, 4 byte for magic header, IDSize for peerID

	MaxHandshakeSize = 8192
)

var (
	ErrInvalidMessageLength = errors.New("invalid message length")

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

// DetermineClientMsgType determines the message type from the first byte of the message
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

// DetermineServerMsgType determines the message type from the first byte of the message
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
// The Hello message is the first message sent by a client after establishing a connection with the Relay server. This
// message is used to authenticate the client with the server. The authentication is done using an HMAC method.
// The protocol does not limit to use HMAC, it can be any other method. If the authentication failed the server will
// close the network connection without any response.
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

// UnmarshalHelloMsg extracts the peerID and the additional data from the hello message. The Additional data is used to
// authenticate the client with the server.
func UnmarshalHelloMsg(msg []byte) ([]byte, []byte, error) {
	if len(msg) < headerSizeHello {
		return nil, nil, fmt.Errorf("invalid 'hello' message")
	}
	if !bytes.Equal(msg[1:5], magicHeader) {
		return nil, nil, fmt.Errorf("invalid magic header")
	}
	return msg[5 : 5+IDSize], msg[headerSizeHello:], nil
}

// MarshalHelloResponse creates a response message to the hello message.
// In case of success connection the server response with a Hello Response message. This message contains the server's
// instance URL. This URL will be used by choose the common Relay server in case if the peers are in different Relay
// servers.
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

// UnmarshalHelloResponse extracts the instance address from the hello response message
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

// MarshalCloseMsg creates a close message.
// The close message is used to close the connection gracefully between the client and the server. The server and the
// client can send this message. After receiving this message, the server or client will close the connection.
func MarshalCloseMsg() []byte {
	msg := make([]byte, 1)
	msg[0] = byte(MsgTypeClose)
	return msg
}

// MarshalTransportMsg creates a transport message.
// The transport message is used to exchange data between peers. The message contains the data to be exchanged and the
// destination peer hashed ID.
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

// UnmarshalTransportMsg extracts the peerID and the payload from the transport message.
func UnmarshalTransportMsg(buf []byte) ([]byte, []byte, error) {
	if len(buf) < headerSizeTransport {
		return nil, nil, ErrInvalidMessageLength
	}

	return buf[1:headerSizeTransport], buf[headerSizeTransport:], nil
}

// UnmarshalTransportID extracts the peerID from the transport message.
func UnmarshalTransportID(buf []byte) ([]byte, error) {
	if len(buf) < headerSizeTransport {
		log.Debugf("invalid message length: %d, expected: %d, %x", len(buf), headerSizeTransport, buf)
		return nil, ErrInvalidMessageLength
	}
	return buf[1:headerSizeTransport], nil
}

// UpdateTransportMsg updates the peerID in the transport message.
// With this function the server can reuse the given byte slice to update the peerID in the transport message. So do
// need to allocate a new byte slice.
func UpdateTransportMsg(msg []byte, peerID []byte) error {
	if len(msg) < 1+len(peerID) {
		return ErrInvalidMessageLength
	}
	copy(msg[1:], peerID)
	return nil
}

// MarshalHealthcheck creates a health check message.
// Health check message is sent by the server periodically. The client will respond with a health check response
// message. If the client does not respond to the health check message, the server will close the connection.
func MarshalHealthcheck() []byte {
	return healthCheckMsg
}
