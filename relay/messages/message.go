package messages

import (
	"bytes"
	"errors"
	"fmt"
)

const (
	MaxHandshakeSize     = 212
	MaxHandshakeRespSize = 8192

	CurrentProtocolVersion = 1

	MsgTypeUnknown MsgType = 0
	// Deprecated: Use MsgTypeAuth instead.
	MsgTypeHello MsgType = 1
	// Deprecated: Use MsgTypeAuthResponse instead.
	MsgTypeHelloResponse MsgType = 2
	MsgTypeTransport     MsgType = 3
	MsgTypeClose         MsgType = 4
	MsgTypeHealthCheck   MsgType = 5
	MsgTypeAuth                  = 6
	MsgTypeAuthResponse          = 7

	// base size of the message
	sizeOfVersionByte = 1
	sizeOfMsgType     = 1
	sizeOfProtoHeader = sizeOfVersionByte + sizeOfMsgType

	// auth message
	sizeOfMagicByte     = 4
	headerSizeAuth      = sizeOfMagicByte + IDSize
	offsetMagicByte     = sizeOfProtoHeader
	offsetAuthPeerID    = sizeOfProtoHeader + sizeOfMagicByte
	headerTotalSizeAuth = sizeOfProtoHeader + headerSizeAuth

	// hello message
	headerSizeHello     = sizeOfMagicByte + IDSize
	headerSizeHelloResp = 0

	// transport
	headerSizeTransport      = IDSize
	offsetTransportID        = sizeOfProtoHeader
	headerTotalSizeTransport = sizeOfProtoHeader + headerSizeTransport
)

var (
	ErrInvalidMessageLength = errors.New("invalid message length")
	ErrUnsupportedVersion   = errors.New("unsupported version")

	magicHeader = []byte{0x21, 0x12, 0xA4, 0x42}

	healthCheckMsg = []byte{byte(CurrentProtocolVersion), byte(MsgTypeHealthCheck)}
)

type MsgType byte

func (m MsgType) String() string {
	switch m {
	case MsgTypeHello:
		return "hello"
	case MsgTypeHelloResponse:
		return "hello response"
	case MsgTypeAuth:
		return "auth"
	case MsgTypeAuthResponse:
		return "auth response"
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

// ValidateVersion checks if the given version is supported by the protocol
func ValidateVersion(msg []byte) (int, error) {
	if len(msg) < sizeOfProtoHeader {
		return 0, ErrInvalidMessageLength
	}
	version := int(msg[0])
	if version != CurrentProtocolVersion {
		return 0, fmt.Errorf("%d: %w", version, ErrUnsupportedVersion)
	}
	return version, nil
}

// DetermineClientMessageType determines the message type from the first the message
func DetermineClientMessageType(msg []byte) (MsgType, error) {
	if len(msg) < sizeOfProtoHeader {
		return 0, ErrInvalidMessageLength
	}

	msgType := MsgType(msg[1])
	switch msgType {
	case
		MsgTypeHello,
		MsgTypeAuth,
		MsgTypeTransport,
		MsgTypeClose,
		MsgTypeHealthCheck:
		return msgType, nil
	default:
		return MsgTypeUnknown, fmt.Errorf("invalid msg type %d", msgType)
	}
}

// DetermineServerMessageType determines the message type from the first the message
func DetermineServerMessageType(msg []byte) (MsgType, error) {
	if len(msg) < sizeOfProtoHeader {
		return 0, ErrInvalidMessageLength
	}

	msgType := MsgType(msg[1])
	switch msgType {
	case
		MsgTypeHelloResponse,
		MsgTypeAuthResponse,
		MsgTypeTransport,
		MsgTypeClose,
		MsgTypeHealthCheck:
		return msgType, nil
	default:
		return MsgTypeUnknown, fmt.Errorf("invalid msg type %d", msgType)
	}
}

// Deprecated: Use MarshalAuthMsg instead.
// MarshalHelloMsg initial hello message
// The Hello message is the first message sent by a client after establishing a connection with the Relay server. This
// message is used to authenticate the client with the server. The authentication is done using an HMAC method.
// The protocol does not limit to use HMAC, it can be any other method. If the authentication failed the server will
// close the network connection without any response.
func MarshalHelloMsg(peerID []byte, additions []byte) ([]byte, error) {
	if len(peerID) != IDSize {
		return nil, fmt.Errorf("invalid peerID length: %d", len(peerID))
	}

	msg := make([]byte, sizeOfProtoHeader+sizeOfMagicByte, sizeOfProtoHeader+headerSizeHello+len(additions))

	msg[0] = byte(CurrentProtocolVersion)
	msg[1] = byte(MsgTypeHello)

	copy(msg[sizeOfProtoHeader:sizeOfProtoHeader+sizeOfMagicByte], magicHeader)

	msg = append(msg, peerID...)
	msg = append(msg, additions...)

	return msg, nil
}

// Deprecated: Use UnmarshalAuthMsg instead.
// UnmarshalHelloMsg extracts peerID and the additional data from the hello message. The Additional data is used to
// authenticate the client with the server.
func UnmarshalHelloMsg(msg []byte) ([]byte, []byte, error) {
	if len(msg) < sizeOfProtoHeader+headerSizeHello {
		return nil, nil, ErrInvalidMessageLength
	}
	if !bytes.Equal(msg[sizeOfProtoHeader:sizeOfProtoHeader+sizeOfMagicByte], magicHeader) {
		return nil, nil, errors.New("invalid magic header")
	}

	return msg[sizeOfProtoHeader+sizeOfMagicByte : sizeOfProtoHeader+headerSizeHello], msg[headerSizeHello:], nil
}

// Deprecated: Use MarshalAuthResponse instead.
// MarshalHelloResponse creates a response message to the hello message.
// In case of success connection the server response with a Hello Response message. This message contains the server's
// instance URL. This URL will be used by choose the common Relay server in case if the peers are in different Relay
// servers.
func MarshalHelloResponse(additionalData []byte) ([]byte, error) {
	msg := make([]byte, sizeOfProtoHeader, sizeOfProtoHeader+headerSizeHelloResp+len(additionalData))

	msg[0] = byte(CurrentProtocolVersion)
	msg[1] = byte(MsgTypeHelloResponse)

	msg = append(msg, additionalData...)

	return msg, nil
}

// Deprecated: Use UnmarshalAuthResponse instead.
// UnmarshalHelloResponse extracts the additional data from the hello response message.
func UnmarshalHelloResponse(msg []byte) ([]byte, error) {
	if len(msg) < sizeOfProtoHeader+headerSizeHelloResp {
		return nil, ErrInvalidMessageLength
	}
	return msg, nil
}

// MarshalAuthMsg initial authentication message
// The Auth message is the first message sent by a client after establishing a connection with the Relay server. This
// message is used to authenticate the client with the server. The authentication is done using an HMAC method.
// The protocol does not limit to use HMAC, it can be any other method. If the authentication failed the server will
// close the network connection without any response.
func MarshalAuthMsg(peerID []byte, authPayload []byte) ([]byte, error) {
	if len(peerID) != IDSize {
		return nil, fmt.Errorf("invalid peerID length: %d", len(peerID))
	}

	msg := make([]byte, sizeOfProtoHeader+sizeOfMagicByte, headerTotalSizeAuth+len(authPayload))

	msg[0] = byte(CurrentProtocolVersion)
	msg[1] = byte(MsgTypeAuth)

	copy(msg[sizeOfProtoHeader:], magicHeader)

	msg = append(msg, peerID...)
	msg = append(msg, authPayload...)

	return msg, nil
}

// UnmarshalAuthMsg extracts peerID and the auth payload from the message
func UnmarshalAuthMsg(msg []byte) ([]byte, []byte, error) {
	if len(msg) < headerTotalSizeAuth {
		return nil, nil, ErrInvalidMessageLength
	}
	if !bytes.Equal(msg[offsetMagicByte:offsetMagicByte+sizeOfMagicByte], magicHeader) {
		return nil, nil, errors.New("invalid magic header")
	}

	return msg[offsetAuthPeerID:headerTotalSizeAuth], msg[headerTotalSizeAuth:], nil
}

// MarshalAuthResponse creates a response message to the auth.
// In case of success connection the server response with a AuthResponse message. This message contains the server's
// instance URL. This URL will be used by choose the common Relay server in case if the peers are in different Relay
// servers.
func MarshalAuthResponse(address string) ([]byte, error) {
	ab := []byte(address)
	msg := make([]byte, sizeOfProtoHeader, sizeOfProtoHeader+len(ab))

	msg[0] = byte(CurrentProtocolVersion)
	msg[1] = byte(MsgTypeAuthResponse)

	msg = append(msg, ab...)

	if len(msg) > MaxHandshakeRespSize {
		return nil, fmt.Errorf("invalid message length: %d", len(msg))
	}

	return msg, nil
}

// UnmarshalAuthResponse it is a confirmation message to auth success
func UnmarshalAuthResponse(msg []byte) (string, error) {
	if len(msg) < sizeOfProtoHeader+1 {
		return "", ErrInvalidMessageLength
	}
	return string(msg[sizeOfProtoHeader:]), nil
}

// MarshalCloseMsg creates a close message.
// The close message is used to close the connection gracefully between the client and the server. The server and the
// client can send this message. After receiving this message, the server or client will close the connection.
func MarshalCloseMsg() []byte {
	return []byte{
		byte(CurrentProtocolVersion),
		byte(MsgTypeClose),
	}
}

// MarshalTransportMsg creates a transport message.
// The transport message is used to exchange data between peers. The message contains the data to be exchanged and the
// destination peer hashed ID.
func MarshalTransportMsg(peerID, payload []byte) ([]byte, error) {
	if len(peerID) != IDSize {
		return nil, fmt.Errorf("invalid peerID length: %d", len(peerID))
	}

	msg := make([]byte, headerTotalSizeTransport, headerTotalSizeTransport+len(payload))
	msg[0] = byte(CurrentProtocolVersion)
	msg[1] = byte(MsgTypeTransport)
	copy(msg[sizeOfProtoHeader:], peerID)
	msg = append(msg, payload...)

	return msg, nil
}

// UnmarshalTransportMsg extracts the peerID and the payload from the transport message.
func UnmarshalTransportMsg(buf []byte) ([]byte, []byte, error) {
	if len(buf) < headerTotalSizeTransport {
		return nil, nil, ErrInvalidMessageLength
	}

	return buf[offsetTransportID:headerTotalSizeTransport], buf[headerTotalSizeTransport:], nil
}

// UnmarshalTransportID extracts the peerID from the transport message.
func UnmarshalTransportID(buf []byte) ([]byte, error) {
	if len(buf) < headerTotalSizeTransport {
		return nil, ErrInvalidMessageLength
	}
	return buf[offsetTransportID:headerTotalSizeTransport], nil
}

// UpdateTransportMsg updates the peerID in the transport message.
// With this function the server can reuse the given byte slice to update the peerID in the transport message. So do
// need to allocate a new byte slice.
func UpdateTransportMsg(msg []byte, peerID []byte) error {
	if len(msg) < offsetTransportID+len(peerID) {
		return ErrInvalidMessageLength
	}
	copy(msg[offsetTransportID:], peerID)
	return nil
}

// MarshalHealthcheck creates a health check message.
// Health check message is sent by the server periodically. The client will respond with a health check response
// message. If the client does not respond to the health check message, the server will close the connection.
func MarshalHealthcheck() []byte {
	return healthCheckMsg
}
