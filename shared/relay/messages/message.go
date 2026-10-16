package messages

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
)

const (
	MaxHandshakeSize     = 8192
	MaxHandshakeRespSize = 8192
	MaxMessageSize       = 8820

	ProtocolV1 ProtocolVersion = 1
	// CurrentProtocolVersion is the highest protocol version this build supports.
	CurrentProtocolVersion = ProtocolV1

	// authEnvelopeMinVersion is the first advertised version whose Auth message carries a
	// length-prefixed token followed by an extension area.
	authEnvelopeMinVersion ProtocolVersion = 2

	MsgTypeUnknown MsgType = 0
	// MsgTypeHello and MsgTypeHelloResponse are the removed legacy handshake
	// message types. They are retained only to reserve wire values 1 and 2 so
	// the values are never reused; the server rejects both.
	MsgTypeHello         = 1
	MsgTypeHelloResponse = 2
	MsgTypeTransport     = 3
	MsgTypeClose         = 4
	MsgTypeHealthCheck   = 5
	MsgTypeAuth          = 6
	MsgTypeAuthResponse  = 7

	// Peers state messages
	MsgTypeSubscribePeerState   = 8
	MsgTypeUnsubscribePeerState = 9
	MsgTypePeersOnline          = 10
	MsgTypePeersWentOffline     = 11

	// base size of the message
	sizeOfVersionByte = 1
	sizeOfMsgType     = 1
	sizeOfProtoHeader = sizeOfVersionByte + sizeOfMsgType

	// auth message
	sizeOfMagicByte     = 4
	sizeOfTokenLen      = 2
	headerSizeAuth      = sizeOfMagicByte + peerIDSize
	offsetMagicByte     = sizeOfProtoHeader
	offsetAuthPeerID    = sizeOfProtoHeader + sizeOfMagicByte
	headerTotalSizeAuth = sizeOfProtoHeader + headerSizeAuth
	offsetAuthTokenLen  = headerTotalSizeAuth
	offsetAuthToken     = offsetAuthTokenLen + sizeOfTokenLen

	// transport
	headerSizeTransport      = peerIDSize
	offsetTransportID        = sizeOfProtoHeader
	headerTotalSizeTransport = sizeOfProtoHeader + headerSizeTransport
)

var (
	ErrInvalidMessageLength = errors.New("invalid message length")
	ErrUnsupportedVersion   = errors.New("unsupported version")
	ErrInvalidTokenLength   = errors.New("invalid token length")
	ErrReservedMsgType      = errors.New("reserved message type")
	ErrMsgTypeDirection     = errors.New("message type not valid from client")
	ErrUnknownMsgType       = errors.New("unknown message type")

	magicHeader = []byte{0x21, 0x12, 0xA4, 0x42}

	healthCheckMsg = []byte{byte(CurrentProtocolVersion), byte(MsgTypeHealthCheck)}
)

type MsgType byte

// ProtocolVersion is the relay wire protocol version carried in the first byte of every frame.
type ProtocolVersion uint8

// Encoder marshals server-originated messages with the protocol version selected for one connection.
type Encoder struct {
	version ProtocolVersion
}

// NewEncoder returns an Encoder that stamps every message with the given protocol version.
func NewEncoder(version ProtocolVersion) Encoder {
	return Encoder{version: version}
}

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
	case MsgTypeSubscribePeerState:
		return "subscribe peer state"
	case MsgTypeUnsubscribePeerState:
		return "unsubscribe peer state"
	case MsgTypePeersOnline:
		return "peers online"
	case MsgTypePeersWentOffline:
		return "peers went offline"
	default:
		return "unknown"
	}
}

// Version returns the protocol version the Encoder stamps on its messages.
func (e Encoder) Version() ProtocolVersion {
	return e.version
}

// AuthResponse creates the response to a successful Auth message. The payload is the instance URL
// of the server, which the clients use to choose a common Relay server.
func (e Encoder) AuthResponse(address string) ([]byte, error) {
	ab := []byte(address)
	msg := make([]byte, sizeOfProtoHeader, sizeOfProtoHeader+len(ab))

	msg[0] = byte(e.version)
	msg[1] = byte(MsgTypeAuthResponse)

	msg = append(msg, ab...)

	if len(msg) > MaxHandshakeRespSize {
		return nil, fmt.Errorf("invalid message length: %d", len(msg))
	}

	return msg, nil
}

// CloseMsg creates a close message for a graceful disconnect.
func (e Encoder) CloseMsg() []byte {
	return []byte{
		byte(e.version),
		byte(MsgTypeClose),
	}
}

// Healthcheck creates a health check message.
func (e Encoder) Healthcheck() []byte {
	return []byte{
		byte(e.version),
		byte(MsgTypeHealthCheck),
	}
}

// PeersOnline creates the peers online notification messages.
func (e Encoder) PeersOnline(ids []PeerID) ([][]byte, error) {
	return marshalPeerIDs(e.version, ids, byte(MsgTypePeersOnline))
}

// PeersWentOffline creates the peers went offline notification messages.
func (e Encoder) PeersWentOffline(ids []PeerID) ([][]byte, error) {
	return marshalPeerIDs(e.version, ids, byte(MsgTypePeersWentOffline))
}

// ReadVersion returns the protocol version carried in the frame header. Zero is invalid.
func ReadVersion(msg []byte) (ProtocolVersion, error) {
	if len(msg) < sizeOfProtoHeader {
		return 0, ErrInvalidMessageLength
	}
	version := ProtocolVersion(msg[0])
	if version == 0 {
		return 0, fmt.Errorf("%d: %w", version, ErrUnsupportedVersion)
	}
	return version, nil
}

// SelectVersion returns the highest protocol version both sides support.
func SelectVersion(advertised, supported ProtocolVersion) ProtocolVersion {
	if advertised < supported {
		return advertised
	}
	return supported
}

// ValidateVersion checks that the frame carries the protocol version of this build.
func ValidateVersion(msg []byte) (int, error) {
	version, err := ReadVersion(msg)
	if err != nil {
		return 0, err
	}
	if version != CurrentProtocolVersion {
		return 0, fmt.Errorf("%d: %w", version, ErrUnsupportedVersion)
	}
	return int(version), nil
}

// ValidateConnectionVersion checks that the frame carries the version selected for the connection.
func ValidateConnectionVersion(msg []byte, selected ProtocolVersion) error {
	version, err := ReadVersion(msg)
	if err != nil {
		return err
	}
	if version != selected {
		return fmt.Errorf("%d instead of selected %d: %w", version, selected, ErrUnsupportedVersion)
	}
	return nil
}

// DetermineClientMessageType determines the message type from the first the message
func DetermineClientMessageType(msg []byte) (MsgType, error) {
	if len(msg) < sizeOfProtoHeader {
		return 0, ErrInvalidMessageLength
	}

	msgType := MsgType(msg[1])
	switch msgType {
	case
		MsgTypeAuth,
		MsgTypeTransport,
		MsgTypeClose,
		MsgTypeHealthCheck,
		MsgTypeSubscribePeerState,
		MsgTypeUnsubscribePeerState:
		return msgType, nil
	case MsgTypeHello, MsgTypeHelloResponse:
		return MsgTypeUnknown, fmt.Errorf("%d: %w", msgType, ErrReservedMsgType)
	case MsgTypeAuthResponse, MsgTypePeersOnline, MsgTypePeersWentOffline:
		return MsgTypeUnknown, fmt.Errorf("%d: %w", msgType, ErrMsgTypeDirection)
	default:
		return MsgTypeUnknown, fmt.Errorf("%d: %w", msgType, ErrUnknownMsgType)
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
		MsgTypeAuthResponse,
		MsgTypeTransport,
		MsgTypeClose,
		MsgTypeHealthCheck,
		MsgTypePeersOnline,
		MsgTypePeersWentOffline:
		return msgType, nil
	default:
		return MsgTypeUnknown, fmt.Errorf("invalid msg type %d", msgType)
	}
}

// MarshalAuthMsg initial authentication message
// The Auth message is the first message sent by a client after establishing a connection with the Relay server. This
// message is used to authenticate the client with the server. The authentication is done using an HMAC method.
// The protocol does not limit to use HMAC, it can be any other method. If the authentication failed the server will
// close the network connection without any response.
func MarshalAuthMsg(peerID PeerID, authPayload []byte) ([]byte, error) {
	if headerTotalSizeAuth+len(authPayload) > MaxHandshakeSize {
		return nil, fmt.Errorf("too large auth payload")
	}

	msg := make([]byte, headerTotalSizeAuth+len(authPayload))
	msg[0] = byte(CurrentProtocolVersion)
	msg[1] = byte(MsgTypeAuth)
	copy(msg[sizeOfProtoHeader:], magicHeader)
	copy(msg[offsetAuthPeerID:], peerID[:])
	copy(msg[headerTotalSizeAuth:], authPayload)
	return msg, nil
}

// MarshalAuthEnvelope creates the Auth message layout used by clients advertising protocol
// version 2 or higher: the token is length-prefixed and followed by an extension area that
// servers without support for it ignore.
func MarshalAuthEnvelope(version ProtocolVersion, peerID PeerID, token, ext []byte) ([]byte, error) {
	if version < authEnvelopeMinVersion {
		return nil, fmt.Errorf("protocol version %d does not use the auth envelope", version)
	}
	if len(token) == 0 || len(token) > math.MaxUint16 {
		return nil, fmt.Errorf("%d: %w", len(token), ErrInvalidTokenLength)
	}

	size := offsetAuthToken + len(token) + len(ext)
	if size > MaxHandshakeSize {
		return nil, fmt.Errorf("too large auth message: %d", size)
	}

	msg := make([]byte, size)
	msg[0] = byte(version)
	msg[1] = byte(MsgTypeAuth)
	copy(msg[offsetMagicByte:], magicHeader)
	copy(msg[offsetAuthPeerID:], peerID[:])
	binary.BigEndian.PutUint16(msg[offsetAuthTokenLen:], uint16(len(token)))
	copy(msg[offsetAuthToken:], token)
	copy(msg[offsetAuthToken+len(token):], ext)
	return msg, nil
}

// UnmarshalAuthMsg extracts the peer ID and the auth token from an Auth message of any
// protocol version. The extension area of the envelope layout is not returned.
func UnmarshalAuthMsg(msg []byte) (*PeerID, []byte, error) {
	version, err := ReadVersion(msg)
	if err != nil {
		return nil, nil, err
	}

	if len(msg) < headerTotalSizeAuth {
		return nil, nil, ErrInvalidMessageLength
	}

	// Validate the magic header
	if !bytes.Equal(msg[offsetMagicByte:offsetMagicByte+sizeOfMagicByte], magicHeader) {
		return nil, nil, errors.New("invalid magic header")
	}

	peerID := PeerID(msg[offsetAuthPeerID:headerTotalSizeAuth])
	if version < authEnvelopeMinVersion {
		return &peerID, msg[headerTotalSizeAuth:], nil
	}

	token, err := unmarshalAuthEnvelopeToken(msg)
	if err != nil {
		return nil, nil, err
	}
	return &peerID, token, nil
}

// MarshalAuthResponse creates a response message to the auth.
// In case of success connection the server response with a AuthResponse message. This message contains the server's
// instance URL. This URL will be used by choose the common Relay server in case if the peers are in different Relay
// servers.
func MarshalAuthResponse(address string) ([]byte, error) {
	return NewEncoder(CurrentProtocolVersion).AuthResponse(address)
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
	return NewEncoder(CurrentProtocolVersion).CloseMsg()
}

// MarshalTransportMsg creates a transport message.
// The transport message is used to exchange data between peers. The message contains the data to be exchanged and the
// destination peer hashed ID.
func MarshalTransportMsg(peerID PeerID, payload []byte) ([]byte, error) {
	// todo validate size
	msg := make([]byte, headerTotalSizeTransport+len(payload))
	msg[0] = byte(CurrentProtocolVersion)
	msg[1] = byte(MsgTypeTransport)
	copy(msg[sizeOfProtoHeader:], peerID[:])
	copy(msg[sizeOfProtoHeader+peerIDSize:], payload)
	return msg, nil
}

// UnmarshalTransportMsg extracts the peerID and the payload from the transport message.
func UnmarshalTransportMsg(buf []byte) (*PeerID, []byte, error) {
	if len(buf) < headerTotalSizeTransport {
		return nil, nil, ErrInvalidMessageLength
	}

	const offsetEnd = offsetTransportID + peerIDSize
	var peerID PeerID
	copy(peerID[:], buf[offsetTransportID:offsetEnd])
	return &peerID, buf[headerTotalSizeTransport:], nil
}

// UnmarshalTransportID extracts the peerID from the transport message.
func UnmarshalTransportID(buf []byte) (*PeerID, error) {
	if len(buf) < headerTotalSizeTransport {
		return nil, ErrInvalidMessageLength
	}

	const offsetEnd = offsetTransportID + peerIDSize
	var id PeerID
	copy(id[:], buf[offsetTransportID:offsetEnd])
	return &id, nil
}

// UpdateTransportMsg rewrites the transport message in place for forwarding: the header carries
// the protocol version of the destination connection and the peer ID field the sender's ID.
// The payload bytes are left untouched, so no new byte slice is allocated.
func UpdateTransportMsg(msg []byte, version ProtocolVersion, peerID PeerID) error {
	if len(msg) < offsetTransportID+peerIDSize {
		return ErrInvalidMessageLength
	}
	msg[0] = byte(version)
	copy(msg[offsetTransportID:], peerID[:])
	return nil
}

// MarshalHealthcheck creates a health check message.
// Health check message is sent by the server periodically. The client will respond with a health check response
// message. If the client does not respond to the health check message, the server will close the connection.
func MarshalHealthcheck() []byte {
	return healthCheckMsg
}

func unmarshalAuthEnvelopeToken(msg []byte) ([]byte, error) {
	if len(msg) < offsetAuthToken {
		return nil, ErrInvalidMessageLength
	}

	tokenLen := int(binary.BigEndian.Uint16(msg[offsetAuthTokenLen:offsetAuthToken]))
	if tokenLen == 0 {
		return nil, fmt.Errorf("%d: %w", tokenLen, ErrInvalidTokenLength)
	}

	end := offsetAuthToken + tokenLen
	if end > len(msg) {
		return nil, fmt.Errorf("%d exceeds the message: %w", tokenLen, ErrInvalidTokenLength)
	}
	return msg[offsetAuthToken:end], nil
}
