package messages

import (
	"fmt"
)

const (
	MsgTypeHello          MsgType = 0
	MsgTypeBindNewChannel MsgType = 1
	MsgTypeBindResponse   MsgType = 2
	MsgTypeTransport      MsgType = 3
)

var (
	ErrInvalidMessageLength = fmt.Errorf("invalid message length")
)

type MsgType byte

func DetermineClientMsgType(msg []byte) (MsgType, error) {
	// todo: validate magic byte
	msgType := MsgType(msg[0])
	switch msgType {
	case MsgTypeHello:
		return msgType, nil
	case MsgTypeBindNewChannel:
		return msgType, nil
	case MsgTypeTransport:
		return msgType, nil
	default:
		return 0, fmt.Errorf("invalid msg type: %s", msg)
	}
}

func DetermineServerMsgType(msg []byte) (MsgType, error) {
	// todo: validate magic byte
	msgType := MsgType(msg[0])
	switch msgType {
	case MsgTypeBindResponse:
		return msgType, nil
	case MsgTypeTransport:
		return msgType, nil
	default:
		return 0, fmt.Errorf("invalid msg type: %s", msg)
	}
}

// MarshalHelloMsg initial hello message
func MarshalHelloMsg(peerID string) ([]byte, error) {
	if len(peerID) == 0 {
		return nil, fmt.Errorf("invalid peer id")
	}
	msg := make([]byte, 1, 1+len(peerID))
	msg[0] = byte(MsgTypeHello)
	msg = append(msg, []byte(peerID)...)
	return msg, nil
}

func UnmarshalHelloMsg(msg []byte) (string, error) {
	if len(msg) < 2 {
		return "", fmt.Errorf("invalid 'hello' messge")
	}
	return string(msg[1:]), nil
}

// Bind new channel

func MarshalBindNewChannelMsg(destinationPeerId string) []byte {
	msg := make([]byte, 1, 1+len(destinationPeerId))
	msg[0] = byte(MsgTypeBindNewChannel)
	msg = append(msg, []byte(destinationPeerId)...)
	return msg
}

func UnmarshalBindNewChannel(msg []byte) (string, error) {
	if len(msg) < 2 {
		return "", fmt.Errorf("invalid 'bind new channel' messge")
	}
	return string(msg[1:]), nil
}

// Bind response

func MarshalBindResponseMsg(channelId uint16, id string) []byte {
	data := []byte(id)
	msg := make([]byte, 3, 3+len(data))
	msg[0] = byte(MsgTypeBindResponse)
	msg[1], msg[2] = uint8(channelId>>8), uint8(channelId&0xff)
	msg = append(msg, data...)
	return msg
}

func UnmarshalBindResponseMsg(buf []byte) (uint16, string, error) {
	if len(buf) < 3 {
		return 0, "", ErrInvalidMessageLength
	}
	channelId := uint16(buf[1])<<8 | uint16(buf[2])
	peerID := string(buf[3:])
	return channelId, peerID, nil
}

// Transport message

func MarshalTransportMsg(channelId uint16, payload []byte) []byte {
	msg := make([]byte, 3, 3+len(payload))
	msg[0] = byte(MsgTypeTransport)
	msg[1], msg[2] = uint8(channelId>>8), uint8(channelId&0xff)
	msg = append(msg, payload...)
	return msg
}

func UnmarshalTransportMsg(buf []byte) (uint16, []byte, error) {
	if len(buf) < 3 {
		return 0, nil, ErrInvalidMessageLength
	}
	channelId := uint16(buf[1])<<8 | uint16(buf[2])
	return channelId, buf[3:], nil
}

func UnmarshalTransportID(buf []byte) (uint16, error) {
	if len(buf) < 3 {
		return 0, ErrInvalidMessageLength
	}
	channelId := uint16(buf[1])<<8 | uint16(buf[2])
	return channelId, nil
}

func UpdateTransportMsg(msg []byte, channelId uint16) error {
	if len(msg) < 3 {
		return ErrInvalidMessageLength
	}
	msg[1], msg[2] = uint8(channelId>>8), uint8(channelId&0xff)
	return nil
}
