package messages

import (
	"errors"
)

const (
	channelIDSize                = 2
	headerSizeEbpfTransport      = channelIDSize
	headerTotalSizeEbpfTransport = sizeOfProtoHeader + headerSizeEbpfTransport
)

type ChannelID [2]byte

func MarshalEbpfTransportMsg(channelID ChannelID, payload []byte) ([]byte, error) {
	totalSize := headerTotalSizeEbpfTransport + len(payload)
	if totalSize > MaxMessageSize {
		return nil, errors.New("message too large")
	}

	msg := make([]byte, totalSize)
	msg[0] = byte(CurrentProtocolVersion)
	msg[1] = byte(MsgTypeEbpfTransport)

	copy(msg[sizeOfProtoHeader:], channelID[:])
	copy(msg[sizeOfProtoHeader+channelIDSize:], payload)

	return msg, nil
}

func UnmarshalEbpfTransportMsg(msg []byte) (ChannelID, []byte, error) {
	if len(msg) < headerTotalSizeEbpfTransport {
		return ChannelID{}, nil, errors.New("message too short")
	}

	var channelID ChannelID
	copy(channelID[:], msg[sizeOfProtoHeader:sizeOfProtoHeader+channelIDSize])
	payload := msg[sizeOfProtoHeader+channelIDSize:]

	return channelID, payload, nil
}
