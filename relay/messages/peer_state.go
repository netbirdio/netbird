package messages

import (
	"fmt"
)

func MarshalSubPeerStateMsg(ids []PeerID) ([][]byte, error) {
	return marshalPeerIDs(ids, byte(MsgTypeSubscribePeerState))
}

func UnmarshalSubPeerStateMsg(buf []byte) ([]PeerID, error) {
	return unmarshalPeerIDs(buf)
}

func MarshalUnsubPeerStateMsg(ids []PeerID) ([][]byte, error) {
	return marshalPeerIDs(ids, byte(MsgTypeUnsubscribePeerState))
}

func UnmarshalUnsubPeerStateMsg(buf []byte) ([]PeerID, error) {
	return unmarshalPeerIDs(buf)
}

func MarshalPeersOnline(ids []PeerID, chs []ChannelID) ([][]byte, error) {
	if len(ids) == 0 {
		return nil, fmt.Errorf("no list of peer ids provided")
	}

	const maxPeersPerMessage = (MaxMessageSize - sizeOfProtoHeader) / (peerIDSize + channelIDSize)
	var messages [][]byte

	for i := 0; i < len(ids); i += maxPeersPerMessage {
		end := i + maxPeersPerMessage
		if end > len(ids) {
			end = len(ids)
		}
		chunk := ids[i:end]
		channelChunk := chs[i:end]

		totalSize := sizeOfProtoHeader + len(chunk)*(peerIDSize+channelIDSize)
		buf := make([]byte, totalSize)
		buf[0] = byte(CurrentProtocolVersion)
		buf[1] = byte(MsgTypePeersOnline)

		offset := sizeOfProtoHeader
		for n, id := range chunk {
			copy(buf[offset:], id[:])
			offset += peerIDSize
			copy(buf[offset:], channelChunk[n][:])
			offset += channelIDSize
		}

		messages = append(messages, buf)
	}

	return messages, nil
}

func UnmarshalPeersOnlineMsg(buf []byte) ([]PeerID, []ChannelID, error) {
	if len(buf) < sizeOfProtoHeader {
		return nil, nil, fmt.Errorf("invalid message format")
	}

	if (len(buf)-sizeOfProtoHeader)%(peerIDSize+channelIDSize) != 0 {
		return nil, nil, fmt.Errorf("invalid peer list size: %d", len(buf)-sizeOfProtoHeader)
	}

	numIDs := (len(buf) - sizeOfProtoHeader) / (peerIDSize + channelIDSize)

	ids := make([]PeerID, numIDs)
	cids := make([]ChannelID, numIDs)
	offset := sizeOfProtoHeader
	for i := 0; i < numIDs; i++ {
		copy(ids[i][:], buf[offset:offset+peerIDSize])
		offset += peerIDSize
		copy(cids[i][:], buf[offset:offset+channelIDSize])
		offset += channelIDSize
	}

	return ids, cids, nil
}

func MarshalPeersWentOffline(ids []PeerID) ([][]byte, error) {
	return marshalPeerIDs(ids, byte(MsgTypePeersWentOffline))
}

func UnMarshalPeersWentOffline(buf []byte) ([]PeerID, error) {
	return unmarshalPeerIDs(buf)
}

// marshalPeerIDs is a generic function to marshal peer IDs with a specific message type
func marshalPeerIDs(ids []PeerID, msgType byte) ([][]byte, error) {
	if len(ids) == 0 {
		return nil, fmt.Errorf("no list of peer ids provided")
	}

	const maxPeersPerMessage = (MaxMessageSize - sizeOfProtoHeader) / peerIDSize
	var messages [][]byte

	for i := 0; i < len(ids); i += maxPeersPerMessage {
		end := i + maxPeersPerMessage
		if end > len(ids) {
			end = len(ids)
		}
		chunk := ids[i:end]

		totalSize := sizeOfProtoHeader + len(chunk)*peerIDSize
		buf := make([]byte, totalSize)
		buf[0] = byte(CurrentProtocolVersion)
		buf[1] = msgType

		offset := sizeOfProtoHeader
		for _, id := range chunk {
			copy(buf[offset:], id[:])
			offset += peerIDSize
		}

		messages = append(messages, buf)
	}

	return messages, nil
}

// unmarshalPeerIDs is a generic function to unmarshal peer IDs from a buffer
func unmarshalPeerIDs(buf []byte) ([]PeerID, error) {
	if len(buf) < sizeOfProtoHeader {
		return nil, fmt.Errorf("invalid message format")
	}

	if (len(buf)-sizeOfProtoHeader)%peerIDSize != 0 {
		return nil, fmt.Errorf("invalid peer list size: %d", len(buf)-sizeOfProtoHeader)
	}

	numIDs := (len(buf) - sizeOfProtoHeader) / peerIDSize

	ids := make([]PeerID, numIDs)
	offset := sizeOfProtoHeader
	for i := 0; i < numIDs; i++ {
		copy(ids[i][:], buf[offset:offset+peerIDSize])
		offset += peerIDSize
	}

	return ids, nil
}
