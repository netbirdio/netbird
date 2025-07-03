package messages

import "errors"

func MarshalSubPeerStateMsg(ids []PeerID) ([][]byte, error) {
	if len(ids) == 0 {
		return nil, errors.New("no list of peer ids provided")
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
		buf[1] = byte(MsgTypeSubscribePeerState)

		offset := sizeOfProtoHeader
		for _, id := range chunk {
			copy(buf[offset:], id[:])
			offset += peerIDSize
		}

		messages = append(messages, buf)
	}

	return messages, nil
}

func UnmarshalSubPeerStateMsg(buf []byte) ([]PeerID, error) {
	if len(buf) < sizeOfProtoHeader {
		return nil, errors.New("invalid message format")
	}

	if (len(buf)-sizeOfProtoHeader)%peerIDSize != 0 {
		return nil, errors.New("invalid NodeID size")
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

func MarshalUnsubPeerStateMsg(ids []PeerID) ([][]byte, error) {
	if len(ids) == 0 {
		return nil, errors.New("no list of peer ids provided")
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
		buf[1] = byte(MsgTypeUnsubscribePeerState)

		offset := sizeOfProtoHeader
		for _, id := range chunk {
			copy(buf[offset:], id[:])
			offset += peerIDSize
		}

		messages = append(messages, buf)
	}

	return messages, nil
}

func UnmarshalUnsubPeerStateMsg(buf []byte) ([]PeerID, error) {
	if len(buf) < sizeOfProtoHeader {
		return nil, errors.New("invalid message format")
	}

	if (len(buf)-sizeOfProtoHeader)%peerIDSize != 0 {
		return nil, errors.New("invalid NodeID size")
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

func MarshalPeersOnline(ids []PeerID) ([][]byte, error) {
	if len(ids) == 0 {
		return nil, errors.New("no list of peer ids provided")
	}

	const maxPeersPerMessage = (MaxMessageSize - sizeOfProtoHeader) / peerIDSize
	var messages [][]byte

	for i := 0; i < len(ids); i += maxPeersPerMessage {
		end := i + maxPeersPerMessage
		if end > len(ids) {
			end = len(ids)
		}
		chunk := ids[i:end]

		// Create a message for this chunk
		totalSize := sizeOfProtoHeader + len(chunk)*peerIDSize
		buf := make([]byte, totalSize)
		buf[0] = byte(CurrentProtocolVersion)
		buf[1] = byte(MsgTypePeersOnline)

		offset := sizeOfProtoHeader
		for _, id := range chunk {
			copy(buf[offset:], id[:])
			offset += peerIDSize
		}

		messages = append(messages, buf)
	}

	return messages, nil
}

func UnmarshalPeersOnlineMsg(buf []byte) ([]PeerID, error) {
	if len(buf) < sizeOfProtoHeader {
		return nil, errors.New("invalid message format")
	}

	if (len(buf)-sizeOfProtoHeader)%peerIDSize != 0 {
		return nil, errors.New("invalid peers size")
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

func MarshalPeersWentOffline(ids []PeerID) ([][]byte, error) {
	if len(ids) == 0 {
		return nil, errors.New("no list of peer ids provided")
	}

	const maxPeersPerMessage = (MaxMessageSize - sizeOfProtoHeader) / peerIDSize
	var messages [][]byte

	for i := 0; i < len(ids); i += maxPeersPerMessage {
		end := i + maxPeersPerMessage
		if end > len(ids) {
			end = len(ids)
		}
		chunk := ids[i:end]

		// Create a message for this chunk
		totalSize := sizeOfProtoHeader + len(chunk)*peerIDSize
		buf := make([]byte, totalSize)
		buf[0] = byte(CurrentProtocolVersion)
		buf[1] = byte(MsgTypePeersWentOffline)

		offset := sizeOfProtoHeader
		for _, id := range chunk {
			copy(buf[offset:], id[:])
			offset += peerIDSize
		}

		messages = append(messages, buf)
	}

	return messages, nil
}

func UnMarshalPeersWentOffline(buf []byte) ([]PeerID, error) {
	if len(buf) < sizeOfProtoHeader {
		return nil, errors.New("invalid message format")
	}

	if (len(buf)-sizeOfProtoHeader)%peerIDSize != 0 {
		return nil, errors.New("invalid peers size")
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
