package peer

import (
	log "github.com/sirupsen/logrus"
)

const (
	// StatusIdle indicate the peer is in disconnected state
	StatusIdle ConnStatus = iota
	// StatusConnecting indicate the peer is in connecting state
	StatusConnecting
	// StatusConnected indicate the peer is in connected state
	StatusConnected
)

// ConnStatus describe the status of a peer's connection
type ConnStatus int32

func (s ConnStatus) String() string {
	switch s {
	case StatusConnecting:
		return "Connecting"
	case StatusConnected:
		return "Connected"
	case StatusIdle:
		return "Idle"
	default:
		log.Errorf("unknown status: %d", s)
		return "INVALID_PEER_CONNECTION_STATUS"
	}
}
