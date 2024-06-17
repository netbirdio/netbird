package peer

import log "github.com/sirupsen/logrus"

const (
	// StatusConnected indicate the peer is in connected state
	StatusConnected ConnStatus = iota
	// StatusConnecting indicate the peer is in connecting state
	StatusConnecting
	// StatusDisconnected indicate the peer is in disconnected state
	StatusDisconnected
)

// ConnStatus describe the status of a peer's connection
type ConnStatus int

func (s ConnStatus) String() string {
	switch s {
	case StatusConnecting:
		return "Connecting"
	case StatusConnected:
		return "Connected"
	case StatusDisconnected:
		return "Disconnected"
	default:
		log.Errorf("unknown status: %d", s)
		return "INVALID_PEER_CONNECTION_STATUS"
	}
}
