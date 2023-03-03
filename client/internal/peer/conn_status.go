package peer

import log "github.com/sirupsen/logrus"

const (
	StatusConnected ConnStatus = iota
	StatusConnecting
	StatusDisconnected
)

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
