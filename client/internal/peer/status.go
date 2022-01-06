package peer

import log "github.com/sirupsen/logrus"

type ConnStatus int

func (s ConnStatus) String() string {
	switch s {
	case StatusConnecting:
		return "StatusConnecting"
	case StatusConnected:
		return "StatusConnected"
	case StatusDisconnected:
		return "StatusDisconnected"
	default:
		log.Errorf("unknown status: %d", s)
		return "INVALID_PEER_CONNECTION_STATUS"
	}
}

const (
	StatusConnected = iota
	StatusConnecting
	StatusDisconnected
)
