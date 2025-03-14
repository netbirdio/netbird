package peer

import (
	"sync/atomic"

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

// AtomicConnStatus is a thread-safe wrapper for ConnStatus
type AtomicConnStatus struct {
	status atomic.Int32
}

// NewAtomicConnStatus creates a new AtomicConnStatus with the given initial status
func NewAtomicConnStatus() *AtomicConnStatus {
	acs := &AtomicConnStatus{}
	acs.Set(StatusIdle)
	return acs
}

// Get returns the current connection status
func (acs *AtomicConnStatus) Get() ConnStatus {
	return ConnStatus(acs.status.Load())
}

// Set updates the connection status
func (acs *AtomicConnStatus) Set(status ConnStatus) {
	acs.status.Store(int32(status))
}

// String returns the string representation of the current status
func (acs *AtomicConnStatus) String() string {
	return acs.Get().String()
}

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
