package peer

import (
	"sync/atomic"

	log "github.com/sirupsen/logrus"
)

const (
	// StatusConnected indicate the peer is in connected state
	StatusConnected ConnStatus = iota
	// StatusConnecting indicate the peer is in connecting state
	StatusConnecting
	// StatusDisconnected indicate the peer is in disconnected state
	StatusDisconnected
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
	acs.Set(StatusDisconnected)
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
	case StatusDisconnected:
		return "Disconnected"
	default:
		log.Errorf("unknown status: %d", s)
		return "INVALID_PEER_CONNECTION_STATUS"
	}
}
