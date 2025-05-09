package worker

import (
	"sync/atomic"

	log "github.com/sirupsen/logrus"
)

const (
	StatusDisconnected Status = iota
	StatusConnected
)

type Status int32

func (s Status) String() string {
	switch s {
	case StatusDisconnected:
		return "Disconnected"
	case StatusConnected:
		return "Connected"
	default:
		log.Errorf("unknown status: %d", s)
		return "unknown"
	}
}

// AtomicWorkerStatus is a thread-safe wrapper for worker status
type AtomicWorkerStatus struct {
	status atomic.Int32
}

func NewAtomicStatus() *AtomicWorkerStatus {
	acs := &AtomicWorkerStatus{}
	acs.SetDisconnected()
	return acs
}

// Get returns the current connection status
func (acs *AtomicWorkerStatus) Get() Status {
	return Status(acs.status.Load())
}

func (acs *AtomicWorkerStatus) SetConnected() {
	acs.status.Store(int32(StatusConnected))
}

func (acs *AtomicWorkerStatus) SetDisconnected() {
	acs.status.Store(int32(StatusDisconnected))
}

// String returns the string representation of the current status
func (acs *AtomicWorkerStatus) String() string {
	return acs.Get().String()
}
