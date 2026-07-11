package peer

import (
	"sync/atomic"

	log "github.com/sirupsen/logrus"
)

const (
	WorkerStatusDisconnected WorkerStatus = iota
	WorkerStatusConnected
)

type WorkerStatus int32

func (s WorkerStatus) String() string {
	switch s {
	case WorkerStatusDisconnected:
		return "Disconnected"
	case WorkerStatusConnected:
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
func (acs *AtomicWorkerStatus) Get() WorkerStatus {
	return WorkerStatus(acs.status.Load())
}

func (acs *AtomicWorkerStatus) SetConnected() {
	acs.status.Store(int32(WorkerStatusConnected))
}

func (acs *AtomicWorkerStatus) SetDisconnected() {
	acs.status.Store(int32(WorkerStatusDisconnected))
}

// String returns the string representation of the current status
func (acs *AtomicWorkerStatus) String() string {
	return acs.Get().String()
}
