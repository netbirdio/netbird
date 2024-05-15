package networkmonitor

import (
	"context"
	"errors"
	"sync"
)

var ErrStopped = errors.New("monitor has been stopped")

// NetworkMonitor watches for changes in network configuration.
type NetworkMonitor struct {
	cancel context.CancelFunc
	wg     sync.WaitGroup
	mu     sync.Mutex
}

// New creates a new network monitor.
func New() *NetworkMonitor {
	return &NetworkMonitor{}
}
