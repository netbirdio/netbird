package networkmonitor

import (
	"context"
)

// NetworkWatcher watches for changes in network configuration.
type NetworkWatcher struct {
	cancel context.CancelFunc
}

// New creates a new network monitor.
func New() *NetworkWatcher {
	return &NetworkWatcher{}
}
