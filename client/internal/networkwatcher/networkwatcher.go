package networkwatcher

import (
	"context"
)

// NetworkWatcher watches for changes in network configuration.
type NetworkWatcher struct {
	cancel context.CancelFunc
}

// New creates a new network watcher.
func New() *NetworkWatcher {
	return &NetworkWatcher{}
}
