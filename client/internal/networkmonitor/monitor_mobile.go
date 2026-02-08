//go:build ios || tvos || android

package networkmonitor

import (
	"context"
	"fmt"
)

type NetworkMonitor struct {
}

// New creates a new network monitor.
func New() *NetworkMonitor {
	return &NetworkMonitor{}
}

func (nw *NetworkMonitor) Listen(_ context.Context) error {
	return fmt.Errorf("network monitor not supported on mobile platforms")
}

func (nw *NetworkMonitor) Stop() {
}
