//go:build ios || android

package networkmonitor

import "context"

func (nw *NetworkMonitor) Start(context.Context, func()) error {
	return nil
}

func (nw *NetworkMonitor) Stop() {
}
