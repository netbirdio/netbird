//go:build ios || android

package networkmonitor

import "context"

func (nw *NetworkMonitor) Start(context.Context, func()) {
}

func (nw *NetworkMonitor) Stop() {
}
