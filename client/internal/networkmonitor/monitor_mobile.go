//go:build ios || android

package networkmonitor

import "context"

func (nw *NetworkWatcher) Start(context.Context, func()) {
}

func (nw *NetworkWatcher) Stop() {
}
