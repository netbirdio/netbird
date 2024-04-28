//go:build ios || android

package networkwatcher

import "context"

func (nw *NetworkWatcher) Start(context.Context, func()) {
}

func (nw *NetworkWatcher) Stop() {
}
