//go:build !linux || android

package watcher

import "context"

type noopWatcher struct{}

// New creates a no-op watcher for unsupported platforms.
func New(_ string) Watcher {
	return &noopWatcher{}
}

// Start blocks until context cancellation.
func (w *noopWatcher) Start(ctx context.Context, _ Handler) error {
	<-ctx.Done()
	return ctx.Err()
}

// Stop terminates the watcher.
func (w *noopWatcher) Stop() error {
	return nil
}
