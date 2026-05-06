// Package debouncer provides a small "trigger now or coalesce within a
// window" helper. Used by the engine to debounce SyncMeta calls.
package debouncer

import (
	"sync"
	"time"
)

// Debouncer coalesces rapid successive Trigger calls: only the last fn
// registered within the delay window is executed, after the window
// expires.
type Debouncer struct {
	delay time.Duration
	mu    sync.Mutex
	timer *time.Timer
	fn    func()
}

// New creates a Debouncer with the given delay window.
func New(delay time.Duration) *Debouncer {
	return &Debouncer{delay: delay}
}

// Trigger schedules fn to run after the configured delay. Subsequent
// Trigger calls within the window REPLACE the pending fn (last-write-wins)
// and reset the timer.
func (d *Debouncer) Trigger(fn func()) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.fn = fn
	if d.timer != nil {
		d.timer.Stop()
	}
	d.timer = time.AfterFunc(d.delay, func() {
		d.mu.Lock()
		f := d.fn
		d.mu.Unlock()
		if f != nil {
			f()
		}
	})
}

// Stop cancels any pending fn. Safe to call multiple times.
func (d *Debouncer) Stop() {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.timer != nil {
		d.timer.Stop()
		d.timer = nil
	}
}
