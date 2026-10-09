package mdm

import "sync"

// ChangeDetector tracks the last observed policy of a Loader so an
// OS-notification-driven caller can ask whether the managed configuration
// actually changed before restarting anything.
type ChangeDetector struct {
	mu     sync.Mutex
	loader *Loader
	prev   *Policy
}

// NewChangeDetector constructs a ChangeDetector seeded with the loader's
// current policy, so only a later change reports as changed.
func NewChangeDetector(loader *Loader) *ChangeDetector {
	return &ChangeDetector{
		loader: loader,
		prev:   loader.Load(),
	}
}

// Changed re-reads the policy, logs the per-key diff, and reports whether it
// diverged from the last observation; the new snapshot becomes the baseline.
func (d *ChangeDetector) Changed() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	curr := d.loader.Load()
	if !policyChanged(d.prev, curr) {
		return false
	}
	d.prev = curr
	return true
}
