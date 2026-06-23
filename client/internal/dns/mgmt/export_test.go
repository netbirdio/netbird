package mgmt

import "time"

// pendingCount returns how many initial resolves are still in flight. Test-only.
func (m *Resolver) pendingCount() int {
	m.mutex.RLock()
	defer m.mutex.RUnlock()
	return len(m.pending)
}

// waitForPendingResolves blocks until all pending resolves settle or the
// timeout elapses, returning true if all settled. Test-only.
func (m *Resolver) waitForPendingResolves(timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for m.pendingCount() > 0 {
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(10 * time.Millisecond)
	}
	return true
}
