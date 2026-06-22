package mgmt

import "time"

// pendingCount returns the number of domains whose initial resolve is still in
// flight. Test-only: lets tests wait for background resolves kicked off by
// UpdateFromServerDomains.
func (m *Resolver) pendingCount() int {
	m.mutex.RLock()
	defer m.mutex.RUnlock()
	return len(m.pending)
}

// waitForPendingResolves blocks until all background initial resolves have
// settled, or the timeout elapses. Returns true if all settled. Test-only.
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
