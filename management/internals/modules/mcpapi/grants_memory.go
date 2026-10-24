package mcpapi

import (
	"context"
	"sync"
	"time"
)

// memorySweepInterval bounds how often a write drops expired entries, which nothing else
// reads again once their login or session is over.
const memorySweepInterval = time.Minute

type expiring[T any] struct {
	value   T
	expires time.Time
}

func (e expiring[T]) live(now time.Time) bool {
	return now.Before(e.expires)
}

// memoryGrants keeps the grants in this process. One mutex makes every method atomic.
type memoryGrants struct {
	mu        sync.Mutex
	grants    map[string]expiring[grantRecord]
	markers   map[string]expiring[string]
	lastSweep time.Time
}

func newMemoryGrants() *memoryGrants {
	return &memoryGrants{
		grants:  make(map[string]expiring[grantRecord]),
		markers: make(map[string]expiring[string]),
	}
}

func (m *memoryGrants) start(_ context.Context, codeID string, codeTTL time.Duration, grantID string, record grantRecord, ttl time.Duration) (string, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now()
	m.sweep(now)
	key := usedCodeKeyPrefix + codeID
	if marker, ok := m.markers[key]; ok && marker.live(now) {
		return marker.value, true, nil
	}
	m.markers[key] = expiring[string]{value: grantID, expires: now.Add(codeTTL)}
	m.grants[grantID] = expiring[grantRecord]{value: record, expires: now.Add(ttl)}
	return "", false, nil
}

func (m *memoryGrants) claim(_ context.Context, key string, ttl time.Duration) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now()
	m.sweep(now)
	if marker, ok := m.markers[key]; ok && marker.live(now) {
		return false, nil
	}
	m.markers[key] = expiring[string]{value: "1", expires: now.Add(ttl)}
	return true, nil
}

func (m *memoryGrants) load(_ context.Context, grantID string) (grantRecord, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	entry, ok := m.grants[grantID]
	if !ok || !entry.live(time.Now()) {
		return grantRecord{}, false, nil
	}
	return entry.value, true, nil
}

func (m *memoryGrants) rotate(_ context.Context, grantID, presented, next string, now time.Time) (rotationOutcome, string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	entry, ok := m.grants[grantID]
	if !ok || !entry.live(time.Now()) {
		return grantGone, "", nil
	}
	outcome := rotateGrant(&entry.value, presented, next, now)
	switch outcome {
	case grantRotated:
		m.grants[grantID] = entry
	case grantReplayed:
		delete(m.grants, grantID)
		return outcome, "", nil
	}
	return outcome, entry.value.Current, nil
}

func (m *memoryGrants) revoke(_ context.Context, grantID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.grants, grantID)
	return nil
}

// sweep drops expired entries at most once per memorySweepInterval. Callers hold mu.
func (m *memoryGrants) sweep(now time.Time) {
	if now.Sub(m.lastSweep) < memorySweepInterval {
		return
	}
	m.lastSweep = now
	for id, entry := range m.grants {
		if !entry.live(now) {
			delete(m.grants, id)
		}
	}
	for key, marker := range m.markers {
		if !marker.live(now) {
			delete(m.markers, key)
		}
	}
}
