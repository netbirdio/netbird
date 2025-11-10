package store

import (
	"sync"

	"golang.org/x/exp/maps"

	"github.com/google/uuid"

	"github.com/netbirdio/netbird/client/internal/netflow/types"
)

const (
	// maxEvents is the maximum number of events to store in memory
	// This prevents unbounded memory growth
	maxEvents = 10000
)

// NewMemoryStore creates a new in-memory event store with a maximum capacity
// to prevent unbounded memory growth.
func NewMemoryStore() *Memory {
	return &Memory{
		events: make(map[uuid.UUID]*types.Event),
	}
}

// Memory is an in-memory store for netflow events.
// It has a maximum capacity to prevent unbounded memory growth.
type Memory struct {
	mux    sync.Mutex
	events map[uuid.UUID]*types.Event
}

// StoreEvent stores an event in memory. If the store is at capacity,
// the oldest event is removed before adding the new one (FIFO eviction).
func (m *Memory) StoreEvent(event *types.Event) {
	m.mux.Lock()
	defer m.mux.Unlock()

	// If we're at capacity, remove the oldest event (first one in map iteration)
	// This is a simple FIFO eviction strategy
	if len(m.events) >= maxEvents {
		// Find and remove the first (oldest) event
		for id := range m.events {
			delete(m.events, id)
			break // Remove only one to make room
		}
	}

	m.events[event.ID] = event
}

// Close clears all events from the store and releases resources.
// This should be called when the store is no longer needed.
func (m *Memory) Close() {
	m.mux.Lock()
	defer m.mux.Unlock()
	maps.Clear(m.events)
}

// GetEvents returns a copy of all events in the store.
// The returned slice is safe to modify without affecting the store.
func (m *Memory) GetEvents() []*types.Event {
	m.mux.Lock()
	defer m.mux.Unlock()
	events := make([]*types.Event, 0, len(m.events))
	for _, event := range m.events {
		events = append(events, event)
	}
	return events
}

// DeleteEvents removes events with the given IDs from the store.
// IDs that don't exist in the store are silently ignored.
func (m *Memory) DeleteEvents(ids []uuid.UUID) {
	m.mux.Lock()
	defer m.mux.Unlock()
	for _, id := range ids {
		delete(m.events, id)
	}
}
