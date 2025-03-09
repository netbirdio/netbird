package store

import (
	"sync"

	"golang.org/x/exp/maps"

	"github.com/google/uuid"

	"github.com/netbirdio/netbird/client/internal/netflow/types"
)

func NewMemoryStore() *Memory {
	return &Memory{
		events: make(map[uuid.UUID]*types.Event),
	}
}

type Memory struct {
	mux    sync.Mutex
	events map[uuid.UUID]*types.Event
}

func (m *Memory) StoreEvent(event *types.Event) {
	m.mux.Lock()
	defer m.mux.Unlock()
	m.events[event.ID] = event
}

func (m *Memory) Close() {
	m.mux.Lock()
	defer m.mux.Unlock()
	maps.Clear(m.events)
}

func (m *Memory) GetEvents() []*types.Event {
	m.mux.Lock()
	defer m.mux.Unlock()
	events := make([]*types.Event, 0, len(m.events))
	for _, event := range m.events {
		events = append(events, event)
	}
	return events
}

func (m *Memory) DeleteEvents(ids []uuid.UUID) {
	m.mux.Lock()
	defer m.mux.Unlock()
	for _, id := range ids {
		delete(m.events, id)
	}
}
