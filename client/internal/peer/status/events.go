package status

import (
	"slices"
	"sync"

	"github.com/netbirdio/netbird/client/proto"
)

type EventQueue struct {
	maxSize int
	events  []*proto.SystemEvent
	mutex   sync.RWMutex
}

func NewEventQueue(size int) *EventQueue {
	return &EventQueue{
		maxSize: size,
		events:  make([]*proto.SystemEvent, 0, size),
	}
}

func (q *EventQueue) Add(event *proto.SystemEvent) {
	q.mutex.Lock()
	defer q.mutex.Unlock()

	q.events = append(q.events, event)

	if len(q.events) > q.maxSize {
		q.events = q.events[len(q.events)-q.maxSize:]
	}
}

func (q *EventQueue) GetAll() []*proto.SystemEvent {
	q.mutex.RLock()
	defer q.mutex.RUnlock()

	return slices.Clone(q.events)
}

type EventSubscription struct {
	id     string
	events chan *proto.SystemEvent
}

func (s *EventSubscription) Events() <-chan *proto.SystemEvent {
	return s.events
}
