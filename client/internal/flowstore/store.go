package flowstore

import (
	"context"
	"io"
	"net/netip"
	"sync"
	"time"

	"github.com/google/uuid"
	log "github.com/sirupsen/logrus"
)

type Type int

const (
	TypeUnknown = iota
	TypeStart
	TypeEnd
)

type Direction int

func (d Direction) String() string {
	switch d {
	case Ingress:
		return "ingress"
	case Egress:
		return "egress"
	default:
		return "unknown"
	}
}

const (
	Unknown = iota
	Ingress
	Egress
)

type Event struct {
	ID        string
	Timestamp time.Time
	EventFields
}

type EventFields struct {
	FlowID     uuid.UUID
	Type       Type
	Direction  Direction
	Protocol   uint8
	SourceIP   netip.Addr
	DestIP     netip.Addr
	SourcePort uint16
	DestPort   uint16
	ICMPType   uint8
	ICMPCode   uint8
}

type Store interface {
	io.Closer
	// stores a flow event
	StoreEvent(flowEvent EventFields)
	// returns all stored events
	GetEvents() []*Event
}

func New(ctx context.Context) Store {
	ctx, cancel := context.WithCancel(ctx)
	store := &memory{
		events:  make(map[string]*Event),
		rcvChan: make(chan *EventFields, 100),
		ctx:     ctx,
		cancel:  cancel,
	}
	go store.startReceiver()
	return store
}

type memory struct {
	mux     sync.Mutex
	events  map[string]*Event
	rcvChan chan *EventFields
	ctx     context.Context
	cancel  context.CancelFunc
}

func (m *memory) startReceiver() {
	for {
		select {
		case <-m.ctx.Done():
			log.Info("flow memory store receiver stopped")
			return
		case eventFields := <-m.rcvChan:
			id := uuid.NewString()
			event := Event{
				ID:          id,
				EventFields: *eventFields,
				Timestamp:   time.Now(),
			}

			m.mux.Lock()
			m.events[id] = &event
			m.mux.Unlock()
		}
	}
}

func (m *memory) StoreEvent(flowEvent EventFields) {
	select {
	case m.rcvChan <- &flowEvent:
	default:
		log.Warn("flow memory store receiver is busy")
	}
}

func (m *memory) Close() error {
	m.cancel()
	return nil
}

func (m *memory) GetEvents() []*Event {
	m.mux.Lock()
	defer m.mux.Unlock()
	events := make([]*Event, 0, len(m.events))
	for _, event := range m.events {
		events = append(events, event)
	}
	return events
}
