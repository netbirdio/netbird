package flowstore

import (
	"context"
	"io"
	"sync"

	log "github.com/sirupsen/logrus"
)

type Event struct {
	ID     string
	FlowID string
}

type Store interface {
	io.Closer
	// stores a flow event
	StoreEvent(flowEvent Event)
	// returns all stored events
	GetEvents() []*Event
}

func New(ctx context.Context) Store {
	ctx, cancel := context.WithCancel(ctx)
	store := &memory{
		events:  make(map[string]*Event),
		rcvChan: make(chan *Event, 100),
		ctx:     ctx,
		cancel:  cancel,
	}
	go store.startReceiver()
	return store
}

type memory struct {
	mux     sync.Mutex
	events  map[string]*Event
	rcvChan chan *Event
	ctx     context.Context
	cancel  context.CancelFunc
}

func (m *memory) startReceiver() {
	for {
		select {
		case <-m.ctx.Done():
			log.Info("flow memory store receiver stopped")
			return
		case event := <-m.rcvChan:
			m.mux.Lock()
			m.events[event.ID] = event
			m.mux.Unlock()
		}
	}
}

func (m *memory) StoreEvent(flowEvent Event) {
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
