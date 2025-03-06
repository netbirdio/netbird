package logger

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/internal/netflow/store"
	"github.com/netbirdio/netbird/client/internal/netflow/types"
)

type rcvChan chan *types.EventFields
type Logger struct {
	mux            sync.Mutex
	ctx            context.Context
	cancel         context.CancelFunc
	enabled        atomic.Bool
	rcvChan        atomic.Pointer[rcvChan]
	cancelReceiver context.CancelFunc
	Store          types.Store
}

func New(ctx context.Context) *Logger {
	ctx, cancel := context.WithCancel(ctx)
	return &Logger{
		ctx:    ctx,
		cancel: cancel,
		Store:  store.NewMemoryStore(),
	}
}

func (l *Logger) StoreEvent(flowEvent types.EventFields) {
	if !l.enabled.Load() {
		return
	}

	c := l.rcvChan.Load()
	if c == nil {
		return
	}

	select {
	case *c <- &flowEvent:
	default:
		// todo: we should collect or log on this
	}
}

func (l *Logger) Enable() {
	if l.enabled.Load() {
		return
	}
	go l.startReceiver()
}

func (l *Logger) startReceiver() {
	l.mux.Lock()
	ctx, cancel := context.WithCancel(l.ctx)
	l.cancelReceiver = cancel
	l.mux.Unlock()

	c := make(rcvChan, 100)
	l.rcvChan.Store(&c)
	l.enabled.Store(true)

	for {
		select {
		case <-ctx.Done():
			log.Info("flow Memory store receiver stopped")
			return
		case eventFields := <-c:
			id := uuid.NewString()
			event := types.Event{
				ID:          id,
				EventFields: *eventFields,
				Timestamp:   time.Now(),
			}
			l.Store.StoreEvent(&event)
		}
	}
}

func (l *Logger) Disable() {
	l.stop()
	l.Store.Close()
}

func (l *Logger) stop() {
	if !l.enabled.Load() {
		return
	}

	l.enabled.Store(false)
	l.mux.Lock()
	if l.cancelReceiver != nil {
		l.cancelReceiver()
		l.cancelReceiver = nil
	}
	l.rcvChan.Store(nil)
	l.mux.Unlock()
}

func (l *Logger) GetEvents() []*types.Event {
	return l.Store.GetEvents()
}

func (l *Logger) DeleteEvents(ids []string) {
	l.Store.DeleteEvents(ids)
}

func (l *Logger) Close() {
	l.stop()
	l.cancel()
}
