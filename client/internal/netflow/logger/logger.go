package logger

import (
	"context"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/internal/netflow/store"
	"github.com/netbirdio/netbird/client/internal/netflow/types"
)

type rcvChan chan *types.EventFields
type Logger struct {
	ctx      context.Context
	cancel   context.CancelFunc
	enabled  atomic.Bool
	rcvChan  atomic.Pointer[rcvChan]
	stopChan chan struct{}
	Store    types.Store
}

func New(ctx context.Context) *Logger {
	ctx, cancel := context.WithCancel(ctx)
	return &Logger{
		ctx:      ctx,
		cancel:   cancel,
		Store:    store.NewMemoryStore(),
		stopChan: make(chan struct{}),
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
	go l.startReceiver()
}

func (l *Logger) startReceiver() {
	if l.enabled.Load() {
		return
	}

	c := make(rcvChan, 100)
	l.rcvChan.Swap(&c)
	l.enabled.Store(true)

	for {
		select {
		case <-l.ctx.Done():
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
		case <-l.stopChan:
			return
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
	l.stopChan <- struct{}{}
}

func (l *Logger) GetEvents() []*types.Event {
	return l.Store.GetEvents()
}

func (l *Logger) Close() {
	l.stop()
	l.cancel()
}
