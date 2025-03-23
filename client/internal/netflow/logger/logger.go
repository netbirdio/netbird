package logger

import (
	"context"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/internal/dnsfwd"
	"github.com/netbirdio/netbird/client/internal/netflow/store"
	"github.com/netbirdio/netbird/client/internal/netflow/types"
	"github.com/netbirdio/netbird/client/internal/peer"
)

type rcvChan chan *types.EventFields
type Logger struct {
	mux                sync.Mutex
	ctx                context.Context
	cancel             context.CancelFunc
	enabled            atomic.Bool
	rcvChan            atomic.Pointer[rcvChan]
	cancelReceiver     context.CancelFunc
	statusRecorder     *peer.Status
	wgIfaceIPNet       net.IPNet
	dnsCollection      atomic.Bool
	exitNodeCollection atomic.Bool
	Store              types.Store
}

func New(ctx context.Context, statusRecorder *peer.Status, wgIfaceIPNet net.IPNet) *Logger {

	ctx, cancel := context.WithCancel(ctx)
	return &Logger{
		ctx:            ctx,
		cancel:         cancel,
		statusRecorder: statusRecorder,
		wgIfaceIPNet:   wgIfaceIPNet,
		Store:          store.NewMemoryStore(),
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
			id := uuid.New()
			event := types.Event{
				ID:          id,
				EventFields: *eventFields,
				Timestamp:   time.Now().UTC(),
			}

			var isExitNode bool
			if event.Direction == types.Ingress {
				if !l.wgIfaceIPNet.Contains(net.IP(event.SourceIP.AsSlice())) {
					event.SourceResourceID, isExitNode = l.statusRecorder.CheckRoutes(event.SourceIP)
				}
			} else if event.Direction == types.Egress {
				if !l.wgIfaceIPNet.Contains(net.IP(event.DestIP.AsSlice())) {
					event.DestResourceID, isExitNode = l.statusRecorder.CheckRoutes(event.DestIP)
				}
			}

			if l.shouldStore(eventFields, isExitNode) {
				l.Store.StoreEvent(&event)
			}
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

func (l *Logger) DeleteEvents(ids []uuid.UUID) {
	l.Store.DeleteEvents(ids)
}

func (l *Logger) UpdateConfig(dnsCollection, exitNodeCollection bool) {
	l.dnsCollection.Store(dnsCollection)
	l.exitNodeCollection.Store(exitNodeCollection)
}

func (l *Logger) Close() {
	l.stop()
	l.cancel()
}

func (l *Logger) shouldStore(event *types.EventFields, isExitNode bool) bool {
	// check dns collection
	if !l.dnsCollection.Load() && event.Protocol == types.UDP && (event.DestPort == 53 || event.DestPort == dnsfwd.ListenPort) {
		return false
	}

	// check exit node collection
	if !l.exitNodeCollection.Load() && isExitNode {
		return false
	}

	return true
}
