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
	enabled            atomic.Bool
	rcvChan            atomic.Pointer[rcvChan]
	cancel             context.CancelFunc
	statusRecorder     *peer.Status
	wgIfaceIPNet       net.IPNet
	dnsCollection      atomic.Bool
	exitNodeCollection atomic.Bool
	Store              types.Store
}

func New(statusRecorder *peer.Status, wgIfaceIPNet net.IPNet) *Logger {

	return &Logger{
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
	ctx, cancel := context.WithCancel(context.Background())
	l.cancel = cancel
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

			var isSrcExitNode bool
			var isDestExitNode bool

			if !l.wgIfaceIPNet.Contains(net.IP(event.SourceIP.AsSlice())) {
				event.SourceResourceID, isSrcExitNode = l.statusRecorder.CheckRoutes(event.SourceIP)
			}

			if !l.wgIfaceIPNet.Contains(net.IP(event.DestIP.AsSlice())) {
				event.DestResourceID, isDestExitNode = l.statusRecorder.CheckRoutes(event.DestIP)
			}

			if l.shouldStore(eventFields, isSrcExitNode || isDestExitNode) {
				l.Store.StoreEvent(&event)
			}
		}
	}
}

func (l *Logger) Close() {
	l.stop()
	l.Store.Close()
}

func (l *Logger) stop() {
	if !l.enabled.Load() {
		return
	}

	l.enabled.Store(false)
	l.mux.Lock()
	if l.cancel != nil {
		l.cancel()
		l.cancel = nil
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
