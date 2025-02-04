package peer

import (
	"context"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/iface/configurer"
)

const (
	wgHandshakePeriod = 3 * time.Minute
)

var (
	wgHandshakeOvertime = 30 * time.Second
	checkPeriod         = wgHandshakePeriod + wgHandshakeOvertime
)

type WGInterfaceStater interface {
	GetStats(key string) (configurer.WGStats, error)
}

type WGWatcher struct {
	log           *log.Entry
	wgIfaceStater WGInterfaceStater
	peerKey       string

	ctx       context.Context
	ctxCancel context.CancelFunc
	ctxLock   sync.Mutex
	waitGroup sync.WaitGroup
}

func NewWGWatcher(log *log.Entry, wgIfaceStater WGInterfaceStater, peerKey string) *WGWatcher {
	return &WGWatcher{
		log:           log,
		wgIfaceStater: wgIfaceStater,
		peerKey:       peerKey,
	}
}

// EnableWgWatcher starts the WireGuard watcher. If it is already enabled, it will return immediately and do nothing.
func (w *WGWatcher) EnableWgWatcher(parentCtx context.Context, onDisconnectedFn func()) {
	w.log.Debugf("enable WireGuard watcher")
	w.ctxLock.Lock()
	defer w.ctxLock.Unlock()

	if w.ctx != nil && w.ctx.Err() == nil {
		w.log.Errorf("WireGuard watcher already enabled")
		return
	}

	ctx, ctxCancel := context.WithCancel(parentCtx)
	w.ctx = ctx
	w.ctxCancel = ctxCancel

	initialHandshake, err := w.wgState()
	if err != nil {
		w.log.Warnf("failed to read wg stats: %v", err)
	}

	w.waitGroup.Add(1)
	go w.periodicHandshakeCheck(ctx, ctxCancel, onDisconnectedFn, initialHandshake)
}

// DisableWgWatcher stops the WireGuard watcher and wait for the watcher to exit
func (w *WGWatcher) DisableWgWatcher() {
	w.ctxLock.Lock()
	defer w.ctxLock.Unlock()

	if w.ctxCancel == nil {
		return
	}

	w.log.Debugf("disable WireGuard watcher")

	w.ctxCancel()
	w.ctxCancel = nil
	w.waitGroup.Wait()
}

// wgStateCheck help to check the state of the WireGuard handshake and relay connection
func (w *WGWatcher) periodicHandshakeCheck(ctx context.Context, ctxCancel context.CancelFunc, onDisconnectedFn func(), initialHandshake time.Time) {
	w.log.Debugf("WireGuard watcher started")
	defer w.waitGroup.Done()

	timer := time.NewTimer(wgHandshakeOvertime)
	defer timer.Stop()
	defer ctxCancel()

	lastHandshake := initialHandshake

	for {
		select {
		case <-timer.C:
			handshake, ok := w.handshakeCheck(lastHandshake)
			if !ok {
				onDisconnectedFn()
				return
			}
			resetTime := time.Until(handshake.Add(checkPeriod))
			w.log.Debugf("WireGuard watcher reset timer: %v", resetTime)
			timer.Reset(resetTime)
			lastHandshake = *handshake
		case <-ctx.Done():
			w.log.Debugf("WireGuard watcher stopped")
			return
		}
	}
}

func (w *WGWatcher) wgState() (time.Time, error) {
	wgState, err := w.wgIfaceStater.GetStats(w.peerKey)
	if err != nil {
		return time.Time{}, err
	}
	return wgState.LastHandshake, nil
}

func (w *WGWatcher) handshakeCheck(lastHandshake time.Time) (*time.Time, bool) {
	handshake, err := w.wgState()
	if err != nil {
		w.log.Errorf("failed to read wg stats: %v", err)
		return nil, false
	}

	w.log.Debugf("previous handshake, handshake: %v, %v", lastHandshake, handshake)

	if handshake.Equal(lastHandshake) {
		w.log.Infof("WireGuard handshake timed out, closing relay connection: %v", handshake)
		return nil, false
	}

	return &handshake, true
}
