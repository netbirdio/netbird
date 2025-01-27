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
	wgReadErrorRetry    = 5 * time.Second
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
}

func NewWGWatcher(log *log.Entry, wgIfaceStater WGInterfaceStater, peerKey string) *WGWatcher {
	return &WGWatcher{
		log:           log,
		wgIfaceStater: wgIfaceStater,
		peerKey:       peerKey,
	}
}

func (w *WGWatcher) EnableWgWatcher(parentCtx context.Context, onDisconnectedFn func()) {
	w.log.Debugf("enable WireGuard watcher")
	w.ctxLock.Lock()
	defer w.ctxLock.Unlock()

	if w.ctx != nil && w.ctx.Err() == nil {
		return
	}

	ctx, ctxCancel := context.WithCancel(parentCtx)
	w.ctx = ctx
	w.ctxCancel = ctxCancel

	w.wgStateCheck(ctx, ctxCancel, onDisconnectedFn)
}

func (w *WGWatcher) DisableWgWatcher() {
	w.ctxLock.Lock()
	defer w.ctxLock.Unlock()

	if w.ctxCancel == nil {
		return
	}

	w.log.Debugf("disable WireGuard watcher")

	w.ctxCancel()
}

// wgStateCheck help to check the state of the WireGuard handshake and relay connection
func (w *WGWatcher) wgStateCheck(ctx context.Context, ctxCancel context.CancelFunc, onDisconnectedFn func()) {
	w.log.Debugf("WireGuard watcher started")
	lastHandshake, err := w.wgState()
	if err != nil {
		w.log.Warnf("failed to read wg stats: %v", err)
		lastHandshake = time.Time{}
	}

	go func(lastHandshake time.Time) {
		timer := time.NewTimer(wgHandshakeOvertime)
		defer timer.Stop()
		defer ctxCancel()

		for {
			select {
			case <-timer.C:
				handshake, err := w.wgState()
				if err != nil {
					w.log.Errorf("failed to read wg stats: %v", err)
					timer.Reset(wgReadErrorRetry)
					continue
				}

				w.log.Tracef("previous handshake, handshake: %v, %v", lastHandshake, handshake)

				if handshake.Equal(lastHandshake) {
					w.log.Infof("WireGuard handshake timed out, closing relay connection: %v", handshake)
					onDisconnectedFn()
					return
				}

				resetTime := time.Until(handshake.Add(checkPeriod))
				lastHandshake = handshake
				timer.Reset(resetTime)
			case <-ctx.Done():
				w.log.Debugf("WireGuard watcher stopped")
				return
			}
		}
	}(lastHandshake)
}

func (w *WGWatcher) wgState() (time.Time, error) {
	wgState, err := w.wgIfaceStater.GetStats(w.peerKey)
	if err != nil {
		return time.Time{}, err
	}
	return wgState.LastHandshake, nil
}
