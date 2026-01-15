package peer

import (
	"context"
	"fmt"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/iface/configurer"
)

const (
	wgHandshakePeriod = 3 * time.Minute
)

var (
	wgHandshakeOvertime = 30 * time.Second // allowed delay in network
	checkPeriod         = wgHandshakePeriod + wgHandshakeOvertime
)

type WGInterfaceStater interface {
	GetStats() (map[string]configurer.WGStats, error)
}

type WGWatcher struct {
	log           *log.Entry
	wgIfaceStater WGInterfaceStater
	peerKey       string
	stateDump     *stateDump

	ctx         context.Context
	ctxCancel   context.CancelFunc
	ctxLock     sync.Mutex
	enabledTime time.Time

	onFirstHandshakeFn func()
}

func NewWGWatcher(log *log.Entry, wgIfaceStater WGInterfaceStater, peerKey string, stateDump *stateDump, onFirstHandshakeFn func()) *WGWatcher {
	return &WGWatcher{
		log:                log,
		wgIfaceStater:      wgIfaceStater,
		peerKey:            peerKey,
		stateDump:          stateDump,
		onFirstHandshakeFn: onFirstHandshakeFn,
	}
}

// EnableWgWatcher starts the WireGuard watcher. If it is already enabled, it will return immediately and do nothing.
func (w *WGWatcher) EnableWgWatcher(parentCtx context.Context, onDisconnectedFn func()) {
	w.log.Debugf("enable WireGuard watcher")
	w.ctxLock.Lock()
	w.enabledTime = time.Now()

	if w.ctx != nil && w.ctx.Err() == nil {
		w.log.Errorf("WireGuard watcher already enabled")
		w.ctxLock.Unlock()
		return
	}

	ctx, ctxCancel := context.WithCancel(parentCtx)
	w.ctx = ctx
	w.ctxCancel = ctxCancel
	w.ctxLock.Unlock()

	initialHandshake, err := w.wgState()
	if err != nil {
		w.log.Warnf("failed to read initial wg stats: %v", err)
	}

	w.periodicHandshakeCheck(ctx, ctxCancel, onDisconnectedFn, initialHandshake)
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
}

// wgStateCheck help to check the state of the WireGuard handshake and relay connection
func (w *WGWatcher) periodicHandshakeCheck(ctx context.Context, ctxCancel context.CancelFunc, onDisconnectedFn func(), initialHandshake time.Time) {
	w.log.Infof("WireGuard watcher started")

	timer := time.NewTimer(wgHandshakeOvertime)
	defer timer.Stop()
	defer ctxCancel()

	lastHandshake := initialHandshake

	for {
		select {
		case <-timer.C:
			handshake, ok := w.handshakeCheck(lastHandshake)
			if !ok {
				if onDisconnectedFn != nil {
					onDisconnectedFn()
				}
				return
			}
			if lastHandshake.IsZero() {
				elapsed := w.calcElapsed(handshake)
				w.log.Infof("first wg handshake detected within: %.2fsec, (%s)", elapsed, handshake)
				if w.onFirstHandshakeFn != nil {
					w.onFirstHandshakeFn()
				}
			}

			lastHandshake = *handshake

			resetTime := time.Until(handshake.Add(checkPeriod))
			timer.Reset(resetTime)
			w.stateDump.WGcheckSuccess()

			w.log.Debugf("WireGuard watcher reset timer: %v", resetTime)
		case <-ctx.Done():
			w.log.Infof("WireGuard watcher stopped")
			return
		}
	}
}

// handshakeCheck checks the WireGuard handshake and return the new handshake time if it is different from the previous one
func (w *WGWatcher) handshakeCheck(lastHandshake time.Time) (*time.Time, bool) {
	handshake, err := w.wgState()
	if err != nil {
		w.log.Errorf("failed to read wg stats: %v", err)
		return nil, false
	}

	w.log.Tracef("previous handshake, handshake: %v, %v", lastHandshake, handshake)

	// the current know handshake did not change
	if handshake.Equal(lastHandshake) {
		w.log.Warnf("WireGuard handshake timed out: %v", handshake)
		return nil, false
	}

	// in case if the machine is suspended, the handshake time will be in the past
	if handshake.Add(checkPeriod).Before(time.Now()) {
		w.log.Warnf("WireGuard handshake timed out: %v", handshake)
		return nil, false
	}

	// error handling for handshake time in the future
	if handshake.After(time.Now()) {
		w.log.Warnf("WireGuard handshake is in the future: %v", handshake)
		return nil, false
	}

	return &handshake, true
}

func (w *WGWatcher) wgState() (time.Time, error) {
	wgStates, err := w.wgIfaceStater.GetStats()
	if err != nil {
		return time.Time{}, err
	}
	wgState, ok := wgStates[w.peerKey]
	if !ok {
		return time.Time{}, fmt.Errorf("peer %s not found in WireGuard endpoints", w.peerKey)
	}
	return wgState.LastHandshake, nil
}

// calcElapsed calculates elapsed time since watcher was enabled.
// The watcher started after the wg configuration happens, because of this need to normalise the negative value
func (w *WGWatcher) calcElapsed(handshake *time.Time) float64 {
	elapsed := handshake.Sub(w.enabledTime).Seconds()
	if elapsed < 0 {
		elapsed = 0
	}
	return elapsed
}
