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

	enabled   bool
	muEnabled sync.RWMutex

	resetCh chan struct{}
}

func NewWGWatcher(log *log.Entry, wgIfaceStater WGInterfaceStater, peerKey string, stateDump *stateDump) *WGWatcher {
	return &WGWatcher{
		log:           log,
		wgIfaceStater: wgIfaceStater,
		peerKey:       peerKey,
		stateDump:     stateDump,
		resetCh:       make(chan struct{}, 1),
	}
}

// EnableWgWatcher starts the WireGuard watcher. If it is already enabled, it will return immediately and do nothing.
// The watcher runs until ctx is cancelled. Caller is responsible for context lifecycle management.
// NOTE: reverted to the pre-#6626 shape for bisecting the NHN issue.
func (w *WGWatcher) EnableWgWatcher(ctx context.Context, enabledTime time.Time, onDisconnectedFn func(), onHandshakeSuccessFn func(when time.Time)) {
	w.muEnabled.Lock()
	if w.enabled {
		w.muEnabled.Unlock()
		return
	}

	w.log.Debugf("enable WireGuard watcher")
	w.enabled = true
	w.muEnabled.Unlock()

	initialHandshake, err := w.wgState()
	if err != nil {
		w.log.Warnf("failed to read initial wg stats: %v", err)
	}
	w.log.Warnf("PSK-DIAG: watcher baseline handshake=%v (zero=%v) [pre-6626 revert]", initialHandshake, initialHandshake.IsZero())

	w.periodicHandshakeCheck(ctx, onDisconnectedFn, onHandshakeSuccessFn, enabledTime, initialHandshake)

	w.muEnabled.Lock()
	w.enabled = false
	w.muEnabled.Unlock()
}

// IsEnabled returns true if the WireGuard watcher is currently enabled
func (w *WGWatcher) IsEnabled() bool {
	w.muEnabled.RLock()
	defer w.muEnabled.RUnlock()
	return w.enabled
}

// Reset signals the watcher that the WireGuard peer has been reset and a new
// handshake is expected. This restarts the handshake timeout from scratch.
func (w *WGWatcher) Reset() {
	select {
	case w.resetCh <- struct{}{}:
	default:
	}
}

// wgStateCheck help to check the state of the WireGuard handshake and relay connection
func (w *WGWatcher) periodicHandshakeCheck(ctx context.Context, onDisconnectedFn func(), onHandshakeSuccessFn func(when time.Time), enabledTime time.Time, initialHandshake time.Time) {
	w.log.Infof("WireGuard watcher started")
	w.log.Warnf("WGW-DIAG: watcher started id=%d baseline=%v (zero=%v) firstCheckIn=%v", enabledTime.UnixNano(), initialHandshake, initialHandshake.IsZero(), wgHandshakeOvertime)

	timer := time.NewTimer(wgHandshakeOvertime)
	defer timer.Stop()

	lastHandshake := initialHandshake

	for {
		select {
		case <-timer.C:
			w.log.Warnf("WGW-DIAG: check fire id=%d lastHandshake=%v", enabledTime.UnixNano(), lastHandshake)
			handshake, ok := w.handshakeCheck(lastHandshake)
			if !ok {
				w.log.Warnf("WGW-DIAG: check failed -> firing onDisconnected (TEARDOWN, pre-6626 no ctx-recheck) id=%d", enabledTime.UnixNano())
				onDisconnectedFn()
				return
			}
			if lastHandshake.IsZero() {
				elapsed := calcElapsed(enabledTime, *handshake)
				w.log.Infof("first wg handshake detected within: %.2fsec, (%s)", elapsed, handshake)
				if onHandshakeSuccessFn != nil {
					onHandshakeSuccessFn(*handshake)
				}
			}

			lastHandshake = *handshake

			resetTime := time.Until(handshake.Add(checkPeriod))
			timer.Reset(resetTime)
			w.stateDump.WGcheckSuccess()

			w.log.Warnf("WGW-DIAG: check ok id=%d handshake=%v nextCheckIn=%v", enabledTime.UnixNano(), handshake, resetTime)
		case <-w.resetCh:
			w.log.Warnf("WGW-DIAG: peer reset received, restarting timeout id=%d", enabledTime.UnixNano())
			lastHandshake = time.Time{}
			enabledTime = time.Now()
			timer.Stop()
			timer.Reset(wgHandshakeOvertime)
		case <-ctx.Done():
			w.log.Warnf("WGW-DIAG: watcher stopped (ctx done) id=%d", enabledTime.UnixNano())
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
func calcElapsed(enabledTime, handshake time.Time) float64 {
	elapsed := handshake.Sub(enabledTime).Seconds()
	if elapsed < 0 {
		elapsed = 0
	}
	return elapsed
}
