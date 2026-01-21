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
}

func NewWGWatcher(log *log.Entry, wgIfaceStater WGInterfaceStater, peerKey string, stateDump *stateDump) *WGWatcher {
	return &WGWatcher{
		log:           log,
		wgIfaceStater: wgIfaceStater,
		peerKey:       peerKey,
		stateDump:     stateDump,
	}
}

// EnableWgWatcher starts the WireGuard watcher. If it is already enabled, it will return immediately and do nothing.
// The watcher runs until ctx is cancelled. Caller is responsible for context lifecycle management.
func (w *WGWatcher) EnableWgWatcher(ctx context.Context, onDisconnectedFn func()) {
	w.muEnabled.Lock()
	if w.enabled {
		w.muEnabled.Unlock()
		return
	}

	w.log.Debugf("enable WireGuard watcher")
	enabledTime := time.Now()
	w.enabled = true
	w.muEnabled.Unlock()

	initialHandshake, err := w.wgState()
	if err != nil {
		w.log.Warnf("failed to read initial wg stats: %v", err)
	}

	w.periodicHandshakeCheck(ctx, onDisconnectedFn, enabledTime, initialHandshake)

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

// wgStateCheck help to check the state of the WireGuard handshake and relay connection
func (w *WGWatcher) periodicHandshakeCheck(ctx context.Context, onDisconnectedFn func(), enabledTime time.Time, initialHandshake time.Time) {
	w.log.Infof("WireGuard watcher started")

	timer := time.NewTimer(wgHandshakeOvertime)
	defer timer.Stop()

	lastHandshake := initialHandshake

	for {
		select {
		case <-timer.C:
			handshake, ok := w.handshakeCheck(lastHandshake)
			if !ok {
				onDisconnectedFn()
				return
			}
			if lastHandshake.IsZero() {
				elapsed := calcElapsed(enabledTime, *handshake)
				w.log.Infof("first wg handshake detected within: %.2fsec, (%s)", elapsed, handshake)
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
func calcElapsed(enabledTime, handshake time.Time) float64 {
	elapsed := handshake.Sub(enabledTime).Seconds()
	if elapsed < 0 {
		elapsed = 0
	}
	return elapsed
}
