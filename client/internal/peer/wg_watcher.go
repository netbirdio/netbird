package peer

import (
	"context"
	"fmt"
	"sync/atomic"
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

// WGWatcher is single-shot: one instance per connection attempt, run once, then discarded.
// Lifecycle is owned by Conn under conn.mu, so it keeps no "enabled" state to go stale.
type WGWatcher struct {
	log           *log.Entry
	wgIfaceStater WGInterfaceStater
	peerKey       string
	stateDump     *stateDump

	// initialHandshake is not thread-safe; never call PrepareInitialHandshake and EnableWgWatcher concurrently.
	initialHandshake time.Time

	resetCh chan struct{}

	// relayIdleFn is set before the watcher runs. When set, the watcher stops its
	// periodic check after a fresh handshake on the relay path and calls it once.
	relayIdleFn func()
	relayPath   atomic.Bool
	pathCh      chan struct{}
}

func NewWGWatcher(log *log.Entry, wgIfaceStater WGInterfaceStater, peerKey string, stateDump *stateDump) *WGWatcher {
	return &WGWatcher{
		log:           log,
		wgIfaceStater: wgIfaceStater,
		peerKey:       peerKey,
		stateDump:     stateDump,
		resetCh:       make(chan struct{}, 1),
		pathCh:        make(chan struct{}, 1),
	}
}

// EnableRelayIdle makes the watcher stop its periodic check on the relay path once a
// handshake is seen, and call onIdle at that point. On the relay path a dead remote
// or relay socket is reported by the relay itself. Call it before EnableWgWatcher.
func (w *WGWatcher) EnableRelayIdle(onIdle func()) {
	w.relayIdleFn = onIdle
}

// SetRelayPath tells the watcher which path the endpoint uses. A switch away from
// relay restarts the periodic check if it was stopped.
func (w *WGWatcher) SetRelayPath(relay bool) {
	w.relayPath.Store(relay)
	select {
	case w.pathCh <- struct{}{}:
	default:
	}
}

func (w *WGWatcher) idleOnRelay() bool {
	return w.relayIdleFn != nil && w.relayPath.Load()
}

// PrepareInitialHandshake reads the peer's current WireGuard handshake time. It must be
// called before the peer is (re)configured on the WireGuard interface, so the captured
// baseline reflects the state prior to this connection attempt instead of racing with
// that configuration.
func (w *WGWatcher) PrepareInitialHandshake() {
	w.log.Debugf("enable WireGuard watcher")
	handshake, _ := w.wgState()
	w.initialHandshake = handshake
}

// EnableWgWatcher runs the WireGuard watcher loop using the handshake baseline captured by
// PrepareInitialHandshake. The watcher runs until ctx is cancelled. Caller is responsible
// for context lifecycle management. onHandshakeSuccessFn is called only for the first
// handshake observed by this run, onCheckSuccessFn for every check that observed a fresh
// handshake, including the first.
func (w *WGWatcher) EnableWgWatcher(ctx context.Context, enabledTime time.Time, onDisconnectedFn func(), onHandshakeSuccessFn func(when time.Time), onCheckSuccessFn func()) {
	w.periodicHandshakeCheck(ctx, onDisconnectedFn, onHandshakeSuccessFn, onCheckSuccessFn, enabledTime, w.initialHandshake)
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
func (w *WGWatcher) periodicHandshakeCheck(ctx context.Context, onDisconnectedFn func(), onHandshakeSuccessFn func(when time.Time), onCheckSuccessFn func(), enabledTime time.Time, initialHandshake time.Time) {
	w.log.Infof("WireGuard watcher started")

	timer := time.NewTimer(wgHandshakeOvertime)
	defer timer.Stop()

	lastHandshake := initialHandshake
	idle := false

	for {
		select {
		case <-timer.C:
			handshake, ok := w.handshakeCheck(lastHandshake)
			if !ok {
				// early ctx cancel check return
				if ctx.Err() != nil {
					return
				}
				onDisconnectedFn()
				return
			}
			if lastHandshake.IsZero() {
				elapsed := calcElapsed(enabledTime, *handshake)
				w.log.Infof("first wg handshake detected within: %.2fsec, (%s)", elapsed, handshake)
				if onHandshakeSuccessFn != nil && ctx.Err() == nil {
					onHandshakeSuccessFn(*handshake)
				}
			}

			if onCheckSuccessFn != nil && ctx.Err() == nil {
				onCheckSuccessFn()
			}

			lastHandshake = *handshake
			w.stateDump.WGcheckSuccess()

			if w.idleOnRelay() && ctx.Err() == nil {
				w.log.Infof("WireGuard watcher idle on relay path, periodic check stopped")
				idle = true
				w.relayIdleFn()
				continue
			}

			resetTime := time.Until(handshake.Add(checkPeriod))
			timer.Reset(resetTime)

			w.log.Debugf("WireGuard watcher reset timer: %v", resetTime)
		case <-w.pathCh:
			if !idle || w.relayPath.Load() {
				continue
			}
			w.log.Infof("WireGuard watcher left relay path, periodic check restarted")
			idle = false
			timer.Reset(checkPeriod)
		case <-w.resetCh:
			w.log.Infof("WireGuard watcher received peer reset, restarting handshake timeout")
			idle = false
			lastHandshake = time.Time{}
			enabledTime = time.Now()
			timer.Stop()
			timer.Reset(wgHandshakeOvertime)
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

	// the current known handshake did not change
	if handshake.Equal(lastHandshake) {
		w.log.Warnf("WireGuard handshake not updated: %v", handshake)
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
