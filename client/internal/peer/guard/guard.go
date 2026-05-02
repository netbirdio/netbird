package guard

import (
	"context"
	"time"

	"github.com/cenkalti/backoff/v4"
	log "github.com/sirupsen/logrus"
)

// ConnStatus represents the connection state as seen by the guard.
type ConnStatus int

const (
	// ConnStatusDisconnected means neither ICE nor Relay is connected.
	ConnStatusDisconnected ConnStatus = iota
	// ConnStatusPartiallyConnected means Relay is connected but ICE is not.
	ConnStatusPartiallyConnected
	// ConnStatusConnected means all required connections are established.
	ConnStatusConnected
)

type connStatusFunc func() ConnStatus

// Guard is responsible for the reconnection logic.
// It will trigger to send an offer to the peer then has connection issues.
// Watch these events:
// - Relay client reconnected to home server
// - Signal server connection state changed
// - ICE connection disconnected
// - Relayed connection disconnected
// - ICE candidate changes
type Guard struct {
	log                     *log.Entry
	isConnectedOnAllWay     connStatusFunc
	timeout                 time.Duration
	srWatcher               *SRWatcher
	relayedConnDisconnected chan struct{}
	iCEConnDisconnected     chan struct{}
	// onNetworkChange is called when signal/relay reconnects after a
	// network change (e.g. LTE-modem replug, WiFi roaming). Set once
	// before Start() is called; no lock needed. Phase 3.5 of #5989.
	onNetworkChange func()
}

func NewGuard(log *log.Entry, isConnectedFn connStatusFunc, timeout time.Duration, srWatcher *SRWatcher) *Guard {
	return &Guard{
		log:                     log,
		isConnectedOnAllWay:     isConnectedFn,
		timeout:                 timeout,
		srWatcher:               srWatcher,
		relayedConnDisconnected: make(chan struct{}, 1),
		iCEConnDisconnected:     make(chan struct{}, 1),
	}
}

// SetOnNetworkChange registers a callback that fires whenever the
// signal/relay layer reconnects after a network change. Must be called
// before Start(). Phase 3.5 of #5989.
func (g *Guard) SetOnNetworkChange(cb func()) {
	g.onNetworkChange = cb
}

func (g *Guard) Start(ctx context.Context, eventCallback func()) {
	g.log.Infof("starting guard for reconnection with MaxInterval: %s", g.timeout)
	g.reconnectLoopWithRetry(ctx, eventCallback)
}

func (g *Guard) SetRelayedConnDisconnected() {
	select {
	case g.relayedConnDisconnected <- struct{}{}:
	default:
	}
}

func (g *Guard) SetICEConnDisconnected() {
	select {
	case g.iCEConnDisconnected <- struct{}{}:
	default:
	}
}

// reconnectLoopWithRetry periodically checks the connection status and sends offers to re-establish connectivity.
//
// Behavior depends on the connection state reported by isConnectedOnAllWay:
//   - Connected: no action, the peer is fully reachable.
//   - Disconnected (neither ICE nor Relay): retries aggressively with exponential backoff (800ms doubling
//     up to timeout), never gives up. This ensures rapid recovery when the peer has no connectivity at all.
//   - PartiallyConnected (Relay up, ICE not): retries up to 3 times with exponential backoff, then switches
//     to one attempt per hour. This limits signaling traffic when relay already provides connectivity.
//
// External events (relay/ICE disconnect, signal/relay reconnect, candidate changes) reset the retry
// counter and backoff ticker, giving ICE a fresh chance after network conditions change.
func (g *Guard) reconnectLoopWithRetry(ctx context.Context, callback func()) {
	srReconnectedChan := g.srWatcher.NewListener()
	defer g.srWatcher.RemoveListener(srReconnectedChan)

	ticker := g.initialTicker(ctx)
	defer ticker.Stop()

	tickerChannel := ticker.C

	iceState := &iceRetryState{log: g.log}
	defer iceState.reset()

	for {
		select {
		case <-tickerChannel:
			switch g.isConnectedOnAllWay() {
			case ConnStatusConnected:
				// all good, nothing to do
			case ConnStatusDisconnected:
				callback()
			case ConnStatusPartiallyConnected:
				if iceState.shouldRetry() {
					callback()
				} else {
					iceState.enterHourlyMode()
					ticker.Stop()
					tickerChannel = iceState.hourlyC()
				}
			}

		case <-g.relayedConnDisconnected:
			g.log.Debugf("Relay connection changed, reset reconnection ticker")
			ticker.Stop()
			ticker = g.newReconnectTicker(ctx)
			tickerChannel = ticker.C
			iceState.reset()

		case <-g.iCEConnDisconnected:
			g.log.Debugf("ICE connection changed, reset reconnection ticker")
			ticker.Stop()
			ticker = g.newReconnectTicker(ctx)
			tickerChannel = ticker.C
			iceState.reset()

		case <-srReconnectedChan:
			g.log.Debugf("has network changes, reset reconnection ticker")
			ticker.Stop()
			ticker = g.newReconnectTicker(ctx)
			tickerChannel = ticker.C
			iceState.reset()
			// Phase 3.5 (#5989): notify Conn to reset iceBackoff + recreate workerICE
			if g.onNetworkChange != nil {
				g.onNetworkChange()
			}

		case <-ctx.Done():
			g.log.Debugf("context is done, stop reconnect loop")
			return
		}
	}
}

// initialTicker give chance to the peer to establish the initial connection.
func (g *Guard) initialTicker(ctx context.Context) *backoff.Ticker {
	bo := backoff.WithContext(&backoff.ExponentialBackOff{
		InitialInterval:     3 * time.Second,
		RandomizationFactor: 0.1,
		Multiplier:          2,
		MaxInterval:         g.timeout,
		Stop:                backoff.Stop,
		Clock:               backoff.SystemClock,
	}, ctx)

	return backoff.NewTicker(bo)
}

func (g *Guard) newReconnectTicker(ctx context.Context) *backoff.Ticker {
	bo := backoff.WithContext(&backoff.ExponentialBackOff{
		InitialInterval:     800 * time.Millisecond,
		RandomizationFactor: 0.1,
		Multiplier:          2,
		MaxInterval:         g.timeout,
		Stop:                backoff.Stop,
		Clock:               backoff.SystemClock,
	}, ctx)

	ticker := backoff.NewTicker(bo)
	<-ticker.C // consume the initial tick what is happening right after the ticker has been created

	return ticker
}
