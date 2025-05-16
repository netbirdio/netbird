package guard

import (
	"context"
	"time"

	"github.com/cenkalti/backoff/v4"
	log "github.com/sirupsen/logrus"
)

type isConnectedFunc func() bool

// Guard is responsible for the reconnection logic.
// It will trigger to send an offer to the peer then has connection issues.
// Watch these events:
// - Relay client reconnected to home server
// - Signal server connection state changed
// - ICE connection disconnected
// - Relayed connection disconnected
// - ICE candidate changes
type Guard struct {
	Reconnect               chan struct{}
	log                     *log.Entry
	isConnectedOnAllWay     isConnectedFunc
	timeout                 time.Duration
	srWatcher               *SRWatcher
	relayedConnDisconnected chan struct{}
	iCEConnDisconnected     chan struct{}
}

func NewGuard(log *log.Entry, isConnectedFn isConnectedFunc, timeout time.Duration, srWatcher *SRWatcher) *Guard {
	return &Guard{
		Reconnect:               make(chan struct{}, 1),
		log:                     log,
		isConnectedOnAllWay:     isConnectedFn,
		timeout:                 timeout,
		srWatcher:               srWatcher,
		relayedConnDisconnected: make(chan struct{}, 1),
		iCEConnDisconnected:     make(chan struct{}, 1),
	}
}

func (g *Guard) Start(ctx context.Context, eventCallback func()) {
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

// reconnectLoopWithRetry periodically check the connection status.
// Try to send offer while the P2P is not established or while the Relay is not connected if is it supported
func (g *Guard) reconnectLoopWithRetry(ctx context.Context, callback func()) {
	waitForInitialConnectionTry(ctx)

	srReconnectedChan := g.srWatcher.NewListener()
	defer g.srWatcher.RemoveListener(srReconnectedChan)

	ticker := g.prepareExponentTicker(ctx)
	defer ticker.Stop()

	tickerChannel := ticker.C

	g.log.Infof("start reconnect loop...")
	for {
		select {
		case t := <-tickerChannel:
			if t.IsZero() {
				g.log.Infof("retry timed out, stop periodic offer sending")
				// after backoff timeout the ticker.C will be closed. We need to a dummy channel to avoid loop
				tickerChannel = make(<-chan time.Time)
				continue
			}

			if !g.isConnectedOnAllWay() {
				callback()
			}

		case <-g.relayedConnDisconnected:
			g.log.Debugf("Relay connection changed, reset reconnection ticker")
			ticker.Stop()
			ticker = g.prepareExponentTicker(ctx)
			tickerChannel = ticker.C

		case <-g.iCEConnDisconnected:
			g.log.Debugf("ICE connection changed, reset reconnection ticker")
			ticker.Stop()
			ticker = g.prepareExponentTicker(ctx)
			tickerChannel = ticker.C

		case <-srReconnectedChan:
			g.log.Debugf("has network changes, reset reconnection ticker")
			ticker.Stop()
			ticker = g.prepareExponentTicker(ctx)
			tickerChannel = ticker.C

		case <-ctx.Done():
			g.log.Debugf("context is done, stop reconnect loop")
			return
		}
	}
}

func (g *Guard) prepareExponentTicker(ctx context.Context) *backoff.Ticker {
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

// Give chance to the peer to establish the initial connection.
// With it, we can decrease to send necessary offer
func waitForInitialConnectionTry(ctx context.Context) {
	select {
	case <-ctx.Done():
		return
	case <-time.After(3 * time.Second):
	}
}
