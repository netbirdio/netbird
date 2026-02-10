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
	log                     *log.Entry
	isConnectedOnAllWay     isConnectedFunc
	timeout                 time.Duration
	srWatcher               *SRWatcher
	relayedConnDisconnected chan struct{}
	iCEConnDisconnected     chan struct{}
	onTimeout               func()
}

func NewGuard(log *log.Entry, isConnectedFn isConnectedFunc, timeout time.Duration, srWatcher *SRWatcher, onTimeout func()) *Guard {
	return &Guard{
		log:                     log,
		isConnectedOnAllWay:     isConnectedFn,
		timeout:                 timeout,
		srWatcher:               srWatcher,
		relayedConnDisconnected: make(chan struct{}, 1),
		iCEConnDisconnected:     make(chan struct{}, 1),
		onTimeout:               onTimeout,
	}
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

// reconnectLoopWithRetry periodically check the connection status.
// Try to send offer while the P2P is not established or while the Relay is not connected if is it supported
func (g *Guard) reconnectLoopWithRetry(ctx context.Context, callback func()) {
	srReconnectedChan := g.srWatcher.NewListener()
	defer g.srWatcher.RemoveListener(srReconnectedChan)

	ticker := g.initialTicker(ctx)
	defer ticker.Stop()

	tickerChannel := ticker.C

	for {
		select {
		case t := <-tickerChannel:
			if t.IsZero() {
				g.log.Infof("retry timed out, stop periodic offer sending")
				if g.onTimeout != nil {
					g.onTimeout()
				}
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

// initialTicker give chance to the peer to establish the initial connection.
func (g *Guard) initialTicker(ctx context.Context) *backoff.Ticker {
	bo := backoff.WithContext(&backoff.ExponentialBackOff{
		InitialInterval:     3 * time.Second,
		RandomizationFactor: 0.1,
		Multiplier:          2,
		MaxInterval:         g.timeout,
		MaxElapsedTime:      g.timeout * 2,
		Stop:                backoff.Stop,
		Clock:               backoff.SystemClock,
	}, ctx)

	return backoff.NewTicker(bo)
}

func (g *Guard) prepareExponentTicker(ctx context.Context) *backoff.Ticker {
	bo := backoff.WithContext(&backoff.ExponentialBackOff{
		InitialInterval:     800 * time.Millisecond,
		RandomizationFactor: 0.1,
		Multiplier:          2,
		MaxInterval:         g.timeout,
		MaxElapsedTime:      g.timeout * 2,
		Stop:                backoff.Stop,
		Clock:               backoff.SystemClock,
	}, ctx)

	ticker := backoff.NewTicker(bo)
	<-ticker.C // consume the initial tick what is happening right after the ticker has been created

	return ticker
}
