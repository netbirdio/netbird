package guard

import (
	"context"
	"time"

	"github.com/cenkalti/backoff/v4"
	log "github.com/sirupsen/logrus"
)

const (
	reconnectMaxElapsedTime = 30 * time.Minute
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
	isController            bool
	isConnectedOnAllWay     isConnectedFunc
	timeout                 time.Duration
	srWatcher               *SRWatcher
	relayedConnDisconnected chan bool
	iCEConnDisconnected     chan bool
}

func NewGuard(log *log.Entry, isController bool, isConnectedFn isConnectedFunc, timeout time.Duration, srWatcher *SRWatcher) *Guard {
	return &Guard{
		Reconnect:               make(chan struct{}, 1),
		log:                     log,
		isController:            isController,
		isConnectedOnAllWay:     isConnectedFn,
		timeout:                 timeout,
		srWatcher:               srWatcher,
		relayedConnDisconnected: make(chan bool, 1),
		iCEConnDisconnected:     make(chan bool, 1),
	}
}

func (g *Guard) Start(ctx context.Context) {
	if g.isController {
		g.reconnectLoopWithRetry(ctx)
	} else {
		g.listenForDisconnectEvents(ctx)
	}
}

func (g *Guard) SetRelayedConnDisconnected(changed bool) {
	select {
	case g.relayedConnDisconnected <- changed:
	default:
	}
}

func (g *Guard) SetICEConnDisconnected(changed bool) {
	select {
	case g.iCEConnDisconnected <- changed:
	default:
	}
}

// reconnectLoopWithRetry periodically check (max 30 min) the connection status.
// Try to send offer while the P2P is not established or while the Relay is not connected if is it supported
func (g *Guard) reconnectLoopWithRetry(ctx context.Context) {
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
				g.triggerOfferSending()
			}

		case changed := <-g.relayedConnDisconnected:
			if !changed {
				continue
			}
			g.log.Debugf("Relay connection changed, reset reconnection ticker")
			ticker.Stop()
			ticker = g.prepareExponentTicker(ctx)
			tickerChannel = ticker.C

		case changed := <-g.iCEConnDisconnected:
			if !changed {
				continue
			}
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

// listenForDisconnectEvents is used when the peer is not a controller and it should reconnect to the peer
// when the connection is lost. It will try to establish a connection only once time if before the connection was established
// It track separately the ice and relay connection status. Just because a lower priority connection reestablished it does not
// mean that to switch to it. We always force to use the higher priority connection.
func (g *Guard) listenForDisconnectEvents(ctx context.Context) {
	srReconnectedChan := g.srWatcher.NewListener()
	defer g.srWatcher.RemoveListener(srReconnectedChan)

	g.log.Infof("start listen for reconnect events...")
	for {
		select {
		case changed := <-g.relayedConnDisconnected:
			if !changed {
				continue
			}
			g.log.Debugf("Relay connection changed, triggering reconnect")
			g.triggerOfferSending()
		case changed := <-g.iCEConnDisconnected:
			if !changed {
				continue
			}
			g.log.Debugf("ICE state changed, try to send new offer")
			g.triggerOfferSending()
		case <-srReconnectedChan:
			g.triggerOfferSending()
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
		MaxElapsedTime:      reconnectMaxElapsedTime,
		Stop:                backoff.Stop,
		Clock:               backoff.SystemClock,
	}, ctx)

	ticker := backoff.NewTicker(bo)
	<-ticker.C // consume the initial tick what is happening right after the ticker has been created

	return ticker
}

func (g *Guard) triggerOfferSending() {
	select {
	case g.Reconnect <- struct{}{}:
	default:
	}
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
