package guard

import (
	"context"
	"time"

	"github.com/cenkalti/backoff/v4"
	log "github.com/sirupsen/logrus"
)

const (
	reconnectMaxElapsedTime = 3 * time.Second
)

type isConnectedFunc func() bool

type Guard struct {
	Reconnect               chan struct{}
	log                     *log.Entry
	isController            bool
	isConnectedFn           isConnectedFunc
	timeout                 time.Duration
	srWatcher               *SRWatcher
	relayedConnDisconnected chan bool
	iCEConnDisconnected     chan bool
}

func NewGuard(log *log.Entry, isController bool, isConnectedFn isConnectedFunc, timeout time.Duration, srWatcher *SRWatcher, relayedConnDisconnected, iCEDisconnected chan bool) *Guard {
	return &Guard{
		Reconnect:               make(chan struct{}, 1),
		log:                     log,
		isController:            isController,
		isConnectedFn:           isConnectedFn,
		timeout:                 timeout,
		srWatcher:               srWatcher,
		relayedConnDisconnected: relayedConnDisconnected,
		iCEConnDisconnected:     iCEDisconnected,
	}
}

func (g *Guard) Start(ctx context.Context) {
	if g.isController {
		g.reconnectLoopWithRetry(ctx)
	} else {
		g.listenForDisconnectEvents(ctx)
	}
}

// reconnectLoopWithRetry periodically check (max 30 min) the connection status with peer and try to reconnect if necessary
// If the Relay is connected but the ICE P2P not then it will trigger ICE connection offer
func (g *Guard) reconnectLoopWithRetry(ctx context.Context) {
	// Give chance to the peer to establish the initial connection.
	// With it, we can decrease to send necessary offer
	select {
	case <-ctx.Done():
		return
	case <-time.After(3 * time.Second):
	}

	srReconnectedChan := g.srWatcher.NewListener()
	defer g.srWatcher.RemoveListener(srReconnectedChan)

	ticker := g.prepareExponentTicker(ctx)
	tickerChannel := ticker.C
	defer ticker.Stop()
	time.Sleep(1 * time.Second)

	g.log.Infof("start reconnect loop...")
	for {
		select {
		case t := <-tickerChannel:
			if t.IsZero() {
				g.log.Infof("stop periodic retry to connection")
				tickerChannel = make(<-chan time.Time) // after the timeout, we should stop the ticker
				continue
			}
			g.logTraceConnState()

			if g.isConnectedFn() {
				continue
			}
			g.triggerOfferSending()

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

// reconnectLoopForOnDisconnectedEvent is used when the peer is not a controller and it should reconnect to the peer
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

// logTraceConnState todo: implement me
func (g *Guard) logTraceConnState() {
	/*
		if g.workerRelay.IsRelayConnectionSupportedWithPeer() {
			if g.statusRelay.Get() == StatusDisconnected || g.statusICE.Get() == StatusDisconnected {
				g.log.Tracef("connectivity guard timedout, relay state: %s, ice state: %s", g.statusRelay, g.statusICE)
			}
		} else {
			if g.statusICE.Get() == StatusDisconnected {
				g.log.Tracef("connectivity guard timedout, ice state: %s", g.statusICE)
			}
		}

	*/
}
