package guard

import (
	"context"
	"time"

	log "github.com/sirupsen/logrus"
)

const (
	offerResendPeriod = 2 * time.Second
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
	offerError              chan struct{}
}

func NewGuard(log *log.Entry, isConnectedFn isConnectedFunc, timeout time.Duration, srWatcher *SRWatcher) *Guard {
	return &Guard{
		log:                     log,
		isConnectedOnAllWay:     isConnectedFn,
		timeout:                 timeout,
		srWatcher:               srWatcher,
		relayedConnDisconnected: make(chan struct{}, 1),
		iCEConnDisconnected:     make(chan struct{}, 1),
		offerError:              make(chan struct{}, 1),
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

func (g *Guard) FailedToSendOffer() {
	select {
	case g.offerError <- struct{}{}:
	default:
	}
}

// reconnectLoopWithRetry periodically check the connection status.
// Try to send offer while the P2P is not established or while the Relay is not connected if is it supported
func (g *Guard) reconnectLoopWithRetry(ctx context.Context, callback func()) {
	srReconnectedChan := g.srWatcher.NewListener()
	defer g.srWatcher.RemoveListener(srReconnectedChan)

	offerResendTimer := time.NewTimer(0)
	offerResendTimer.Stop()
	defer offerResendTimer.Stop()

	for {
		select {
		case <-g.relayedConnDisconnected:
			g.log.Debugf("Relay connection changed, reset reconnection ticker")
			offerResendTimer.Stop()
			if !g.isConnectedOnAllWay() {
				callback()
			}
		case <-g.iCEConnDisconnected:
			g.log.Debugf("ICE connection changed, reset reconnection ticker")
			offerResendTimer.Stop()
			if !g.isConnectedOnAllWay() {
				callback()
			}
		case <-srReconnectedChan:
			g.log.Debugf("has network changes, reset reconnection ticker")
			offerResendTimer.Stop()
			if !g.isConnectedOnAllWay() {
				callback()
			}
		case <-g.offerError:
			g.log.Debugf("failed to send offer, reset reconnection ticker")
			offerResendTimer.Reset(offerResendPeriod)
			continue
		case <-offerResendTimer.C:
			if !g.isConnectedOnAllWay() {
				callback()
			}
		case <-ctx.Done():
			g.log.Debugf("context is done, stop reconnect loop")
			return
		}
	}
}
