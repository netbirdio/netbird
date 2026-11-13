package client

import (
	"context"
	"sync/atomic"
	"time"

	"github.com/cenkalti/backoff/v4"
	log "github.com/sirupsen/logrus"
)

const (
	defaultMaxBackoffInterval = 60 * time.Second

	// quickReconnectBudget bounds how long a quick reconnect waits for the
	// network before handing the retry over to the ticker.
	quickReconnectBudget = 1500 * time.Millisecond

	// verdictSettleWindow is how long an online verdict must hold before it
	// is trusted: the disconnect often precedes the OS offline flag by a few
	// milliseconds.
	verdictSettleWindow = 200 * time.Millisecond
)

// NetworkWatcher is the availability view the guard gates reconnects on.
type NetworkWatcher interface {
	Wait(ctx context.Context) (bool, error)
	IsOnline() bool
	WaitSettled(ctx context.Context, budget, settleWindow time.Duration) bool
}

// Guard manage the reconnection tries to the Relay server in case of disconnection event.
type Guard struct {
	serverPicker *ServerPicker

	// maxBackoffInterval caps the exponential backoff between reconnect
	// attempts.
	maxBackoffInterval time.Duration

	// netWatcher gates reconnect attempts on OS-reported network availability.
	netWatcher NetworkWatcher

	// lastErr is the error from the most recent failed reconnect attempt,
	// surfaced as the home relay status while disconnected.
	lastErr atomic.Pointer[error]
}

// NewGuard creates a new guard for the relay client. A non-positive
// maxBackoffInterval falls back to defaultMaxBackoffInterval.
func NewGuard(sp *ServerPicker, maxBackoffInterval time.Duration, netWatcher NetworkWatcher) *Guard {
	if maxBackoffInterval <= 0 {
		maxBackoffInterval = defaultMaxBackoffInterval
	}
	g := &Guard{
		serverPicker:       sp,
		maxBackoffInterval: maxBackoffInterval,
		netWatcher:         netWatcher,
	}
	return g
}

// LastError returns the error from the most recent failed reconnect attempt, or
// nil if reconnection last succeeded.
func (g *Guard) LastError() error {
	if p := g.lastErr.Load(); p != nil {
		return *p
	}
	return nil
}

func (g *Guard) Reconnect(ctx context.Context, relayClient *Client) *session {
	// try to reconnect to the same server
	if s := g.tryToQuickReconnect(ctx, relayClient); s != nil {
		g.setLastError(nil)
		return s
	}

	// start a ticker to pick a new server
	ticker := g.exponentTicker(ctx)
	defer func() {
		ticker.Stop()
	}()

	for {
		select {
		case _, ok := <-ticker.C:
			if !ok || ctx.Err() != nil {
				return nil
			}
			// suspend reconnect attempts while the OS reports no usable network
			if g.netWatcher != nil {
				if waited, err := g.netWatcher.Wait(ctx); err != nil {
					return nil
				} else if waited {
					ticker.Stop()
					ticker = g.exponentTicker(ctx)
					continue
				}
			}
			log.Infof("try to pick up a new Relay server")
			s, err := g.serverPicker.Pick(ctx)
			if err != nil {
				log.Errorf("failed to pick new Relay server: %s", err)
				g.setLastError(err)
				continue
			}
			g.setLastError(nil)
			return s
		case <-ctx.Done():
			return nil
		}
	}
}

func (g *Guard) setLastError(err error) {
	g.lastErr.Store(&err)
}

func (g *Guard) tryToQuickReconnect(parentCtx context.Context, rc *Client) *session {
	if rc == nil {
		return nil
	}

	if !g.isServerURLStillValid(rc) {
		return nil
	}

	if g.netWatcher != nil {
		if ok := g.netWatcher.WaitSettled(parentCtx, quickReconnectBudget, verdictSettleWindow); !ok {
			return nil
		}
		// Still offline after the budget: leave the retry to the ticker.
		if !g.netWatcher.IsOnline() {
			return nil
		}
	} else {
		if cancelled := waitBeforeRetry(parentCtx); !cancelled {
			return nil
		}
	}

	log.Infof("try to reconnect to Relay server: %s", rc.connectionURL)

	s, err := rc.ConnectSession(parentCtx)
	if err != nil {
		log.Errorf("failed to reconnect to relay server: %s", err)
		g.setLastError(err)
		return nil
	}
	return s
}

func (g *Guard) isServerURLStillValid(rc *Client) bool {
	for _, url := range g.serverPicker.ServerURLs.Load().([]string) {
		if url == rc.connectionURL {
			return true
		}
	}
	return false
}

func (g *Guard) exponentTicker(ctx context.Context) *backoff.Ticker {
	bo := backoff.WithContext(&backoff.ExponentialBackOff{
		InitialInterval: 2 * time.Second,
		// Spreads the reconnects of every client that lost the same relay server.
		RandomizationFactor: backoff.DefaultRandomizationFactor,
		Multiplier:          2,
		MaxInterval:         g.maxBackoffInterval,
		Clock:               backoff.SystemClock,
	}, ctx)

	return backoff.NewTicker(bo)
}

func waitBeforeRetry(ctx context.Context) bool {
	timer := time.NewTimer(quickReconnectBudget)
	defer timer.Stop()

	select {
	case <-timer.C:
		return true
	case <-ctx.Done():
		return false
	}
}
