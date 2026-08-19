package client

import (
	"context"
	"sync/atomic"
	"time"

	"github.com/cenkalti/backoff/v4"
	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/netstate"
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

// Guard manage the reconnection tries to the Relay server in case of disconnection event.
type Guard struct {
	// OnNewRelayClient is a channel that is used to notify the relay manager about a new relay client instance.
	OnNewRelayClient chan *Client
	OnReconnected    chan struct{}
	serverPicker     *ServerPicker

	// maxBackoffInterval caps the exponential backoff between reconnect
	// attempts.
	maxBackoffInterval time.Duration

	// netState gates reconnect attempts on OS-reported network availability;
	// nil disables gating.
	netState *netstate.State

	// lastErr is the error from the most recent failed reconnect attempt,
	// surfaced as the home relay status while disconnected.
	lastErr atomic.Pointer[error]
}

// NewGuard creates a new guard for the relay client. A non-positive
// maxBackoffInterval falls back to defaultMaxBackoffInterval. A nil netState
// disables network availability gating.
func NewGuard(sp *ServerPicker, maxBackoffInterval time.Duration, netState *netstate.State) *Guard {
	if maxBackoffInterval <= 0 {
		maxBackoffInterval = defaultMaxBackoffInterval
	}
	g := &Guard{
		OnNewRelayClient:   make(chan *Client, 1),
		OnReconnected:      make(chan struct{}, 1),
		serverPicker:       sp,
		maxBackoffInterval: maxBackoffInterval,
		netState:           netState,
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

// StartReconnectTrys is called when the relay client is disconnected from the relay server.
// It attempts to reconnect to the relay server. The function first tries a quick reconnect
// to the same server that was used before, if the server URL is still valid. If the quick
// reconnect fails, it starts a ticker to periodically attempt server picking until it
// succeeds or the context is done.
//
// Parameters:
// - ctx: The context to control the lifecycle of the reconnection attempts.
// - relayClient: The relay client instance that was disconnected.
// todo prevent multiple reconnection instances. In the current usage it should not happen, but it is better to prevent
func (g *Guard) StartReconnectTrys(ctx context.Context, relayClient *Client) {
	// try to reconnect to the same server
	if ok := g.tryToQuickReconnect(ctx, relayClient); ok {
		g.notifyReconnected()
		return
	}

	// start a ticker to pick a new server
	ticker := g.exponentTicker(ctx)
	defer func() {
		ticker.Stop()
	}()

	for {
		select {
		case <-ticker.C:
			// suspend reconnect attempts while the OS reports no usable network
			if waited, err := g.netState.Wait(ctx); err != nil {
				return
			} else if waited {
				ticker.Stop()
				ticker = g.exponentTicker(ctx)
				continue
			}
			if err := g.retry(ctx); err != nil {
				log.Errorf("failed to pick new Relay server: %s", err)
				g.setLastError(err)
				continue
			}
			return
		case <-ctx.Done():
			return
		}
	}
}

func (g *Guard) setLastError(err error) {
	g.lastErr.Store(&err)
}

func (g *Guard) tryToQuickReconnect(parentCtx context.Context, rc *Client) bool {
	if rc == nil {
		return false
	}

	if !g.isServerURLStillValid(rc) {
		return false
	}

	if ok := g.waitForNetwork(parentCtx); !ok {
		return false
	}

	// Still offline after the budget: leave the retry to the ticker.
	if !g.netState.IsOnline() {
		return false
	}

	log.Infof("try to reconnect to Relay server: %s", rc.connectionURL)

	if err := rc.Connect(parentCtx); err != nil {
		log.Errorf("failed to reconnect to relay server: %s", err)
		g.setLastError(err)
		return false
	}
	return true
}

func (g *Guard) retry(ctx context.Context) error {
	log.Infof("try to pick up a new Relay server")
	relayClient, err := g.serverPicker.PickServer(ctx)
	if err != nil {
		return err
	}
	g.setLastError(nil)

	// prevent to work with a deprecated Relay client instance
	g.drainRelayClientChan()

	g.OnNewRelayClient <- relayClient
	return nil
}

func (g *Guard) drainRelayClientChan() {
	select {
	case <-g.OnNewRelayClient:
	default:
	}
}

func (g *Guard) isServerURLStillValid(rc *Client) bool {
	for _, url := range g.serverPicker.ServerURLs.Load().([]string) {
		if url == rc.connectionURL {
			return true
		}
	}
	return false
}

func (g *Guard) notifyReconnected() {
	g.setLastError(nil)
	select {
	case g.OnReconnected <- struct{}{}:
	default:
	}
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

// waitForNetwork waits out the settle window while online, or waits for the
// network to return while offline, within the budget. Returns false when ctx
// is cancelled. Without an injected netState it degrades to a fixed
// budget-long sleep, the pre-netstate behavior.
func (g *Guard) waitForNetwork(ctx context.Context) bool {
	budget := time.NewTimer(quickReconnectBudget)
	defer budget.Stop()

	settleWindow := verdictSettleWindow
	if g.netState == nil {
		settleWindow = quickReconnectBudget
	}
	settle := time.NewTimer(settleWindow)
	defer settle.Stop()

	for {
		// Channel first, flag second: a flip in between still fires the channel.
		changedCh := g.netState.Changed()
		if g.netState.IsOnline() {
			select {
			case <-settle.C:
				return true
			case <-changedCh:
			case <-ctx.Done():
				return false
			}
		} else {
			select {
			case <-budget.C:
				return true
			case <-changedCh:
			case <-ctx.Done():
				return false
			}
		}
		if !settle.Stop() {
			select {
			case <-settle.C:
			default:
			}
		}
		settle.Reset(settleWindow)
	}
}
