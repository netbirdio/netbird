package client

import (
	"context"
	"time"

	"github.com/cenkalti/backoff/v4"
	log "github.com/sirupsen/logrus"
)

var (
	reconnectingTimeout = 60 * time.Second
)

// Guard manage the reconnection tries to the Relay server in case of disconnection event.
type Guard struct {
	// OnNewRelayClient is a channel that is used to notify the relay client about a new relay client instance.
	OnNewRelayClient chan *Client
	serverPicker     *ServerPicker
}

// NewGuard creates a new guard for the relay client.
func NewGuard(sp *ServerPicker) *Guard {
	g := &Guard{
		OnNewRelayClient: make(chan *Client, 1),
		serverPicker:     sp,
	}
	return g
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
	if relayClient == nil {
		goto RETRY
	}
	if g.isServerURLStillValid(relayClient) && g.quickReconnect(ctx, relayClient) {
		return
	}

RETRY:
	ticker := exponentTicker(ctx)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if err := g.retry(ctx); err != nil {
				log.Errorf("failed to pick new Relay server: %s", err)
				continue
			}
			return
		case <-ctx.Done():
			return
		}
	}
}

func (g *Guard) retry(ctx context.Context) error {
	log.Infof("try to pick up a new Relay server")
	relayClient, err := g.serverPicker.PickServer(ctx)
	if err != nil {
		return err
	}

	// prevent to work with a deprecated Relay client instance
	g.drainRelayClientChan()

	g.OnNewRelayClient <- relayClient
	return nil
}

func (g *Guard) quickReconnect(parentCtx context.Context, rc *Client) bool {
	ctx, cancel := context.WithTimeout(parentCtx, 1500*time.Millisecond)
	defer cancel()
	<-ctx.Done()

	if parentCtx.Err() != nil {
		return false
	}
	log.Infof("try to reconnect to Relay server: %s", rc.connectionURL)

	if err := rc.Connect(); err != nil {
		log.Errorf("failed to reconnect to relay server: %s", err)
		return false
	}
	return true
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

func exponentTicker(ctx context.Context) *backoff.Ticker {
	bo := backoff.WithContext(&backoff.ExponentialBackOff{
		InitialInterval: 2 * time.Second,
		Multiplier:      2,
		MaxInterval:     reconnectingTimeout,
		Clock:           backoff.SystemClock,
	}, ctx)

	return backoff.NewTicker(bo)
}
